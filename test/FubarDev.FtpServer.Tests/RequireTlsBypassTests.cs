// <copyright file="RequireTlsBypassTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using FubarDev.FtpServer.ServerCommandHandlers;

using Microsoft.Extensions.DependencyInjection;

using Xunit;
using Xunit.Abstractions;

namespace FubarDev.FtpServer.Tests
{
    /// <summary>
    /// Regression tests for three ways the <c>RequireTlsForLogin</c> / <c>RequireProtectedDataConnections</c>
    /// guards could be bypassed: a client pipelining plaintext commands behind <c>AUTH TLS</c> in
    /// the same TCP segment (STARTTLS command injection, CVE-2011-0411 class), <c>SITE BLST</c>
    /// opening a plaintext data connection because it wasn't on the enforcement command list, and
    /// <c>REIN</c> leaving the protected-data-connection flag stuck from a previous session.
    /// </summary>
    public class RequireTlsBypassTests
    {
        private readonly ITestOutputHelper _out;

        public RequireTlsBypassTests(ITestOutputHelper output)
        {
            _out = output;
        }

        /// <summary>
        /// A client that pipelines <c>USER</c>/<c>PASS</c>/<c>PWD</c> in the same write as
        /// <c>AUTH TLS</c> must never have them executed as if they'd arrived over TLS: the
        /// dispatcher must discard anything collected from the plaintext segment once TLS is
        /// actually active. <paramref name="fillers"/> pads the command with enough <c>FEAT</c>s
        /// to fill the connection's bounded command channel (capacity 5) exactly at <c>AUTH TLS</c>,
        /// forcing the race between the collector and the TLS switch that a small, unpadded
        /// command list (<c>fillers: 0</c>) might not reliably exercise.
        /// </summary>
        /// <param name="fillers">The number of filler <c>FEAT</c> commands pipelined behind <c>AUTH TLS</c>.</param>
        /// <returns>The task.</returns>
        [Theory(Timeout = 60000)]
        [InlineData(0)]
        [InlineData(4)]
        public async Task PipelinedPlaintextCredentialsAfterAuthTls(int fillers)
        {
            var host = new Host(_out, requireTlsForLogin: true, requireProtectedDataConnections: false);
            await host.InitializeAsync();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                var plaintext = client.GetStream();
                await ReadReplyAsync(plaintext);

                var pipelined = new StringBuilder("AUTH TLS\r\n");
                for (var i = 0; i < fillers; i++)
                {
                    pipelined.Append("FEAT\r\n");
                }

                pipelined.Append("USER anonymous\r\nPASS test@test.net\r\nPWD\r\n");
                await plaintext.WriteAsync(Encoding.ASCII.GetBytes(pipelined.ToString()));

                var authReply = await ReadReplyAsync(plaintext);
                _out.WriteLine("plaintext: " + authReply);
                Assert.StartsWith("234", authReply);

                using var tls = new SslStream(plaintext, true, (_, _, _, _) => true);
                await tls.AuthenticateAsClientAsync("localhost");

                var repliesOverTls = new List<string>();
                using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
                {
                    while (true)
                    {
                        string line;
                        try
                        {
                            line = await ReadLineAsync(tls, cts.Token);
                        }
                        catch (OperationCanceledException)
                        {
                            break;
                        }

                        repliesOverTls.Add(line);
                        _out.WriteLine("tls: " + line);
                        if (line.StartsWith("257 ", StringComparison.Ordinal)
                            || line.StartsWith("530 Not logged in", StringComparison.Ordinal))
                        {
                            break;
                        }
                    }
                }

                // The pipelined USER/PASS must not have logged the connection in, and PWD must
                // not have succeeded either - both would mean the plaintext commands executed as
                // if they'd arrived over TLS.
                Assert.DoesNotContain(repliesOverTls, line => line.StartsWith("230", StringComparison.Ordinal));
                Assert.DoesNotContain(repliesOverTls, line => line.StartsWith("257 ", StringComparison.Ordinal));
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        /// <summary>
        /// <c>SITE BLST</c> is not on any data-transfer command list, but it still opens a data
        /// connection - it must be rejected the same way <c>RETR</c>/<c>STOR</c>/<c>LIST</c> are
        /// when <c>RequireProtectedDataConnections</c> is on and the client never sent <c>PROT P</c>.
        /// </summary>
        /// <returns>The task.</returns>
        [Fact(Timeout = 60000)]
        public async Task SiteBlst_WithoutProtP_IsRejectedWith521()
        {
            var host = new Host(_out, requireTlsForLogin: false, requireProtectedDataConnections: true);
            await host.InitializeAsync();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                var stream = client.GetStream();
                await ReadReplyAsync(stream);
                await SendAsync(stream, "USER anonymous");
                await ReadLineAsync(stream, default);
                await SendAsync(stream, "PASS test@test.net");
                await ReadLineAsync(stream, default);
                await SendAsync(stream, "PASV");
                var pasvReply = await ReadReplyAsync(stream);
                _out.WriteLine("pasv: " + pasvReply);
                var dataPort = ParsePasvPort(pasvReply);

                await SendAsync(stream, "SITE BLST");

                // 150 is sent unconditionally by the command handler before the data-connection
                // choke point runs, exactly like it is for RETR/STOR when they later fail with
                // 425 - the rejection is the final 521, not the absence of 150.
                var opening = await ReadLineAsync(stream, default);
                _out.WriteLine(opening);
                Assert.StartsWith("150", opening);

                var final = await ReadLineAsync(stream, default);
                _out.WriteLine(final);
                Assert.StartsWith("521", final);

                // No listing must have been produced over the data connection: connecting to the
                // advertised port and reading must not see the client's background-task listing
                // land before the control connection closes it out.
                await AssertNoDataArrivesAsync(dataPort);
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        /// <summary>
        /// <c>REIN</c> must reset <c>IsDataConnectionProtected</c> along with the control
        /// connection's TLS state: a client that did <c>PROT P</c>, then <c>REIN</c>, then
        /// re-authenticated must not be able to <c>STOR</c> in plaintext on the strength of the
        /// previous session's protection level.
        /// </summary>
        /// <returns>The task.</returns>
        [Fact(Timeout = 60000)]
        public async Task ReinAfterProtP_RequiresProtPAgainForSubsequentStor()
        {
            var host = new Host(_out, requireTlsForLogin: true, requireProtectedDataConnections: true);
            await host.InitializeAsync();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                var plaintext = client.GetStream();
                await ReadReplyAsync(plaintext);

                await SendAsync(plaintext, "AUTH TLS");
                Assert.StartsWith("234", await ReadReplyAsync(plaintext));
                var tls = new SslStream(plaintext, true, (_, _, _, _) => true);
                await tls.AuthenticateAsClientAsync("localhost");

                await SendAsync(tls, "PBSZ 0");
                _out.WriteLine(await ReadLineAsync(tls, default));
                await SendAsync(tls, "PROT P");
                _out.WriteLine(await ReadLineAsync(tls, default));

                await SendAsync(tls, "REIN");

                // REIN's own handler resets the control connection's adapter back to plaintext
                // before its response is sent, so - unlike every other reply in this test - the
                // 220 banner for the new session arrives on the raw transport, preceded by the
                // outgoing TLS stream's own close_notify alert bytes (not ASCII), not through the
                // (now stale) TLS stream. Scan the raw bytes for the banner rather than parsing
                // the first line, and tolerate that leading alert. Seeing the banner at all also
                // proves the handler didn't crash with a NullReferenceException (a pre-existing
                // bug fixed alongside this one: GetBannerMessage() used to run after the feature
                // it needs was wiped).
                var reinReply = await ReadUntilBannerAsync(plaintext);
                _out.WriteLine("REIN reply: " + reinReply);
                Assert.Contains("220 ", reinReply);

                // Server dropped TLS for the new, plaintext session: AUTH TLS again.
                await SendAsync(plaintext, "AUTH TLS");
                Assert.StartsWith("234", await ReadReplyAsync(plaintext));
                tls = new SslStream(plaintext, true, (_, _, _, _) => true);
                await tls.AuthenticateAsClientAsync("localhost");

                await SendAsync(tls, "USER anonymous");
                _out.WriteLine(await ReadLineAsync(tls, default));
                await SendAsync(tls, "PASS test@test.net");
                _out.WriteLine(await ReadLineAsync(tls, default));
                await SendAsync(tls, "PASV");
                var pasvReply = await ReadLineAsync(tls, default);
                _out.WriteLine(pasvReply);
                var dataPort = ParsePasvPort(pasvReply);

                // No PROT P in this new session: STOR must be rejected, not silently accepted on
                // the strength of the PROT P sent before REIN. STOR is one of
                // RequireTlsCommandMiddleware's fast-path commands, so it's rejected immediately -
                // no 150 is sent at all.
                await SendAsync(tls, "STOR leak.txt");
                var final = await ReadLineAsync(tls, default);
                _out.WriteLine(final);
                Assert.StartsWith("521", final);

                await AssertNoDataArrivesAsync(dataPort);
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        /// <summary>
        /// Connects to a PASV data port and asserts nothing is ever sent over it: either the
        /// control side closes it immediately (a 0-byte read) or it never sends anything before
        /// the short timeout elapses - both mean no data was transferred.
        /// </summary>
        /// <summary>
        /// Connecting to a rejected data connection's advertised port must not yield any data.
        /// The choke point closes its listener on rejection (see
        /// <see cref="DataConnectionServerCommandHandler"/>), so connecting at all is now
        /// expected to fail outright with "connection refused" - tolerated here alongside a clean
        /// close (0-byte read) or a timeout with nothing ever arriving, which also mean no data
        /// was transferred.
        /// </summary>
        private static async Task AssertNoDataArrivesAsync(int dataPort)
        {
            using var data = new TcpClient();
            try
            {
                await data.ConnectAsync("127.0.0.1", dataPort);
            }
            catch (SocketException)
            {
                return;
            }

            var buffer = new byte[1];
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                var read = await data.GetStream().ReadAsync(buffer, cts.Token);
                Assert.Equal(0, read);
            }
            catch (OperationCanceledException) when (cts.IsCancellationRequested)
            {
                // Nothing arrived before the timeout - also acceptable.
            }
        }

        private static async Task<string> ReadUntilBannerAsync(Stream stream)
        {
            var raw = new StringBuilder();
            var buffer = new byte[1];
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (!Regex.IsMatch(raw.ToString(), "220 [^\n]*\n"))
            {
                var read = await stream.ReadAsync(buffer, cts.Token);
                if (read == 0)
                {
                    throw new EndOfStreamException(raw.ToString());
                }

                raw.Append((char)buffer[0]);
            }

            return raw.ToString();
        }

        private static int ParsePasvPort(string pasvReply)
        {
            var match = Regex.Match(pasvReply, @"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)");
            return (int.Parse(match.Groups[5].Value) * 256) + int.Parse(match.Groups[6].Value);
        }

        private static async Task SendAsync(Stream stream, string command)
        {
            await stream.WriteAsync(Encoding.ASCII.GetBytes(command + "\r\n"));
            await stream.FlushAsync();
        }

        private static async Task<string> ReadReplyAsync(Stream stream)
        {
            // Reads lines until a final (non-continuation) "ddd " line.
            while (true)
            {
                var line = await ReadLineAsync(stream, default);
                if (line.Length >= 4 && char.IsDigit(line[0]) && line[3] == ' ')
                {
                    return line;
                }
            }
        }

        private static async Task<string> ReadLineAsync(Stream stream, CancellationToken cancellationToken)
        {
            var builder = new StringBuilder();
            var buffer = new byte[1];
            while (true)
            {
                var read = await stream.ReadAsync(buffer, cancellationToken);
                if (read == 0)
                {
                    throw new EndOfStreamException(builder.ToString());
                }

                if (buffer[0] == '\n')
                {
                    return builder.ToString().TrimEnd('\r');
                }

                builder.Append((char)buffer[0]);
            }
        }

        private static X509Certificate2 CreateSelfSignedCertificate()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMinutes(5));
#pragma warning disable SYSLIB0057 // X509CertificateLoader isn't available on netstandard2.1.
            return new X509Certificate2(certificate.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
        }

        private sealed class Host : FtpServerTestsBase
        {
            private readonly bool _requireTlsForLogin;
            private readonly bool _requireProtectedDataConnections;

            public Host(ITestOutputHelper testOutputHelper, bool requireTlsForLogin, bool requireProtectedDataConnections)
                : base(testOutputHelper)
            {
                _requireTlsForLogin = requireTlsForLogin;
                _requireProtectedDataConnections = requireProtectedDataConnections;
            }

            protected override IServiceCollection Configure(IServiceCollection services)
            {
                var certificate = CreateSelfSignedCertificate();
                return base.Configure(services)
                   .Configure<AuthTlsOptions>(
                        opt =>
                        {
                            opt.ServerCertificate = certificate;
                            opt.RequireTlsForLogin = _requireTlsForLogin;
                            opt.RequireProtectedDataConnections = _requireProtectedDataConnections;
                        });
            }
        }
    }
}
