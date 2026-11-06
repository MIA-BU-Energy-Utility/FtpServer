// <copyright file="RequireTlsRound3Tests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using FubarDev.FtpServer.Authentication;
using FubarDev.FtpServer.ServerCommandHandlers;

using Microsoft.Extensions.DependencyInjection;

using Xunit;
using Xunit.Abstractions;

namespace FubarDev.FtpServer.Tests
{
    // Regression tests for the AUTH-TLS barrier, the data-connection choke point, REIN, and implicit FTPS.
    public class RequireTlsRound3Tests
    {
        private readonly ITestOutputHelper _out;

        public RequireTlsRound3Tests(ITestOutputHelper output)
        {
            _out = output;
        }

        // Any amount of plaintext pipelined behind AUTH TLS gets 421, never a hang.
        [Theory(Timeout = 60000)]
        [InlineData(5)]
        [InlineData(8)]
        [InlineData(20)]
        public async Task ManyPipelinedCommandsAfterAuthTls_DoesNotHang(int fillers)
        {
            var host = new Host(_out, requireTlsForLogin: true, requireProtectedDataConnections: false);
            await host.InitializeAsync();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                var plaintext = client.GetStream();
                await ReadReplyAsync(plaintext, default);

                var pipelined = new StringBuilder("AUTH TLS\r\n");
                for (var i = 0; i < fillers; i++)
                {
                    pipelined.Append("FEAT\r\n");
                }

                pipelined.Append("USER anonymous\r\nPASS test@test.net\r\n");
                await plaintext.WriteAsync(Encoding.ASCII.GetBytes(pipelined.ToString()));

                var authReply = await ReadReplyAsync(plaintext, default);
                _out.WriteLine("auth reply: " + authReply);
                Assert.StartsWith("421", authReply);

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var buffer = new byte[256];
                var read = await plaintext.ReadAsync(buffer, cts.Token);
                Assert.Equal(0, read);
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        // A command sent in the same flight as the handshake's last message must not be dropped.
        [Fact(Timeout = 300000)]
        public async Task FirstCommandRightAfterHandshake_IsNeverDropped()
        {
            var host = new Host(_out, requireTlsForLogin: true, requireProtectedDataConnections: false);
            await host.InitializeAsync();
            const int runs = 100;
            var dropped = 0;
            try
            {
                for (var i = 0; i < runs; i++)
                {
                    using var client = new TcpClient { NoDelay = true };
                    await client.ConnectAsync("127.0.0.1", host.Server.Port);
                    var plaintext = client.GetStream();
                    await ReadReplyAsync(plaintext, default);
                    await SendAsync(plaintext, "AUTH TLS");
                    await ReadReplyAsync(plaintext, default);

                    using var tls = new SslStream(plaintext, true, (_, _, _, _) => true);
                    await tls.AuthenticateAsClientAsync("localhost");
                    await SendAsync(tls, "SYST");

                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    try
                    {
                        var reply = await ReadReplyAsync(tls, cts.Token);
                        if (!reply.StartsWith("215", StringComparison.Ordinal))
                        {
                            _out.WriteLine($"run {i}: unexpected reply {reply}");
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        dropped++;
                        _out.WriteLine($"run {i}: no reply (command dropped)");
                    }
                }
            }
            finally
            {
                await host.DisposeAsync();
            }

            _out.WriteLine($"dropped {dropped}/{runs}");
            Assert.Equal(0, dropped);
        }

        // Garbage instead of a real ClientHello closes the connection instead of hanging.
        [Fact(Timeout = 60000)]
        public async Task AuthTls_GarbageHandshake_ClosesNotHangs()
        {
            var host = new Host(_out, requireTlsForLogin: true, requireProtectedDataConnections: false);
            await host.InitializeAsync();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                var plaintext = client.GetStream();
                await ReadReplyAsync(plaintext, default);
                await SendAsync(plaintext, "AUTH TLS");
                await ReadReplyAsync(plaintext, default);

                await plaintext.WriteAsync(Encoding.ASCII.GetBytes("USER anonymous\r\nPASS x\r\n"));

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var all = new StringBuilder();
                var buffer = new byte[256];
                while (true)
                {
                    var read = await plaintext.ReadAsync(buffer, cts.Token);
                    if (read == 0)
                    {
                        break;
                    }

                    all.Append(Encoding.ASCII.GetString(buffer, 0, read));
                }

                _out.WriteLine("after garbage: " + all.ToString().Replace("\r\n", "|"));
                Assert.DoesNotContain("230", all.ToString());
                Assert.DoesNotContain("331", all.ToString());
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        /// <summary>
        /// 100 connections that send <c>AUTH TLS</c> and then disconnect immediately (with and
        /// without an RST) must not prevent the server from shutting down.
        /// </summary>
        /// <param name="reset">Whether to force an RST on close (<c>true</c>) rather than a clean FIN.</param>
        /// <returns>The task.</returns>
        [Theory(Timeout = 120000)]
        [InlineData(true)]
        [InlineData(false)]
        public async Task AuthTlsThenDisconnect_ServerStopsCleanly(bool reset)
        {
            var host = new Host(_out, requireTlsForLogin: true, requireProtectedDataConnections: false);
            await host.InitializeAsync();
            for (var i = 0; i < 100; i++)
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                var plaintext = client.GetStream();
                await ReadReplyAsync(plaintext, default);
                await plaintext.WriteAsync(Encoding.ASCII.GetBytes("AUTH TLS\r\n"));
                if (reset)
                {
                    client.LingerState = new LingerOption(true, 0);
                }
            }

            await Task.Delay(2000);
            var stop = host.DisposeAsync();
            var completed = await Task.WhenAny(stop, Task.Delay(TimeSpan.FromSeconds(30)));
            Assert.Same(stop, completed);
        }

        /// <summary>
        /// A <c>521</c> rejection from the data-connection choke point must not leave the PASV
        /// listener it already opened accepting connections indefinitely. Uses <c>SITE BLST</c>
        /// rather than e.g. <c>NLST</c> deliberately: it isn't on <see cref="RequireTlsCommandMiddleware"/>'s
        /// fast-path list (see that class's remarks), so this exercises the choke point itself -
        /// <see cref="DataConnectionServerCommandHandler"/> - rather than
        /// the middleware short-circuiting before a data connection is ever opened.
        /// </summary>
        /// <returns>The task.</returns>
        [Fact(Timeout = 60000)]
        public async Task PasvListener_AfterRejected521_StopsAccepting()
        {
            var host = new Host(_out, requireTlsForLogin: false, requireProtectedDataConnections: true);
            await host.InitializeAsync();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                var stream = client.GetStream();
                await ReadReplyAsync(stream, default);
                await SendAsync(stream, "USER anonymous");
                await ReadReplyAsync(stream, default);
                await SendAsync(stream, "PASS test@test.net");
                await ReadReplyAsync(stream, default);
                await SendAsync(stream, "PASV");
                var dataPort = ParsePasvPort(await ReadReplyAsync(stream, default));

                await SendAsync(stream, "SITE BLST");
                Assert.StartsWith("150", await ReadReplyAsync(stream, default));
                Assert.StartsWith("521", await ReadReplyAsync(stream, default));

                // Give the handler's disposal of the listener a moment, then confirm it's gone.
                await Task.Delay(500);
                using var late = new TcpClient();
                var connectedLate = true;
                try
                {
                    await late.ConnectAsync("127.0.0.1", dataPort);
                }
                catch (SocketException)
                {
                    connectedLate = false;
                }

                Assert.False(connectedLate, "The PASV listener should have been closed once the 521 was sent.");
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        /// <summary>
        /// <c>REIN</c> resets the current directory, transfer type, and login - not just the TLS
        /// state flags covered elsewhere in this suite.
        /// </summary>
        /// <returns>The task.</returns>
        [Fact(Timeout = 60000)]
        public async Task Rein_ResetsCwdTypeAndLogin()
        {
            var host = new Host(_out, requireTlsForLogin: false, requireProtectedDataConnections: false);
            await host.InitializeAsync();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                var stream = client.GetStream();
                await ReadReplyAsync(stream, default);

                async Task<string> CommandAsync(string cmd)
                {
                    await SendAsync(stream, cmd);
                    var reply = await ReadReplyAsync(stream, default);
                    _out.WriteLine($"{cmd} -> {reply}");
                    return reply;
                }

                await CommandAsync("USER anonymous");
                await CommandAsync("PASS test@test.net");
                await CommandAsync("MKD secretdir");
                await CommandAsync("CWD secretdir");
                await CommandAsync("TYPE I");
                await CommandAsync("REST 100");
                Assert.StartsWith("257 \"/secretdir\"", await CommandAsync("PWD"));

                Assert.StartsWith("220", await CommandAsync("REIN"));
                Assert.StartsWith("530", await CommandAsync("PWD"));
                Assert.StartsWith("530", await CommandAsync("LIST"));

                await CommandAsync("USER anonymous");
                await CommandAsync("PASS test@test.net");
                Assert.StartsWith("257 \"/\"", await CommandAsync("PWD"));
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        /// <summary>
        /// Implicit FTPS (the whole control connection is TLS from the first byte) plus
        /// <see cref="AuthTlsOptions.RequireTlsForLogin"/> must still allow a normal login -
        /// <see cref="RequireTlsTests"/> only covers explicit <c>AUTH TLS</c>.
        /// </summary>
        /// <returns>The task.</returns>
        [Fact(Timeout = 60000)]
        public async Task ImplicitFtps_WithRequireTlsForLogin_LogsIn()
        {
            var host = new ImplicitHost(_out);
            await host.InitializeAsync();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                using var tls = new SslStream(client.GetStream(), false, (_, _, _, _) => true);
                await tls.AuthenticateAsClientAsync("localhost");

                await ReadReplyAsync(tls, default);
                await SendAsync(tls, "USER anonymous");
                Assert.StartsWith("331", await ReadReplyAsync(tls, default));
                await SendAsync(tls, "PASS test@test.net");
                Assert.StartsWith("230", await ReadReplyAsync(tls, default));
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        // A second AUTH TLS once already secure gets 503; the connection stays usable.
        [Fact(Timeout = 60000)]
        public async Task AuthTlsTwice_GetsBadSequence_AndConnectionStaysUsable()
        {
            var host = new Host(_out, requireTlsForLogin: true, requireProtectedDataConnections: false);
            await host.InitializeAsync();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                var plaintext = client.GetStream();
                await ReadReplyAsync(plaintext, default);
                await SendAsync(plaintext, "AUTH TLS");
                Assert.StartsWith("234", await ReadReplyAsync(plaintext, default));

                using var tls = new SslStream(plaintext, true, (_, _, _, _) => true);
                await tls.AuthenticateAsClientAsync("localhost");

                await SendAsync(tls, "AUTH TLS");
                var secondAuth = await ReadReplyAsync(tls, default);
                _out.WriteLine("second AUTH TLS -> " + secondAuth);
                Assert.StartsWith("503", secondAuth);

                await SendAsync(tls, "USER anonymous");
                Assert.StartsWith("331", await ReadReplyAsync(tls, default));
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        // Pipelined plaintext behind AUTH TLS, then a disconnect (clean or RST), must not leak the connection.
        [Theory(Timeout = 30000)]
        [InlineData(false)]
        [InlineData(true)]
        public async Task PipelinedThenDisconnect_DoesNotLeakConnections(bool reset)
        {
            var host = new Host(_out, requireTlsForLogin: true, requireProtectedDataConnections: false);
            await host.InitializeAsync();
            try
            {
                const int connections = 20;
                const int fillers = 40;

                for (var i = 0; i < connections; i++)
                {
                    using var client = new TcpClient();
                    await client.ConnectAsync("127.0.0.1", host.Server.Port);
                    var stream = client.GetStream();
                    await ReadReplyAsync(stream, default);

                    var pipelined = new StringBuilder("AUTH TLS\r\n");
                    for (var f = 0; f < fillers; f++)
                    {
                        pipelined.Append("FEAT\r\n");
                    }

                    await stream.WriteAsync(Encoding.ASCII.GetBytes(pipelined.ToString()));

                    if (reset)
                    {
                        client.LingerState = new LingerOption(true, 0);
                    }
                }

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                var lastLogged = -1L;
                while (host.Server.Statistics.ActiveConnections > 0 && !cts.IsCancellationRequested)
                {
                    var current = host.Server.Statistics.ActiveConnections;
                    if (current != lastLogged)
                    {
                        _out.WriteLine($"active connections: {current}");
                        lastLogged = current;
                    }

                    await Task.Delay(250, CancellationToken.None);
                }

                _out.WriteLine($"final active connections: {host.Server.Statistics.ActiveConnections}");
                Assert.Equal(0L, host.Server.Statistics.ActiveConnections);
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        // AUTH TLS split across two TCP writes, with smuggled commands appended to the second, still gets 421.
        [Fact(Timeout = 30000)]
        public async Task SplitSegmentPipelinedCredentialsAfterAuthTls_NeverLogsIn()
        {
            var host = new Host(_out, requireTlsForLogin: true, requireProtectedDataConnections: false);
            await host.InitializeAsync();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                var plaintext = client.GetStream();
                await ReadReplyAsync(plaintext, default);

                await plaintext.WriteAsync(Encoding.ASCII.GetBytes("AUTH TL"));
                await plaintext.FlushAsync();
                await Task.Delay(100);

                await plaintext.WriteAsync(Encoding.ASCII.GetBytes("S\r\nUSER anonymous\r\nPASS test@test.net\r\nPWD\r\n"));
                await plaintext.FlushAsync();

                var authReply = await ReadReplyAsync(plaintext, default);
                _out.WriteLine("auth reply: " + authReply);
                Assert.StartsWith("421", authReply);

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var buffer = new byte[256];
                var read = await plaintext.ReadAsync(buffer, cts.Token);
                Assert.Equal(0, read);
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        // Plaintext racing the pause window (sent right behind AUTH TLS, before 234) must never log in.
        [Fact(Timeout = 30000)]
        public async Task PlaintextRaceWithPause_NeverLogsIn()
        {
            var host = new Host(_out, requireTlsForLogin: true, requireProtectedDataConnections: false);
            await host.InitializeAsync();
            try
            {
                for (var attempt = 0; attempt < 10; attempt++)
                {
                    using var client = new TcpClient();
                    await client.ConnectAsync("127.0.0.1", host.Server.Port);
                    var plaintext = client.GetStream();
                    await ReadReplyAsync(plaintext, default);

                    await plaintext.WriteAsync(Encoding.ASCII.GetBytes("AUTH TLS\r\n"));
                    await plaintext.FlushAsync();
                    await plaintext.WriteAsync(Encoding.ASCII.GetBytes("USER anonymous\r\nPASS test@test.net\r\n"));
                    await plaintext.FlushAsync();

                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    var sawLogin = false;
                    try
                    {
                        while (true)
                        {
                            var line = await ReadLineAsync(plaintext, cts.Token);
                            _out.WriteLine($"attempt {attempt}: {line}");
                            if (line.StartsWith("230", StringComparison.Ordinal) || line.StartsWith("331", StringComparison.Ordinal))
                            {
                                sawLogin = true;
                            }
                        }
                    }
                    catch (OperationCanceledException)
                    {
                    }
                    catch (EndOfStreamException)
                    {
                    }

                    Assert.False(sawLogin, $"attempt {attempt} logged in or started to");
                }
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        // A stalled handshake (AUTH TLS accepted, no ClientHello ever sent) must not wedge the server.
        [Fact(Timeout = 60000)]
        public async Task StalledHandshake_DoesNotWedgeServer()
        {
            var host = new Host(_out, requireTlsForLogin: true, requireProtectedDataConnections: false);
            await host.InitializeAsync();
            try
            {
                using var stalled = new TcpClient();
                await stalled.ConnectAsync("127.0.0.1", host.Server.Port);
                var stalledStream = stalled.GetStream();
                await ReadReplyAsync(stalledStream, default);
                await SendAsync(stalledStream, "AUTH TLS");
                Assert.StartsWith("234", await ReadReplyAsync(stalledStream, default));

                await Task.Delay(TimeSpan.FromSeconds(35));

                using var other = new TcpClient();
                await other.ConnectAsync("127.0.0.1", host.Server.Port);
                var otherStream = other.GetStream();
                await ReadReplyAsync(otherStream, default);
                await SendAsync(otherStream, "SYST");
                Assert.StartsWith("215", await ReadReplyAsync(otherStream, default));
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        // Regression for the R5 blocker: PlaintextPaused must not resolve until the receiver is actually paused.
        [Fact(Timeout = 300000)]
        public async Task R5_InjectionRacingQueuedPause()
        {
            var host = new Host(_out, requireTlsForLogin: false, requireProtectedDataConnections: false);
            await host.InitializeAsync();
            try
            {
                var gapsMicroseconds = new[] { 0, 50, 200, 1000 };
                const int iterations = 300;
                var loggedIn = 0;
                var byGap = new Dictionary<int, int>();

                for (var i = 0; i < iterations; i++)
                {
                    var gap = gapsMicroseconds[i % gapsMicroseconds.Length];

                    using var client = new TcpClient { NoDelay = true };
                    await client.ConnectAsync("127.0.0.1", host.Server.Port);
                    var plaintext = client.GetStream();
                    await ReadReplyAsync(plaintext, default);

                    await plaintext.WriteAsync(Encoding.ASCII.GetBytes("AUTH TLS\r\n"));
                    await plaintext.FlushAsync();

                    var sw = Stopwatch.StartNew();
                    while (sw.Elapsed.TotalMilliseconds * 1000.0 < gap)
                    {
                    }

                    await plaintext.WriteAsync(Encoding.ASCII.GetBytes("USER anonymous\r\nPASS test@test.net\r\nPWD\r\n"));
                    await plaintext.FlushAsync();

                    var sawLogin = await ProbeForLoginAsync(plaintext);
                    if (sawLogin)
                    {
                        loggedIn++;
                        byGap[gap] = byGap.GetValueOrDefault(gap) + 1;
                    }
                }

                foreach (var gap in gapsMicroseconds)
                {
                    _out.WriteLine($"gap {gap}us: logged in {byGap.GetValueOrDefault(gap)}/{iterations / gapsMicroseconds.Length}");
                }

                _out.WriteLine($"total logged in: {loggedIn}/{iterations}");
                Assert.Equal(0, loggedIn);
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        private static async Task<bool> ProbeForLoginAsync(NetworkStream plaintext)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            string authReply;
            try
            {
                authReply = await ReadReplyAsync(plaintext, cts.Token);
            }
            catch (Exception)
            {
                return false;
            }

            if (!authReply.StartsWith("234", StringComparison.Ordinal))
            {
                return false;
            }

            SslStream tls;
            try
            {
                tls = new SslStream(plaintext, true, (_, _, _, _) => true);
                using var handshakeTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await tls.AuthenticateAsClientAsync(
                    new SslClientAuthenticationOptions { TargetHost = "localhost" },
                    handshakeTimeout.Token);
            }
            catch (Exception)
            {
                return false;
            }

            using (tls)
            {
                try
                {
                    await SendAsync(tls, "SYST");
                    while (true)
                    {
                        var line = await ReadLineAsync(tls, cts.Token);
                        if (line.StartsWith("230", StringComparison.Ordinal) || line.StartsWith("331", StringComparison.Ordinal))
                        {
                            return true;
                        }

                        if (line.StartsWith("215", StringComparison.Ordinal))
                        {
                            return false;
                        }
                    }
                }
                catch (Exception)
                {
                    return false;
                }
            }
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

        private static async Task<string> ReadReplyAsync(Stream stream, CancellationToken cancellationToken)
        {
            while (true)
            {
                var line = await ReadLineAsync(stream, cancellationToken);
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

        private sealed class ImplicitHost : FtpServerTestsBase
        {
            private readonly X509Certificate2 _certificate = CreateSelfSignedCertificate();

            public ImplicitHost(ITestOutputHelper testOutputHelper)
                : base(testOutputHelper)
            {
            }

            protected override IFtpServerBuilder Configure(IFtpServerBuilder builder)
            {
                return base.Configure(builder).UseImplicitTls(_certificate);
            }

            protected override IServiceCollection Configure(IServiceCollection services)
            {
                return base.Configure(services)
                   .Configure<AuthTlsOptions>(opt => opt.RequireTlsForLogin = true);
            }
        }
    }
}
