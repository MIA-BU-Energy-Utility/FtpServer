// <copyright file="RequireTlsTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using FluentFTP;

using Microsoft.Extensions.DependencyInjection;

using Xunit;
using Xunit.Abstractions;

namespace FubarDev.FtpServer.Tests
{
    /// <summary>
    /// Tests for <see cref="AuthTlsOptions.RequireTlsForLogin"/> and
    /// <see cref="AuthTlsOptions.RequireProtectedDataConnections"/>, the opt-in guards against
    /// the FTP server accepting plaintext credentials or plaintext data transfers.
    /// </summary>
    public class RequireTlsTests
    {
        /// <summary>
        /// A plaintext <c>USER</c> must be rejected with <c>530</c> while
        /// <see cref="AuthTlsOptions.RequireTlsForLogin"/> is enabled and the control
        /// connection hasn't been secured with <c>AUTH TLS</c> yet.
        /// </summary>
        [Fact(Timeout = 60000)]
        public async Task PlaintextUser_WhenTlsRequiredForLogin_IsRejectedWith530()
        {
            var host = new RequireTlsForLoginHost(RequireTlsForLoginHost.NullOutput);
            await host.InitializeAsync();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                using var stream = client.GetStream();

                await ReadReplyAsync(stream); // Greeting.
                await WriteCommandAsync(stream, "USER anonymous");
                var reply = await ReadReplyAsync(stream);

                Assert.StartsWith("530", reply);
                Assert.Contains("TLS required", reply);

                // Not just the reply code: USER must not have logged the connection in either.
                await WriteCommandAsync(stream, "PWD");
                var pwdReply = await ReadReplyAsync(stream);
                Assert.StartsWith("530 Not logged in", pwdReply);
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        /// <summary>
        /// A plaintext <c>PASS</c> (sent on its own, without a prior <c>USER</c>) must be
        /// rejected with <c>530</c> the same way <c>USER</c> is, and must not leave the
        /// connection logged in: a following command must still see <c>530 Not logged in.</c>.
        /// </summary>
        [Fact(Timeout = 60000)]
        public async Task PlaintextPass_WhenTlsRequiredForLogin_IsRejectedWith530AndDoesNotLogIn()
        {
            var host = new RequireTlsForLoginHost(RequireTlsForLoginHost.NullOutput);
            await host.InitializeAsync();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                using var stream = client.GetStream();

                await ReadReplyAsync(stream); // Greeting.
                await WriteCommandAsync(stream, "PASS anything");
                var passReply = await ReadReplyAsync(stream);
                Assert.StartsWith("530", passReply);
                Assert.Contains("TLS required", passReply);

                await WriteCommandAsync(stream, "PWD");
                var pwdReply = await ReadReplyAsync(stream);
                Assert.StartsWith("530 Not logged in", pwdReply);
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        /// <summary>
        /// A plaintext <c>ACCT</c> must be rejected with <c>530</c> the same way <c>USER</c> is,
        /// and must not leave the connection logged in.
        /// </summary>
        [Fact(Timeout = 60000)]
        public async Task PlaintextAcct_WhenTlsRequiredForLogin_IsRejectedWith530AndDoesNotLogIn()
        {
            var host = new RequireTlsForLoginHost(RequireTlsForLoginHost.NullOutput);
            await host.InitializeAsync();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                using var stream = client.GetStream();

                await ReadReplyAsync(stream); // Greeting.
                await WriteCommandAsync(stream, "ACCT anything");
                var acctReply = await ReadReplyAsync(stream);
                Assert.StartsWith("530", acctReply);
                Assert.Contains("TLS required", acctReply);

                await WriteCommandAsync(stream, "PWD");
                var pwdReply = await ReadReplyAsync(stream);
                Assert.StartsWith("530 Not logged in", pwdReply);
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        /// <summary>
        /// After a successful <c>AUTH TLS</c>, the (now encrypted) control connection may log
        /// in normally even though <see cref="AuthTlsOptions.RequireTlsForLogin"/> is enabled.
        /// </summary>
        [Fact(Timeout = 60000)]
        public async Task User_AfterAuthTls_WhenTlsRequiredForLogin_Succeeds()
        {
            var host = new RequireTlsForLoginHost(RequireTlsForLoginHost.NullOutput);
            await host.InitializeAsync();
            try
            {
                using var client = CreateExplicitTlsClient(host.Server.Port, dataConnectionEncryption: false);
                await client.Connect();
                Assert.True(client.IsConnected);
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        /// <summary>
        /// When <see cref="AuthTlsOptions.RequireTlsForLogin"/> is left at its default
        /// (disabled), a plaintext login keeps working exactly as before.
        /// </summary>
        [Fact(Timeout = 60000)]
        public async Task PlaintextUser_WhenTlsNotRequired_Succeeds()
        {
            var host = new RequireTlsForLoginHost(RequireTlsForLoginHost.NullOutput, requireTlsForLogin: false);
            await host.InitializeAsync();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                using var stream = client.GetStream();

                await ReadReplyAsync(stream); // Greeting.
                await WriteCommandAsync(stream, "USER anonymous");
                var reply = await ReadReplyAsync(stream);

                Assert.StartsWith("331", reply);
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        /// <summary>
        /// A data-transfer command without <c>PROT P</c> must be rejected with <c>521</c> while
        /// <see cref="AuthTlsOptions.RequireProtectedDataConnections"/> is enabled, and no data
        /// may cross the data connection. Driven over a raw socket rather than FluentFTP: the
        /// handler sends <c>150</c> unconditionally before the choke point runs (exactly as it
        /// does when a data connection later fails for unrelated reasons, e.g. <c>425</c>), and
        /// FluentFTP's high-level <c>UploadBytes</c> does not reliably surface that as a thrown
        /// exception when no bytes ever follow the <c>150</c>.
        /// </summary>
        [Fact(Timeout = 60000)]
        public async Task Upload_WithoutProtP_WhenDataConnectionsMustBeProtected_IsRejectedWith521()
        {
            var host = new RequireProtectedDataConnectionsHost(RequireProtectedDataConnectionsHost.NullOutput);
            await host.InitializeAsync();
            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", host.Server.Port);
                using var stream = client.GetStream();

                await ReadReplyAsync(stream); // Greeting.
                await WriteCommandAsync(stream, "USER anonymous");
                await ReadReplyAsync(stream);
                await WriteCommandAsync(stream, "PASS test@test.net");
                await ReadReplyAsync(stream);
                await WriteCommandAsync(stream, "PASV");
                var pasvReply = await ReadReplyAsync(stream);
                var dataPort = ParsePasvPort(pasvReply);

                await WriteCommandAsync(stream, "STOR plain.txt");
                var opening = await ReadLineAsync(stream);
                Assert.StartsWith("150", opening);

                var final = await ReadLineAsync(stream);
                Assert.StartsWith("521", final);

                // No file content may have crossed the data connection: connect to the
                // advertised port and confirm nothing is ever sent over it.
                using var data = new TcpClient();
                await data.ConnectAsync("127.0.0.1", dataPort);
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
            finally
            {
                await host.DisposeAsync();
            }
        }

        /// <summary>
        /// Once the client has selected <c>PROT P</c>, data transfers succeed even while
        /// <see cref="AuthTlsOptions.RequireProtectedDataConnections"/> is enabled.
        /// </summary>
        [Fact(Timeout = 60000)]
        public async Task Upload_WithProtP_WhenDataConnectionsMustBeProtected_Succeeds()
        {
            var host = new RequireProtectedDataConnectionsHost(RequireProtectedDataConnectionsHost.NullOutput);
            await host.InitializeAsync();
            try
            {
                using var client = CreateExplicitTlsClient(host.Server.Port, dataConnectionEncryption: true);
                await client.Connect();

                await client.UploadBytes(Encoding.UTF8.GetBytes("protected upload"), "protected.txt");

                var temp = new MemoryStream();
                await client.DownloadStream(temp, "protected.txt");
                Assert.Equal("protected upload", Encoding.UTF8.GetString(temp.ToArray()));
            }
            finally
            {
                await host.DisposeAsync();
            }
        }

        private static AsyncFtpClient CreateExplicitTlsClient(int port, bool dataConnectionEncryption)
        {
            var client = new AsyncFtpClient("127.0.0.1", "anonymous", "test@test.net", port);
            client.Config.EncryptionMode = FtpEncryptionMode.Explicit;
            client.Config.DataConnectionEncryption = dataConnectionEncryption;
            client.Config.ValidateAnyCertificate = true;
            return client;
        }

        private static async Task WriteCommandAsync(NetworkStream stream, string command)
        {
            var bytes = Encoding.ASCII.GetBytes(command + "\r\n");
            await stream.WriteAsync(bytes);
            await stream.FlushAsync();
        }

        /// <summary>
        /// Reads lines until a final (non-continuation) FTP reply line, e.g. <c>530 Not logged in.</c>.
        /// A single <see cref="NetworkStream.ReadAsync(System.Memory{byte})"/> call is not
        /// guaranteed to return exactly one reply (or a whole one): TCP gives no such boundary.
        /// </summary>
        private static async Task<string> ReadReplyAsync(NetworkStream stream)
        {
            while (true)
            {
                var line = await ReadLineAsync(stream);
                if (line.Length >= 4 && char.IsDigit(line[0]) && line[3] == ' ')
                {
                    return line;
                }
            }
        }

        private static async Task<string> ReadLineAsync(NetworkStream stream)
        {
            var builder = new StringBuilder();
            var buffer = new byte[1];
            while (true)
            {
                var read = await stream.ReadAsync(buffer, CancellationToken.None);
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

        private static int ParsePasvPort(string pasvReply)
        {
            var match = Regex.Match(pasvReply, @"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)");
            return (int.Parse(match.Groups[5].Value) * 256) + int.Parse(match.Groups[6].Value);
        }

        private static X509Certificate2 CreateSelfSignedCertificate()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest(
                "CN=localhost",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            var certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddMinutes(5));

#pragma warning disable SYSLIB0057 // X509CertificateLoader isn't available on netstandard2.1.
            return new X509Certificate2(
                certificate.Export(X509ContentType.Pfx),
                (string?)null,
                X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
        }

        /// <summary>
        /// A server configured with a self-signed certificate and
        /// <see cref="AuthTlsOptions.RequireTlsForLogin"/>.
        /// </summary>
        private sealed class RequireTlsForLoginHost : FtpServerTestsBase
        {
            public static readonly ITestOutputHelper NullOutput = new NullTestOutputHelper();

            private readonly bool _requireTlsForLogin;

            public RequireTlsForLoginHost(ITestOutputHelper testOutputHelper, bool requireTlsForLogin = true)
                : base(testOutputHelper)
            {
                _requireTlsForLogin = requireTlsForLogin;
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
                        });
            }
        }

        /// <summary>
        /// A server configured with a self-signed certificate and
        /// <see cref="AuthTlsOptions.RequireProtectedDataConnections"/>.
        /// </summary>
        private sealed class RequireProtectedDataConnectionsHost : FtpServerTestsBase
        {
            public static readonly ITestOutputHelper NullOutput = new NullTestOutputHelper();

            public RequireProtectedDataConnectionsHost(ITestOutputHelper testOutputHelper)
                : base(testOutputHelper)
            {
            }

            protected override IServiceCollection Configure(IServiceCollection services)
            {
                var certificate = CreateSelfSignedCertificate();
                return base.Configure(services)
                   .Configure<AuthTlsOptions>(
                        opt =>
                        {
                            opt.ServerCertificate = certificate;
                            opt.RequireProtectedDataConnections = true;
                        });
            }
        }

        private sealed class NullTestOutputHelper : ITestOutputHelper
        {
            public void WriteLine(string message)
            {
            }

            public void WriteLine(string format, params object[] args)
            {
            }
        }
    }
}
