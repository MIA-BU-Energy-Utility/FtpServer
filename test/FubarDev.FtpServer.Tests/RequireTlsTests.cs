// <copyright file="RequireTlsTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

using FluentFTP;
using FluentFTP.Exceptions;

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
        /// <see cref="AuthTlsOptions.RequireProtectedDataConnections"/> is enabled.
        /// </summary>
        [Fact(Timeout = 60000)]
        public async Task Upload_WithoutProtP_WhenDataConnectionsMustBeProtected_IsRejectedWith521()
        {
            var host = new RequireProtectedDataConnectionsHost(RequireProtectedDataConnectionsHost.NullOutput);
            await host.InitializeAsync();
            try
            {
                using var client = new AsyncFtpClient("127.0.0.1", "anonymous", "test@test.net", host.Server.Port);
                await client.Connect();

                var exception = await Assert.ThrowsAsync<FtpException>(
                    () => client.UploadBytes(Encoding.UTF8.GetBytes("plaintext upload"), "plain.txt"));

                var commandException = Assert.IsType<FtpCommandException>(exception.InnerException);
                Assert.Equal("521", commandException.CompletionCode);
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
        /// Reads a single (non-continuation) FTP reply line, e.g. <c>530 Not logged in.</c>.
        /// </summary>
        private static async Task<string> ReadReplyAsync(NetworkStream stream)
        {
            var buffer = new byte[4096];
            var read = await stream.ReadAsync(buffer);
            return Encoding.ASCII.GetString(buffer, 0, read).TrimEnd('\r', '\n');
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
