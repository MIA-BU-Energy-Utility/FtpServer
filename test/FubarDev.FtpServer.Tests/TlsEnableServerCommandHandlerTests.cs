// <copyright file="TlsEnableServerCommandHandlerTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.IO;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

using FubarDev.FtpServer.ConnectionHandlers;
using FubarDev.FtpServer.Features;
using FubarDev.FtpServer.Features.Impl;
using FubarDev.FtpServer.ServerCommandHandlers;
using FubarDev.FtpServer.ServerCommands;

using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Xunit;

namespace FubarDev.FtpServer.Tests
{
    /// <summary>
    /// <c>REIN</c> relies on <see cref="ISecureConnectionFeature.CloseEncryptedControlStream"/> -
    /// set up by <see cref="TlsEnableServerCommandHandler"/> once <c>AUTH TLS</c> succeeds - to
    /// reset both TLS state flags for the next session on the same connection. A pre-existing,
    /// unrelated bug in <c>REIN</c>'s own command handler (it clears <c>IEncodingFeature</c>,
    /// which every subsequent response - including its own - needs to be sent) crashes the
    /// connection before a black-box protocol test could observe the reset, so this exercises the
    /// reset mechanism directly instead.
    /// </summary>
    public class TlsEnableServerCommandHandlerTests
    {
        /// <summary>
        /// After <c>AUTH TLS</c> succeeds and the client selects <c>PROT P</c>, the delegate
        /// <c>REIN</c> calls to tear the control connection's TLS down again must reset both
        /// <see cref="ISecureConnectionFeature.IsControlConnectionSecure"/> and
        /// <see cref="ISecureConnectionFeature.IsDataConnectionProtected"/> - not just the former.
        /// </summary>
        /// <returns>The task.</returns>
        [Fact]
        public async Task CloseEncryptedControlStream_ResetsControlSecureAndDataProtectedFlags()
        {
            var secureConnectionFeature = new FakeSecureConnectionFeature();
            var serverCommandChannel = Channel.CreateUnbounded<IServerCommand>();
            var features = new FeatureCollection();
            features.Set<ISecureConnectionFeature>(secureConnectionFeature);
            features.Set<INetworkStreamFeature>(new FakeNetworkStreamFeature());
            features.Set<IServerCommandFeature>(new ServerCommandFeature(serverCommandChannel.Writer));

            var connectionAccessor = new FakeFtpConnectionAccessor
            {
                FtpConnection = new FakeFtpConnection(features),
            };

            using var certificate = CreateSelfSignedCertificate();
            var options = Options.Create(new AuthTlsOptions { ServerCertificate = certificate });
            var handler = new TlsEnableServerCommandHandler(connectionAccessor, options);

            var enableCommand = new TlsEnableServerCommand();
            await handler.ExecuteAsync(enableCommand, CancellationToken.None);
            await enableCommand.Completion;

            Assert.True(secureConnectionFeature.IsControlConnectionSecure);

            // Simulate the client having selected PROT P during the session.
            secureConnectionFeature.IsDataConnectionProtected = true;

            // This is exactly the delegate ReinCommandHandler calls.
            await secureConnectionFeature.CloseEncryptedControlStream(CancellationToken.None);

            Assert.False(secureConnectionFeature.IsControlConnectionSecure);
            Assert.False(secureConnectionFeature.IsDataConnectionProtected);
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

        private sealed class FakeFtpConnectionAccessor : IFtpConnectionAccessor
        {
            public IFtpConnection FtpConnection { get; set; } = null!;
        }

        private sealed class FakeNetworkStreamFeature : INetworkStreamFeature
        {
            public IFtpSecureConnectionAdapter SecureConnectionAdapter { get; } = new FakeSecureConnectionAdapter();

            public PipeWriter Output => throw new NotSupportedException();
        }

        private sealed class FakeSecureConnectionAdapter : IFtpSecureConnectionAdapter
        {
            public IFtpService Sender => throw new NotSupportedException();

            public IPausableFtpService Receiver => throw new NotSupportedException();

            public Task ResetAsync(CancellationToken cancellationToken) => Task.CompletedTask;

            public Task EnableSslStreamAsync(X509Certificate certificate, CancellationToken cancellationToken) => Task.CompletedTask;

            public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

            public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        }

        private sealed class FakeSecureConnectionFeature : ISecureConnectionFeature
        {
#pragma warning disable CS0618 // Type or member is obsolete
            public NetworkStream OriginalStream => throw new NotSupportedException();
#pragma warning restore CS0618

            public CreateEncryptedStreamDelegate CreateEncryptedStream { get; set; } = Task.FromResult;

            public CloseEncryptedStreamDelegate CloseEncryptedControlStream { get; set; } = _ => Task.CompletedTask;

            public bool IsControlConnectionSecure { get; set; }

            public bool IsDataConnectionProtected { get; set; }
        }

        /// <summary>
        /// A minimal <see cref="IFtpConnection"/> stub providing just enough surface for
        /// <see cref="TlsEnableServerCommandHandler"/> to run against a fake feature set. None of
        /// the other members are exercised by this test.
        /// </summary>
        private sealed class FakeFtpConnection : IFtpConnection
        {
            public FakeFtpConnection(IFeatureCollection features)
            {
                Features = features;
            }

            public event EventHandler? Closed
            {
                add { }
                remove { }
            }

            public IServiceProvider ConnectionServices => throw new NotSupportedException();

            public IFeatureCollection Features { get; }

#pragma warning disable CS0618 // Type or member is obsolete
            public Encoding Encoding
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public FtpConnectionData Data => throw new NotSupportedException();

            public ILogger? Log => null;

            public Stream OriginalStream => throw new NotSupportedException();

            public Stream SocketStream
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public bool IsSecure => throw new NotSupportedException();
#pragma warning restore CS0618

            public CancellationToken CancellationToken => CancellationToken.None;

            public IPEndPoint LocalEndPoint => new IPEndPoint(IPAddress.Loopback, 0);

            public IPEndPoint RemoteEndPoint => new IPEndPoint(IPAddress.Loopback, 0);

#pragma warning disable CS0618 // Type or member is obsolete
            public Address RemoteAddress => throw new NotSupportedException();
#pragma warning restore CS0618

            public Task StartAsync() => throw new NotSupportedException();

            public Task StopAsync() => throw new NotSupportedException();

#pragma warning disable CS0618 // Type or member is obsolete
            public Task WriteAsync(IFtpResponse response, CancellationToken cancellationToken) =>
                throw new NotSupportedException();

            public Task WriteAsync(string response, CancellationToken cancellationToken) =>
                throw new NotSupportedException();
#pragma warning restore CS0618

            public Task<IFtpDataConnection> OpenDataConnectionAsync(TimeSpan? timeout = null, CancellationToken cancellationToken = default) =>
                throw new NotSupportedException();

#pragma warning disable CS0618 // Type or member is obsolete
            public Task<Stream> CreateEncryptedStream(Stream unencryptedStream) =>
                throw new NotSupportedException();
#pragma warning restore CS0618

            public void Dispose()
            {
            }
        }
    }
}
