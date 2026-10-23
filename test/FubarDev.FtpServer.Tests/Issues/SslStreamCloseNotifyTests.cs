// <copyright file="SslStreamCloseNotifyTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

using FubarDev.FtpServer.Authentication;

using Xunit;

namespace FubarDev.FtpServer.Tests.Issues
{
    /// <summary>
    /// Regression tests ensuring that closing an SSL stream sends a TLS close_notify
    /// alert instead of abruptly terminating the connection.
    /// </summary>
    /// <remarks>
    /// Without a close_notify, strict TLS clients (e.g. GnuTLS-based FileZilla) report
    /// "The TLS connection was non-properly terminated" / ECONNABORTED for directory
    /// listings and uploads. A bare socket close is not detectable by asking .NET's own
    /// <see cref="SslStream"/> client to read past it, because it treats a transport-level
    /// EOF without a close_notify as a clean end of stream too. So this test instead
    /// inspects the bytes actually written to the wire by the server side while closing:
    /// a close_notify is a TLS alert record, which starts with content type 0x15.
    /// </remarks>
    public class SslStreamCloseNotifyTests
    {
        [Fact(Timeout = 60000)]
        public async Task CloseStreamAsync_WritesTlsAlertRecord_ForCloseNotify()
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            using var certificate = CreateSelfSignedCertificate();

            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;

            var acceptTask = listener.AcceptTcpClientAsync();

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port).WaitAsync(cts.Token);

            using var server = await acceptTask.WaitAsync(cts.Token);

            var wireSpy = new WireSpyStream(server.GetStream());

            var factory = new DefaultSslStreamWrapperFactory();

            var serverStreamTask = factory.WrapStreamAsync(
                wireSpy,
                keepOpen: false,
                certificate,
                cts.Token);

            using var clientSslStream = new SslStream(
                client.GetStream(),
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, _, _, _) => true);

            // Pin to TLS 1.2: under TLS 1.3, the close_notify alert is itself encrypted
            // and travels inside an application_data record (content type 0x17), so the
            // 0x15 (plaintext alert record) assertion below only holds for TLS 1.2.
            var clientAuthTask = clientSslStream.AuthenticateAsClientAsync(
                "localhost",
                clientCertificates: null,
                enabledSslProtocols: System.Security.Authentication.SslProtocols.Tls12,
                checkCertificateRevocation: false);

            var serverStream = await serverStreamTask.WaitAsync(cts.Token);
            await clientAuthTask.WaitAsync(cts.Token);

            // Start observing writes only after the handshake, so we isolate the bytes
            // written while closing the server side the same way the FTP server does
            // for both its control and data connections.
            wireSpy.StartRecording();
            await factory.CloseStreamAsync(serverStream, cts.Token).WaitAsync(cts.Token);

            // Drain the client so the close can complete on both ends.
            var buffer = new byte[16];
            await clientSslStream.ReadAsync(buffer, 0, buffer.Length).WaitAsync(cts.Token);

            // A TLS alert record (the close_notify) starts with content type 0x15. A bare
            // socket close (no ShutdownAsync) writes nothing at all before disconnecting.
            Assert.True(wireSpy.RecordedBytes.Count > 0, "Expected the server to write a close_notify alert, but nothing was written to the wire.");
            Assert.Equal(0x15, wireSpy.RecordedBytes[0]);
        }

        [Fact(Timeout = 60000)]
        public async Task CloseStreamAsync_DoesNotThrow_WhenPeerAlreadyClosedTheConnection()
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            using var certificate = CreateSelfSignedCertificate();

            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;

            var acceptTask = listener.AcceptTcpClientAsync();

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port).WaitAsync(cts.Token);

            using var server = await acceptTask.WaitAsync(cts.Token);

            var factory = new DefaultSslStreamWrapperFactory();

            var serverStreamTask = factory.WrapStreamAsync(
                server.GetStream(),
                keepOpen: false,
                certificate,
                cts.Token);

            using (var clientSslStream = new SslStream(
                client.GetStream(),
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, _, _, _) => true))
            {
                var clientAuthTask = clientSslStream.AuthenticateAsClientAsync(
                    "localhost",
                    clientCertificates: null,
                    enabledSslProtocols: System.Security.Authentication.SslProtocols.Tls12,
                    checkCertificateRevocation: false);

                var serverStream = await serverStreamTask.WaitAsync(cts.Token);
                await clientAuthTask.WaitAsync(cts.Token);

                // Abruptly close the client side (no close_notify, no graceful FIN) to
                // simulate a peer that has already reset/closed the connection before
                // the server gets a chance to send its own close_notify.
                client.Client.Close(0);

                // Closing the (now peerless) stream must not throw and must still
                // dispose/close the underlying stream - this is the best-effort
                // handling added for the close_notify fix.
                var exception = await Record.ExceptionAsync(
                    () => factory.CloseStreamAsync(serverStream, cts.Token).WaitAsync(cts.Token));

                Assert.Null(exception);
            }
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

            // SslStream's server-side authentication requires the certificate's
            // private key to be re-importable; round-tripping through PKCS#12
            // ensures that on every platform.
#pragma warning disable SYSLIB0057 // X509CertificateLoader isn't available on netstandard2.1.
            return new X509Certificate2(
                certificate.Export(X509ContentType.Pfx),
                (string?)null,
                X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
        }

        /// <summary>
        /// A transparent stream wrapper that records the raw bytes written to the
        /// underlying transport once recording is enabled.
        /// </summary>
        private sealed class WireSpyStream : Stream
        {
            private readonly Stream _inner;
            private bool _recording;

            public WireSpyStream(Stream inner)
            {
                _inner = inner;
            }

            public System.Collections.Generic.List<byte> RecordedBytes { get; } = new System.Collections.Generic.List<byte>();

            public override bool CanRead => _inner.CanRead;

            public override bool CanSeek => _inner.CanSeek;

            public override bool CanWrite => _inner.CanWrite;

            public override long Length => _inner.Length;

            public override long Position
            {
                get => _inner.Position;
                set => _inner.Position = value;
            }

            public void StartRecording() => _recording = true;

            public override void Flush() => _inner.Flush();

            public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);

            public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);

            public override void SetLength(long value) => _inner.SetLength(value);

            public override void Write(byte[] buffer, int offset, int count)
            {
                Record(buffer, offset, count);
                _inner.Write(buffer, offset, count);
            }

            public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                Record(buffer, offset, count);
                return _inner.WriteAsync(buffer, offset, count, cancellationToken);
            }

            public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _inner.Dispose();
                }

                base.Dispose(disposing);
            }

            private void Record(byte[] buffer, int offset, int count)
            {
                if (_recording)
                {
                    for (var i = 0; i < count; i++)
                    {
                        RecordedBytes.Add(buffer[offset + i]);
                    }
                }
            }
        }
    }
}
