// <copyright file="DefaultSslStreamWrapperFactory.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;

namespace FubarDev.FtpServer.Authentication
{
    /// <summary>
    /// The default implementation of the <see cref="ISslStreamWrapperFactory"/> interface.
    /// </summary>
    public class DefaultSslStreamWrapperFactory : ISslStreamWrapperFactory
    {
        private readonly ILogger<DefaultSslStreamWrapperFactory>? _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultSslStreamWrapperFactory"/> class.
        /// </summary>
        /// <param name="logger">The logger.</param>
        public DefaultSslStreamWrapperFactory(
            ILogger<DefaultSslStreamWrapperFactory>? logger = null)
        {
            _logger = logger;
        }

        /// <inheritdoc />
        public async Task<Stream> WrapStreamAsync(
            Stream unencryptedStream,
            bool keepOpen,
            X509Certificate certificate,
            CancellationToken cancellationToken)
        {
            try
            {
                _logger?.LogTrace("Create SSL stream");
                var sslStream = CreateSslStream(unencryptedStream, keepOpen);
                try
                {
                    _logger?.LogTrace("Authenticate as server");
                    await sslStream.AuthenticateAsServerAsync(certificate)
                       .ConfigureAwait(false);
                }
                catch
                {
                    sslStream.Dispose();
                    throw;
                }

                return sslStream;
            }
            catch (Exception ex)
            {
                _logger?.LogError(0, ex, ex.Message);
                throw;
            }
        }

        /// <inheritdoc />
        public async Task CloseStreamAsync(Stream sslStream, CancellationToken cancellationToken)
        {
            if (sslStream is SslStream s)
            {
                try
                {
                    await s.ShutdownAsync().ConfigureAwait(false);

                    // Why is this needed? I get a GnuTLS error -110 when it's not called!
                    await Task.Yield();

                    await s.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException)
                {
                    // The peer may already have closed or reset the connection (e.g. an
                    // FTP client aborting a transfer), so sending close_notify is
                    // best-effort: closing the stream below must still happen.
                    _logger?.LogDebug(0, ex, "Failed to send TLS close_notify");
                }
                finally
                {
                    s.Close();
                }
            }
        }

        /// <summary>
        /// Create a new <see cref="SslStream"/> instance.
        /// </summary>
        /// <param name="unencryptedStream">The stream to wrap in an <see cref="SslStream"/> instance.</param>
        /// <param name="keepOpen">Keep the inner stream open.</param>
        /// <returns>The new <see cref="SslStream"/>.</returns>
        protected virtual SslStream CreateSslStream(
            Stream unencryptedStream,
            bool keepOpen)
        {
            return new SslStream(unencryptedStream, keepOpen);
        }
    }
}
