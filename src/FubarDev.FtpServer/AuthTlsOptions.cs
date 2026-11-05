// <copyright file="AuthTlsOptions.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System.Security.Cryptography.X509Certificates;

namespace FubarDev.FtpServer
{
    /// <summary>
    /// Options for SSL/TLS connections.
    /// </summary>
    public class AuthTlsOptions
    {
        /// <summary>
        /// Gets or sets the server certificate.
        /// </summary>
        public X509Certificate? ServerCertificate { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether implicit FTPS is used.
        /// </summary>
        public bool ImplicitFtps { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether a client must secure the control
        /// connection with <c>AUTH TLS</c> before issuing login commands such as
        /// <c>USER</c>, <c>PASS</c> and <c>ACCT</c>. When enabled, those commands are
        /// rejected with <c>530</c> until the control connection is TLS-secured.
        /// Defaults to <see langword="false"/> so existing deployments keep accepting
        /// plaintext logins unless they opt in.
        /// </summary>
        public bool RequireTlsForLogin { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether data-transfer commands (<c>RETR</c>,
        /// <c>STOR</c>, <c>APPE</c>, <c>LIST</c>, <c>NLST</c>, <c>MLSD</c>, ...) require the
        /// client to have selected <c>PROT P</c> beforehand. When enabled, those commands
        /// are rejected with <c>521</c> until the client switches the data channel
        /// protection level to <c>P</c>. Defaults to <see langword="false"/> so existing
        /// deployments keep allowing plaintext data connections unless they opt in.
        /// </summary>
        public bool RequireProtectedDataConnections { get; set; }
    }
}
