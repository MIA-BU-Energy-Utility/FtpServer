// <copyright file="ISecureConnectionFeature.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Net.Sockets;

namespace FubarDev.FtpServer.Features
{
    /// <summary>
    /// Information about low-level connection information.
    /// </summary>
    public interface ISecureConnectionFeature
    {
        /// <summary>
        /// Gets the control connection stream.
        /// </summary>
        [Obsolete("Unused and will be removed.")]
        NetworkStream OriginalStream { get; }

        /// <summary>
        /// Gets or sets a delegate that allows the creation of an encrypted stream.
        /// </summary>
        CreateEncryptedStreamDelegate CreateEncryptedStream { get; set; }

        /// <summary>
        /// Gets or sets a delegate that closes an encrypted control stream.
        /// </summary>
        /// <remarks>This doesn't apply to encrypted data streams.</remarks>
        CloseEncryptedStreamDelegate CloseEncryptedControlStream { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the control connection is currently
        /// secured with TLS, either because <c>AUTH TLS</c> succeeded or because the
        /// connection uses implicit FTPS.
        /// </summary>
        bool IsControlConnectionSecure { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the client requested protected data
        /// connections through <c>PROT P</c>. <c>PROT C</c> (the default) resets this to
        /// <see langword="false"/>.
        /// </summary>
        bool IsDataConnectionProtected { get; set; }
    }
}
