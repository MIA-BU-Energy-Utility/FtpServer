// <copyright file="ClaimsPrincipalExtensions.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Linq;
using System.Security.Claims;

using FubarDev.FtpServer.AccountManagement;

namespace FubarDev.FtpServer
{
    /// <summary>
    /// Extension methods for <see cref="ClaimsPrincipal"/>.
    /// </summary>
    public static class ClaimsPrincipalExtensions
    {
        /// <summary>
        /// Checks if the principal represents an anonymous user.
        /// </summary>
        /// <param name="principal">The principal to check.</param>
        /// <returns><see langword="true"/> when the principal contains an anonymous identity.</returns>
        public static bool IsAnonymous(this ClaimsPrincipal principal)
        {
            return principal.Identities.Any(x => x.IsAnonymous());
        }

        /// <summary>
        /// Gets the user name of an FTP user.
        /// </summary>
        /// <param name="principal">The FTP user.</param>
        /// <returns>
        /// The user name, or <see langword="null"/> if the identity has no name claim.
        /// </returns>
        public static string GetUserName(this ClaimsPrincipal principal)
        {
            // ClaimsPrincipal.Identity is only null if no identity was ever assigned,
            // which does not happen for an authenticated FTP user. Name itself can
            // legitimately be null when the identity has no name claim.
            return principal.Identity?.Name!;
        }

        /// <summary>
        /// Checks if the principal represents an unix user.
        /// </summary>
        /// <param name="principal">The principal to check.</param>
        /// <returns><see langword="true"/> when the principal contains an unix identity.</returns>
        public static bool IsUnixUser(this ClaimsPrincipal principal)
        {
            return !string.IsNullOrEmpty(principal.FindFirst(FtpClaimTypes.UserId)?.Value);
        }
    }
}
