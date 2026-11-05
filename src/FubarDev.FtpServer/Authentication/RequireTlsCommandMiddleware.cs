// <copyright file="RequireTlsCommandMiddleware.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using FubarDev.FtpServer.Commands;
using FubarDev.FtpServer.Features;
using FubarDev.FtpServer.Localization;
using FubarDev.FtpServer.ServerCommands;

using Microsoft.Extensions.Options;

namespace FubarDev.FtpServer.Authentication
{
    /// <summary>
    /// Enforces <see cref="AuthTlsOptions.RequireTlsForLogin"/>, and provides a fast path for
    /// <see cref="AuthTlsOptions.RequireProtectedDataConnections"/>.
    /// </summary>
    /// <remarks>
    /// The authoritative enforcement of <see cref="AuthTlsOptions.RequireProtectedDataConnections"/>
    /// is in <see cref="ServerCommandHandlers.DataConnectionServerCommandHandler"/> - the single
    /// choke point every data-transfer command goes through to open its data connection, so no
    /// current or future command can slip past it. This middleware additionally rejects the
    /// well-known data-transfer commands here, before the <c>150</c> that handler would otherwise
    /// send first: RFC 4217 §9 expects an immediate <c>521</c>, and FluentFTP-style clients can
    /// stall for their data-connection read timeout waiting on a <c>150</c> that's never going to
    /// be followed by data. A command missing from this list still gets the correct (if slightly
    /// later) <c>521</c> from the choke point.
    /// </remarks>
    public class RequireTlsCommandMiddleware : IFtpCommandMiddleware
    {
        /// <summary>
        /// Commands a client must be able to use before the control connection is
        /// TLS-secured: negotiating TLS itself, and read-only/informational commands that
        /// carry no credentials or user data.
        /// </summary>
        private static readonly HashSet<string> _allowedBeforeLogin = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "AUTH", "ADAT", "FEAT", "SYST", "NOOP", "QUIT", "LOGOUT", "HELP", "OPTS", "PBSZ", "PROT", "LANG", "HOST",
        };

        /// <summary>
        /// The well-known commands that unconditionally open a data connection. Deliberately not
        /// exhaustive and not including e.g. <c>SITE</c> - see the remarks on this class: this is
        /// only a fast path, and <c>SITE BLST</c>'s data-vs-control behavior depends on its
        /// argument, which this middleware has no business parsing. The choke point is what
        /// actually has to be correct for every command.
        /// </summary>
        private static readonly HashSet<string> _knownDataTransferCommands = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "RETR", "STOR", "STOU", "APPE", "LIST", "NLST", "MLSD",
        };

        private readonly IOptions<AuthTlsOptions> _options;

        /// <summary>
        /// Initializes a new instance of the <see cref="RequireTlsCommandMiddleware"/> class.
        /// </summary>
        /// <param name="options">Options for SSL/TLS connections.</param>
        public RequireTlsCommandMiddleware(IOptions<AuthTlsOptions> options)
        {
            _options = options;
        }

        /// <inheritdoc />
        public Task InvokeAsync(FtpExecutionContext context, FtpCommandExecutionDelegate next)
        {
            var options = _options.Value;
            if (!options.RequireTlsForLogin && !options.RequireProtectedDataConnections)
            {
                return next(context);
            }

            var secureConnectionFeature = context.Connection.Features.Get<ISecureConnectionFeature>();

            if (options.RequireTlsForLogin
                && !secureConnectionFeature.IsControlConnectionSecure
                && !_allowedBeforeLogin.Contains(context.Command.Name))
            {
                return RejectAsync(context, 530, T(context, "TLS required: use AUTH TLS before logging in."));
            }

            if (options.RequireProtectedDataConnections
                && !secureConnectionFeature.IsDataConnectionProtected
                && _knownDataTransferCommands.Contains(context.Command.Name))
            {
                return RejectAsync(context, 521, T(context, "Data connections must be encrypted."));
            }

            return next(context);
        }

        private static async Task RejectAsync(FtpExecutionContext context, int code, string message)
        {
            await context.ServerCommandWriter
               .WriteAsync(
                    new SendResponseServerCommand(new FtpResponse(code, message)),
                    context.CommandAborted)
               .ConfigureAwait(false);
        }

        private static string T(FtpExecutionContext context, string message)
        {
            return context.Connection.Features.Get<ILocalizationFeature>().Catalog.GetString(message);
        }
    }
}
