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
    /// Enforces <see cref="AuthTlsOptions.RequireTlsForLogin"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="AuthTlsOptions.RequireProtectedDataConnections"/> is enforced separately, in
    /// <see cref="ServerCommandHandlers.DataConnectionServerCommandHandler"/> - the single choke
    /// point every data-transfer command (RETR, STOR, APPE, LIST, NLST, MLSD, SITE BLST, ...)
    /// goes through to open its data connection, rather than a command-name list here that a new
    /// or overlooked command could slip past.
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
            if (!options.RequireTlsForLogin)
            {
                return next(context);
            }

            var secureConnectionFeature = context.Connection.Features.Get<ISecureConnectionFeature>();
            if (!secureConnectionFeature.IsControlConnectionSecure
                && !_allowedBeforeLogin.Contains(context.Command.Name))
            {
                return RejectAsync(context, 530, T(context, "TLS required: use AUTH TLS before logging in."));
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
