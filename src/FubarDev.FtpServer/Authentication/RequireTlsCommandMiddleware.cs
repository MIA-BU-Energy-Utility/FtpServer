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
    /// Enforces <see cref="AuthTlsOptions.RequireTlsForLogin"/> and
    /// <see cref="AuthTlsOptions.RequireProtectedDataConnections"/>.
    /// </summary>
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
        /// Commands that open a data connection and therefore need <c>PROT P</c> when
        /// protected data connections are required.
        /// </summary>
        private static readonly HashSet<string> _dataTransferCommands = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "RETR", "STOR", "APPE", "LIST", "NLST", "LS", "MLSD",
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
            var commandName = context.Command.Name;

            if (options.RequireTlsForLogin
                && !secureConnectionFeature.IsControlConnectionSecure
                && !_allowedBeforeLogin.Contains(commandName))
            {
                return RejectAsync(context, 530, T(context, "TLS required: use AUTH TLS before logging in."));
            }

            if (options.RequireProtectedDataConnections
                && !secureConnectionFeature.IsDataConnectionProtected
                && _dataTransferCommands.Contains(commandName))
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
