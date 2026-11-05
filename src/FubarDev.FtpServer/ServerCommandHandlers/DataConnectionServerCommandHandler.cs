// <copyright file="DataConnectionServerCommandHandler.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Threading;
using System.Threading.Tasks;

using FubarDev.FtpServer.DataConnection;
using FubarDev.FtpServer.Events;
using FubarDev.FtpServer.Features;
using FubarDev.FtpServer.ServerCommands;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FubarDev.FtpServer.ServerCommandHandlers
{
    /// <summary>
    /// Handler for the <see cref="DataConnectionServerCommand"/>.
    /// </summary>
    public class DataConnectionServerCommandHandler : IServerCommandHandler<DataConnectionServerCommand>
    {
        private readonly IFtpConnectionAccessor _connectionAccessor;
        private readonly IOptions<AuthTlsOptions> _authTlsOptions;
        private readonly IOptions<PortCommandOptions> _portOptions;
        private readonly ILogger<DataConnectionServerCommandHandler>? _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="DataConnectionServerCommandHandler"/> class.
        /// </summary>
        /// <param name="connectionAccessor">The FTP connection accessor.</param>
        /// <param name="authTlsOptions">Options for SSL/TLS connections.</param>
        /// <param name="portOptions">The <c>PORT</c> command options.</param>
        /// <param name="logger">The logger.</param>
        public DataConnectionServerCommandHandler(
            IFtpConnectionAccessor connectionAccessor,
            IOptions<AuthTlsOptions> authTlsOptions,
            IOptions<PortCommandOptions> portOptions,
            ILogger<DataConnectionServerCommandHandler>? logger = null)
        {
            _connectionAccessor = connectionAccessor;
            _authTlsOptions = authTlsOptions;
            _portOptions = portOptions;
            _logger = logger;
        }

        /// <inheritdoc />
        public async Task ExecuteAsync(DataConnectionServerCommand command, CancellationToken cancellationToken)
        {
            var connection = _connectionAccessor.FtpConnection;
            var serverCommandWriter = connection.Features.Get<IServerCommandFeature>().ServerCommandWriter;
            var localizationFeature = connection.Features.Get<ILocalizationFeature>();

            // Single choke point for every command that opens a data connection (RETR, STOR,
            // APPE, LIST/NLST, MLSD, SITE BLST, ...): reject here instead of listing command
            // names, so nothing that transfers data over FTP-DATA can slip past this check. (A
            // command-name list in RequireTlsCommandMiddleware also rejects the well-known cases
            // before the 150 below is even sent; this is still what every command - known or not
            // - ultimately goes through.)
            if (_authTlsOptions.Value.RequireProtectedDataConnections
                && !connection.Features.Get<ISecureConnectionFeature>().IsDataConnectionProtected)
            {
                // A PASV listener (or an already-bound active-mode socket) was set up for this
                // command's data connection before it was even sent - close it instead of leaving
                // it accepting connections until the next PASV/PORT/REIN, which stalls clients
                // that connect to it expecting data that will now never arrive.
                var dataConnectionFeature = connection.Features.Get<IFtpDataConnectionFeature>();
                if (dataConnectionFeature != null)
                {
                    await dataConnectionFeature.DisposeAsync().ConfigureAwait(false);
                    var activeDataConnectionFeatureFactory =
                        connection.ConnectionServices.GetRequiredService<ActiveDataConnectionFeatureFactory>();
                    var connectionFeature = connection.Features.Get<IConnectionFeature>();
                    var replacementFeature = await activeDataConnectionFeatureFactory
                       .CreateFeatureAsync(null, connectionFeature.RemoteEndPoint, _portOptions.Value.DataPort)
                       .ConfigureAwait(false);
                    connection.Features.Set(replacementFeature);
                }

                var deniedResponse = new FtpResponse(
                    521,
                    localizationFeature.Catalog.GetString("Data connections must be encrypted."));
                await serverCommandWriter
                   .WriteAsync(new SendResponseServerCommand(deniedResponse), cancellationToken)
                   .ConfigureAwait(false);
                return;
            }

            using (new ConnectionKeepAlive(connection, command.Command))
            {
                // Try to open the data connection
                IFtpDataConnection dataConnection;
                try
                {
                    dataConnection = await connection.OpenDataConnectionAsync(null, cancellationToken)
                       .ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(0, ex, "Could not open data connection: {error}", ex.Message);
                    var errorResponse = new FtpResponse(
                        425,
                        localizationFeature.Catalog.GetString("Could not open data connection"));
                    await serverCommandWriter
                       .WriteAsync(new SendResponseServerCommand(errorResponse), cancellationToken)
                       .ConfigureAwait(false);
                    return;
                }

                // Execute the operation on the data connection.
                var commandResponse = await connection.ExecuteCommand(
                    command.Command,
                    (_, ct) => command.DataConnectionDelegate(dataConnection, ct),
                    _logger,
                    cancellationToken);
                var response =
                    commandResponse
                    ?? new FtpResponse(226, localizationFeature.Catalog.GetString("Closing data connection."));

                // We have to leave the connection open if the response code is 250.
                if (response.Code != 250)
                {
                    // Close the data connection.
                    await serverCommandWriter
                       .WriteAsync(new CloseDataConnectionServerCommand(dataConnection), cancellationToken)
                       .ConfigureAwait(false);
                }

                // Send the response.
                await serverCommandWriter
                   .WriteAsync(new SendResponseServerCommand(response), cancellationToken)
                   .ConfigureAwait(false);
            }
        }

        private class ConnectionKeepAlive : IDisposable
        {
            private readonly string _transferId = Guid.NewGuid().ToString("N");
            private readonly IFtpConnectionEventHost _eventHost;

            public ConnectionKeepAlive(
                IFtpConnection connection,
                FtpCommand command)
            {
                _eventHost = connection.Features.Get<IFtpConnectionEventHost>();
                _eventHost.PublishEvent(new FtpConnectionDataTransferStartedEvent(_transferId, command));
            }

            /// <inheritdoc />
            public void Dispose()
            {
                _eventHost.PublishEvent(new FtpConnectionDataTransferStoppedEvent(_transferId));
            }
        }
    }
}
