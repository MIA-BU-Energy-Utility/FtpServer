// <copyright file="ReinCommandHandler.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Threading;
using System.Threading.Tasks;

using FubarDev.FtpServer.AccountManagement;
using FubarDev.FtpServer.Commands;
using FubarDev.FtpServer.DataConnection;
using FubarDev.FtpServer.Features;
using FubarDev.FtpServer.Features.Impl;
using FubarDev.FtpServer.Localization;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FubarDev.FtpServer.CommandHandlers
{
    /// <summary>
    /// Implementation of the <c>REIN</c> command.
    /// </summary>
    [FtpCommandHandler("REIN", isLoginRequired: false)]
    public class ReinCommandHandler : FtpCommandHandler
    {
        private readonly int? _dataPort;
        private readonly IFtpServerMessages _serverMessages;
        private readonly ILogger<ReinCommandHandler>? _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="ReinCommandHandler"/> class.
        /// </summary>
        /// <param name="portOptions">The PORT command options.</param>
        /// <param name="serverMessages">The FTP server messages.</param>
        /// <param name="logger">The logger.</param>
        public ReinCommandHandler(
            IOptions<PortCommandOptions> portOptions,
            IFtpServerMessages serverMessages,
            ILogger<ReinCommandHandler>? logger = null)
        {
            _dataPort = portOptions.Value.DataPort;
            _serverMessages = serverMessages;
            _logger = logger;
        }

        /// <inheritdoc />
        public override async Task<IFtpResponse?> Process(FtpCommand command, CancellationToken cancellationToken)
        {
            var authorizationInformationFeature = Connection.Features.Get<IAuthorizationInformationFeature>();
            var user = authorizationInformationFeature.FtpUser;
            var membershipProvider = authorizationInformationFeature.MembershipProvider;
            if (user != null && membershipProvider is IMembershipProviderAsync membershipProviderAsync)
            {
                await membershipProviderAsync.LogOutAsync(user, cancellationToken);
            }

            var connectionFeature = Connection.Features.Get<IConnectionFeature>();
            var defaultEncoding = Connection.Features.Get<IEncodingFeature>().DefaultEncoding;

            foreach (var featureItem in Connection.Features)
            {
                try
                {
                    switch (featureItem.Value)
                    {
                        case IFtpConnection _:
                            break;
                        case IFtpDataConnectionFeature f:
                            await f.DisposeAsync().ConfigureAwait(false);
                            break;
                        case IDisposable disposable:
                            disposable.Dispose();
                            break;
                    }
                }
                catch (Exception ex)
                {
                    // Ignore exceptions
                    _logger?.LogWarning(
                        ex,
                        "Failed to dispose feature of type {FeatureType}: {ErrorMessage}",
                        featureItem.Key,
                        ex.Message);
                }

                Connection.Features[featureItem.Key] = null;
            }

            var catalogLoader = Connection.ConnectionServices.GetRequiredService<IFtpCatalogLoader>();
            FtpConnectionData.InitializeSessionFeatures(Connection.Features, defaultEncoding, catalogLoader);
            Connection.Features.Set<IFtpDataConnectionConfigurationFeature>(new FtpDataConnectionConfigurationFeature());

            var loginStateMachine = Connection.ConnectionServices.GetRequiredService<IFtpLoginStateMachine>();
            loginStateMachine.Reset();

            var secureConnectionFeature = Connection.Features.Get<ISecureConnectionFeature>();
            await secureConnectionFeature.CloseEncryptedControlStream(cancellationToken)
               .ConfigureAwait(false);

            var activeDataConnectionFeatureFactory = Connection.ConnectionServices.GetRequiredService<ActiveDataConnectionFeatureFactory>();
            var dataConnectionFeature = await activeDataConnectionFeatureFactory.CreateFeatureAsync(null, connectionFeature.RemoteEndPoint, _dataPort)
               .ConfigureAwait(false);
            Connection.Features.Set(dataConnectionFeature);

            return new FtpResponseTextBlock(220, _serverMessages.GetBannerMessage());
        }
    }
}
