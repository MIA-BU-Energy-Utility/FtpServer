// <copyright file="ReinCommandHandlerTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using FubarDev.FtpServer.AccountManagement;
using FubarDev.FtpServer.Authentication;
using FubarDev.FtpServer.Authorization;
using FubarDev.FtpServer.CommandHandlers;
using FubarDev.FtpServer.DataConnection;
using FubarDev.FtpServer.Features;
using FubarDev.FtpServer.Features.Impl;
using FubarDev.FtpServer.FileSystem;
using FubarDev.FtpServer.Localization;

using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

using Xunit;

namespace FubarDev.FtpServer.Tests
{
    // R8: REIN must not dispose a connection-level (parent) feature it cannot actually remove.
    public class ReinCommandHandlerTests
    {
        private interface IDisposeProbe
        {
            bool Disposed { get; }
        }

        [Fact]
        public async Task Process_DoesNotDisposeParentFeature()
        {
            var probe = new DisposeProbe();
            var parent = new FeatureCollection();
            parent.Set<IDisposeProbe>(probe);
            parent.Set<IConnectionFeature>(new FakeConnectionFeature());
            parent.Set<ISecureConnectionFeature>(new FakeSecureConnectionFeature());

            var features = new FeatureCollection(parent);
            FtpConnectionData.InitializeSessionFeatures(features, Encoding.ASCII, new DefaultFtpCatalogLoader());

            var connectionAccessor = new FakeFtpConnectionAccessor();
            var services = new ServiceCollection()
               .AddSingleton<IFtpCatalogLoader, DefaultFtpCatalogLoader>()
               .AddSingleton<IFtpLoginStateMachine>(new FakeLoginStateMachine())
               .AddSingleton(new ActiveDataConnectionFeatureFactory(connectionAccessor, Array.Empty<IFtpDataConnectionValidator>()))
               .BuildServiceProvider();

            var connection = new FakeFtpConnection(features, services);
            connectionAccessor.FtpConnection = connection;

            var handler = new ReinCommandHandler(Options.Create(new PortCommandOptions()), new FakeServerMessages());
            handler.CommandContext = new FtpCommandHandlerContext(new FtpContext(new FtpCommand("REIN", string.Empty), null!, connection));

            var response = await handler.Process(new FtpCommand("REIN", string.Empty), CancellationToken.None);

            Assert.Equal(220, response!.Code);
            Assert.False(probe.Disposed, "REIN must not dispose a parent-layer feature it cannot remove.");
            Assert.Same(probe, features.Get<IDisposeProbe>());
        }

        private sealed class DisposeProbe : IDisposeProbe, IDisposable
        {
            public bool Disposed { get; private set; }

            public void Dispose() => Disposed = true;
        }

        private sealed class FakeConnectionFeature : IConnectionFeature
        {
            public IPEndPoint LocalEndPoint { get; } = new IPEndPoint(IPAddress.Loopback, 21);

            public IPEndPoint RemoteEndPoint { get; } = new IPEndPoint(IPAddress.Loopback, 0);

#pragma warning disable CS0618
            public Address RemoteAddress => throw new NotSupportedException();
#pragma warning restore CS0618
        }

        private sealed class FakeSecureConnectionFeature : ISecureConnectionFeature
        {
#pragma warning disable CS0618
            public System.Net.Sockets.NetworkStream OriginalStream => throw new NotSupportedException();
#pragma warning restore CS0618

            public CreateEncryptedStreamDelegate CreateEncryptedStream { get; set; } = Task.FromResult;

            public CloseEncryptedStreamDelegate CloseEncryptedControlStream { get; set; } = _ => Task.CompletedTask;

            public bool IsControlConnectionSecure { get; set; }

            public bool IsDataConnectionProtected { get; set; }
        }

        private sealed class FakeServerMessages : IFtpServerMessages
        {
            public IEnumerable<string> GetBannerMessage() => new[] { "test" };

            public IEnumerable<string> GetDirectoryChangedMessage(Stack<IUnixDirectoryEntry> path) => Array.Empty<string>();

            public IEnumerable<string> GetPasswordAuthorizationSuccessfulMessage(IAccountInformation accountInformation) => Array.Empty<string>();
        }

        private sealed class FakeLoginStateMachine : IFtpLoginStateMachine
        {
            public SecurityStatus Status => SecurityStatus.Unauthenticated;

            public IAuthenticationMechanism? SelectedAuthenticationMechanism => null;

            public IAuthorizationMechanism? SelectedAuthorizationMechanism => null;

            public void Reset()
            {
            }

            public void Activate(IAuthenticationMechanism authenticationMechanism) => throw new NotSupportedException();

            public Task<IFtpResponse?> ExecuteAsync(FtpCommand ftpCommand, CancellationToken cancellationToken = default) =>
                throw new NotSupportedException();
        }

        private sealed class FakeFtpConnectionAccessor : IFtpConnectionAccessor
        {
            public IFtpConnection FtpConnection { get; set; } = null!;
        }

        private sealed class FakeFtpConnection : IFtpConnection
        {
            public FakeFtpConnection(IFeatureCollection features, IServiceProvider connectionServices)
            {
                Features = features;
                ConnectionServices = connectionServices;
            }

            public event EventHandler? Closed
            {
                add { }
                remove { }
            }

            public IServiceProvider ConnectionServices { get; }

            public IFeatureCollection Features { get; }

#pragma warning disable CS0618
            public string ConnectionId { get; set; } = "fake";

            public Encoding Encoding
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public FtpConnectionData Data => throw new NotSupportedException();

            public Microsoft.Extensions.Logging.ILogger? Log => null;

            public System.IO.Stream OriginalStream => throw new NotSupportedException();

            public System.IO.Stream SocketStream
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public bool IsSecure => throw new NotSupportedException();

            public IPEndPoint LocalEndPoint => new IPEndPoint(IPAddress.Loopback, 21);

            public IPEndPoint RemoteEndPoint => new IPEndPoint(IPAddress.Loopback, 0);

            public Address RemoteAddress => throw new NotSupportedException();
#pragma warning restore CS0618

            public CancellationToken CancellationToken => CancellationToken.None;

            public Task StartAsync() => throw new NotSupportedException();

            public Task StopAsync() => throw new NotSupportedException();

#pragma warning disable CS0618
            public Task WriteAsync(IFtpResponse response, CancellationToken cancellationToken) =>
                throw new NotSupportedException();

            public Task WriteAsync(string response, CancellationToken cancellationToken) =>
                throw new NotSupportedException();

            public Task<System.IO.Stream> CreateEncryptedStream(System.IO.Stream unencryptedStream) =>
                throw new NotSupportedException();
#pragma warning restore CS0618

            public Task<IFtpDataConnection> OpenDataConnectionAsync(TimeSpan? timeout = null, CancellationToken cancellationToken = default) =>
                throw new NotSupportedException();

            public void Dispose()
            {
            }
        }
    }
}
