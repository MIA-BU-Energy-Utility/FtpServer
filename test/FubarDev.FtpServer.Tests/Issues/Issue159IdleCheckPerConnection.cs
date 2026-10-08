// <copyright file="Issue159IdleCheckPerConnection.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using FubarDev.FtpServer.ConnectionChecks;
using FubarDev.FtpServer.Features;

using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using Xunit;

namespace FubarDev.FtpServer.Tests.Issues
{
    /// <summary>
    /// Regression test for https://github.com/FubarDevelopment/FtpServer/issues/159.
    /// </summary>
    /// <remarks>
    /// <see cref="ConnectionChecks.FtpConnectionIdleCheck"/> keeps per-connection state (last
    /// activity time, active data transfers) and subscribes to a single connection's events.
    /// Registering it as a singleton means it is constructed once, for whichever connection
    /// resolves it first, and that very instance is then handed out to every later connection
    /// -- so the idle check for every connection after the first ends up tracking the activity
    /// of the first connection instead of its own.
    /// </remarks>
    public class Issue159IdleCheckPerConnection
    {
        /// <summary>
        /// Each connection must get its own <see cref="ConnectionChecks.FtpConnectionIdleCheck"/>
        /// instance, bound to its own connection.
        /// </summary>
        [Fact]
        public void EachConnectionGetsItsOwnIdleCheckInstance()
        {
            var services = new ServiceCollection()
               .AddLogging()
               .AddFtpServer(builder => { });
            using var serviceProvider = services.BuildServiceProvider(validateScopes: true);

            using var scope1 = serviceProvider.CreateScope();
            var connection1 = new FakeFtpConnection();
            scope1.ServiceProvider.GetRequiredService<IFtpConnectionAccessor>().FtpConnection = connection1;
            var check1 = scope1.ServiceProvider
               .GetRequiredService<IEnumerable<IFtpConnectionCheck>>()
               .OfType<FtpConnectionIdleCheck>()
               .Single();

            using var scope2 = serviceProvider.CreateScope();
            var connection2 = new FakeFtpConnection();
            scope2.ServiceProvider.GetRequiredService<IFtpConnectionAccessor>().FtpConnection = connection2;
            var check2 = scope2.ServiceProvider
               .GetRequiredService<IEnumerable<IFtpConnectionCheck>>()
               .OfType<FtpConnectionIdleCheck>()
               .Single();

            Assert.NotSame(check1, check2);
        }

        /// <summary>
        /// A minimal <see cref="IFtpConnection"/> stub that provides just enough surface for
        /// <see cref="ConnectionChecks.FtpConnectionIdleCheck"/>'s constructor to run. None of
        /// the other members are exercised by this test.
        /// </summary>
        private sealed class FakeFtpConnection : IFtpConnection
        {
            public event EventHandler? Closed
            {
                add { }
                remove { }
            }

            public IServiceProvider ConnectionServices => throw new NotSupportedException();

            public IFeatureCollection Features => throw new NotSupportedException();

#pragma warning disable CS0618 // Type or member is obsolete
            public Encoding Encoding
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public FtpConnectionData Data => throw new NotSupportedException();

            public ILogger? Log => null;

            public Stream OriginalStream => throw new NotSupportedException();

            public Stream SocketStream
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public bool IsSecure => throw new NotSupportedException();
#pragma warning restore CS0618

            public CancellationToken CancellationToken => CancellationToken.None;

            public IPEndPoint LocalEndPoint => new IPEndPoint(IPAddress.Loopback, 0);

            public IPEndPoint RemoteEndPoint => new IPEndPoint(IPAddress.Loopback, 0);

#pragma warning disable CS0618 // Type or member is obsolete
            public Address RemoteAddress => throw new NotSupportedException();
#pragma warning restore CS0618

            public Task StartAsync() => throw new NotSupportedException();

            public Task StopAsync() => throw new NotSupportedException();

#pragma warning disable CS0618 // Type or member is obsolete
            public Task WriteAsync(IFtpResponse response, CancellationToken cancellationToken) =>
                throw new NotSupportedException();

            public Task WriteAsync(string response, CancellationToken cancellationToken) =>
                throw new NotSupportedException();
#pragma warning restore CS0618

            public Task<IFtpDataConnection> OpenDataConnectionAsync(TimeSpan? timeout = null, CancellationToken cancellationToken = default) =>
                throw new NotSupportedException();

#pragma warning disable CS0618 // Type or member is obsolete
            public Task<Stream> CreateEncryptedStream(Stream unencryptedStream) =>
                throw new NotSupportedException();
#pragma warning restore CS0618

            public void Dispose()
            {
            }
        }
    }
}
