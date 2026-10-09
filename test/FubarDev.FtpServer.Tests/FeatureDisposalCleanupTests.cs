// <copyright file="FeatureDisposalCleanupTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.DependencyInjection;

using Xunit;
using Xunit.Abstractions;

namespace FubarDev.FtpServer.Tests
{
    /// <summary>
    /// Regression tests for https://github.com/FubarDevelopment/FtpServer/issues/147.
    /// </summary>
    public class FeatureDisposalCleanupTests : FtpServerTestsBase
    {
        public FeatureDisposalCleanupTests(ITestOutputHelper testOutputHelper)
            : base(testOutputHelper)
        {
        }

        private interface ISelfMutatingFeature
        {
        }

        private interface IMarkerFeature
        {
        }

        /// <summary>
        /// A feature whose disposal registers another (previously unset) feature on the same
        /// connection must not break the enumeration performed while disposing all features on
        /// connection shutdown. Otherwise the thrown exception escapes before the connection is
        /// marked closed, and the server leaks the connection forever.
        /// </summary>
        /// <returns>The task.</returns>
        [Fact]
        public async Task ConnectionIsReleasedWhenFeatureDisposalRegistersAnotherFeatureAsync()
        {
            using var client = new TcpClient();
            await client.ConnectAsync("127.0.0.1", Server.Port);

            // Read the banner, so that the connection fully starts and runs through the
            // normal command dispatcher shutdown path (as opposed to the early-close path).
            using (var stream = client.GetStream())
            using (var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true))
            {
                await reader.ReadLineAsync();
            }

            client.Close();

            await WaitUntilAsync(() => Server.Statistics.ActiveConnections == 0);

            Assert.Equal(0, Server.Statistics.ActiveConnections);
        }

        /// <inheritdoc />
        protected override IServiceCollection Configure(IServiceCollection services)
        {
            return base.Configure(services)
               .AddSingleton<IFtpConnectionConfigurator, SelfMutatingFeatureConfigurator>();
        }

        private static async Task WaitUntilAsync(Func<bool> condition)
        {
            var stopwatch = Stopwatch.StartNew();
            while (!condition() && stopwatch.Elapsed < TimeSpan.FromSeconds(10))
            {
                await Task.Delay(50);
            }
        }

        /// <summary>
        /// Registers a feature whose disposal mutates the connection's feature collection.
        /// </summary>
        private sealed class SelfMutatingFeatureConfigurator : IFtpConnectionConfigurator
        {
            /// <inheritdoc />
            public Task Configure(IFtpConnection connection, CancellationToken cancellationToken)
            {
                connection.Features.Set<ISelfMutatingFeature>(new SelfMutatingFeature(connection));
                return Task.CompletedTask;
            }
        }

        private sealed class MarkerFeature : IMarkerFeature
        {
        }

        /// <summary>
        /// Disposing this feature sets a brand-new feature type on the connection, simulating the
        /// kind of self-mutation that triggers "Collection was modified" when the owning loop
        /// enumerates <see cref="IFtpConnection.Features"/> directly instead of a snapshot.
        /// </summary>
        private sealed class SelfMutatingFeature : ISelfMutatingFeature, IDisposable
        {
            private readonly IFtpConnection _connection;

            public SelfMutatingFeature(IFtpConnection connection)
            {
                _connection = connection;
            }

            public void Dispose()
            {
                _connection.Features.Set<IMarkerFeature>(new MarkerFeature());
            }
        }
    }
}
