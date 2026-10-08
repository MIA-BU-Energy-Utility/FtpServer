// <copyright file="ConnectionCleanupTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading.Tasks;

using Xunit;
using Xunit.Abstractions;

namespace FubarDev.FtpServer.Tests
{
    public class ConnectionCleanupTests : FtpServerTestsBase
    {
        private const int Iterations = 20;

        public ConnectionCleanupTests(ITestOutputHelper testOutputHelper)
            : base(testOutputHelper)
        {
        }

        /// <summary>
        /// A client (e.g. a TCP health probe) that disconnects before reading the banner
        /// must not leave the connection registered on the server.
        /// </summary>
        /// <param name="reset">Whether to abort the connection with RST instead of closing it with FIN.</param>
        /// <returns>The task.</returns>
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task ConnectionClosedBeforeBannerIsReleasedAsync(bool reset)
        {
            for (var i = 0; i < Iterations; i++)
            {
                using var client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", Server.Port);
                if (reset)
                {
                    client.LingerState = new LingerOption(true, 0);
                }

                client.Close();
            }

            await WaitUntilAsync(() => Server.Statistics.TotalConnections == Iterations);
            await WaitUntilAsync(() => Server.Statistics.ActiveConnections == 0);

            Assert.Equal(0, Server.Statistics.ActiveConnections);
        }

        private static async Task WaitUntilAsync(Func<bool> condition)
        {
            var stopwatch = Stopwatch.StartNew();
            while (!condition() && stopwatch.Elapsed < TimeSpan.FromSeconds(10))
            {
                await Task.Delay(50);
            }
        }
    }
}
