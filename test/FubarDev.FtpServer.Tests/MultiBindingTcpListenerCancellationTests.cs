// <copyright file="MultiBindingTcpListenerCancellationTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Net.Sockets;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

using Xunit;

namespace FubarDev.FtpServer.Tests
{
    /// <summary>
    /// Regression test for https://github.com/FubarDevelopment/FtpServer/issues/149: every call to
    /// <see cref="MultiBindingTcpListener.WaitAnyTcpClientAsync"/> used to register a
    /// <c>Task.Delay(-1, token)</c> continuation directly on the long-lived server cancellation
    /// token and never released it, so the registration (and the delay task behind it) leaked for
    /// as long as the server was running, one per accepted connection.
    /// </summary>
    public class MultiBindingTcpListenerCancellationTests
    {
        private const int Iterations = 5;

        private const BindingFlags AllInstanceMembers =
            BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance;

        [Fact]
        public async Task WaitAnyTcpClientAsyncDoesNotLeakCancellationRegistrationsAsync()
        {
            var listener = new MultiBindingTcpListener("127.0.0.1", 0);
            await listener.StartAsync();
            listener.StartAccepting();

            try
            {
                // Simulates the server's long-lived listener cancellation token, which is only
                // ever cancelled when the whole server shuts down.
                using var serverCts = new CancellationTokenSource();

                for (var i = 0; i < Iterations; i++)
                {
                    using var connectingClient = new TcpClient();
                    var connectTask = connectingClient.ConnectAsync("127.0.0.1", listener.Port);

                    using var acceptedClient = await listener.WaitAnyTcpClientAsync(serverCts.Token);
                    await connectTask;
                }

                // None of the completed calls above should have left a dangling
                // CancellationTokenRegistration behind on the long-lived token.
                var remaining = CountCancellationRegistrations(serverCts);
                Assert.Equal(0, remaining);
            }
            finally
            {
                listener.Stop();
            }
        }

        /// <summary>
        /// Walks the private callback linked list of a <see cref="CancellationTokenSource"/> to
        /// count the number of outstanding (not yet disposed) registrations. This relies on BCL
        /// implementation details of <see cref="CancellationTokenSource"/>, but is the only way to
        /// observe the leak directly rather than inferring it indirectly: before the fix, this
        /// count grows by one per call to <c>WaitAnyTcpClientAsync</c> and is never reduced; after
        /// the fix it is always back at zero once a call has returned.
        /// </summary>
        private static int CountCancellationRegistrations(CancellationTokenSource cts)
        {
            var registrationsField = Array.Find(
                typeof(CancellationTokenSource).GetFields(AllInstanceMembers),
                f => f.Name == "_registrations");
            Assert.NotNull(registrationsField);

            var registrations = registrationsField!.GetValue(cts);
            if (registrations == null)
            {
                return 0;
            }

            var callbacksField = Array.Find(
                registrations.GetType().GetFields(AllInstanceMembers),
                f => f.Name == "Callbacks");
            Assert.NotNull(callbacksField);

            var node = callbacksField!.GetValue(registrations);

            var count = 0;
            while (node != null)
            {
                count++;

                var nextField = Array.Find(
                    node.GetType().GetFields(AllInstanceMembers),
                    f => f.Name == "Next");
                Assert.NotNull(nextField);

                node = nextField!.GetValue(node);
            }

            return count;
        }
    }
}
