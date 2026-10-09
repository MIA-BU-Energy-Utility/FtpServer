// <copyright file="Issue131UnobservedReadTaskException.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading.Tasks;

using FluentFTP;

using Xunit;
using Xunit.Abstractions;

namespace FubarDev.FtpServer.Tests.Issues
{
    /// <summary>
    /// Regression test for https://github.com/FubarDevelopment/FtpServer/issues/131.
    /// </summary>
    /// <remarks>
    /// <see cref="TaskScheduler.UnobservedTaskException"/> is a process-global event, so this
    /// test runs in a dedicated, non-parallel collection and only counts exceptions of types
    /// that are plausible for an abandoned socket read (rather than asserting on an empty
    /// global exception list).
    /// </remarks>
    [Collection(nameof(UnobservedTaskExceptionCollection))]
    public class Issue131UnobservedReadTaskException : FtpServerTestsBase
    {
        private const int Iterations = 20;

        public Issue131UnobservedReadTaskException(ITestOutputHelper testOutputHelper)
            : base(testOutputHelper)
        {
        }

        /// <summary>
        /// A client that disconnects with QUIT (which makes the server abort the connection
        /// while the raw socket read for the next command is still pending) must not leave the
        /// abandoned read task's exception unobserved.
        /// </summary>
        /// <returns>The task.</returns>
        [Fact]
        public async Task DisconnectingClientsDoesNotRaiseUnobservedTaskExceptionAsync()
        {
            var unobservedExceptions = new List<Exception>();

            void Handler(object? sender, UnobservedTaskExceptionEventArgs args)
            {
                foreach (var exception in args.Exception.Flatten().InnerExceptions)
                {
                    // The event is process-global, so other tests running concurrently in a
                    // different collection may surface unrelated, already-handled exceptions
                    // (e.g. the listener's accept loop being torn down). Only count exceptions
                    // that plausibly originate from an abandoned *read* of the client socket.
                    if (exception is OperationCanceledException or IOException or SocketException or ObjectDisposedException
                        && exception.StackTrace?.Contains("AcceptForListenerAsync") != true)
                    {
                        unobservedExceptions.Add(exception);
                    }
                }

                args.SetObserved();
            }

            TaskScheduler.UnobservedTaskException += Handler;
            try
            {
                for (var i = 0; i < Iterations; i++)
                {
                    var client = new AsyncFtpClient("127.0.0.1", "anonymous", "test@test.net", Server.Port);
                    await client.Connect();
                    await client.Disconnect();
                    client.Dispose();
                }

                // Give the abandoned read tasks a chance to actually fault before we force
                // finalization below.
                await Task.Delay(TimeSpan.FromMilliseconds(500));

                for (var i = 0; i < 3; i++)
                {
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                }
            }
            finally
            {
                TaskScheduler.UnobservedTaskException -= Handler;
            }

            Assert.Empty(unobservedExceptions);
        }
    }
}
