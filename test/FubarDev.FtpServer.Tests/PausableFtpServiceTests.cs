// <copyright file="PausableFtpServiceTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using FubarDev.FtpServer.Networking;

using Xunit;

namespace FubarDev.FtpServer.Tests
{
    /// <summary>
    /// Regression test for https://github.com/FubarDevelopment/FtpServer/issues/102 (also
    /// MIA-BU-Energy-Utility/melvapro#67): <see cref="PausableFtpService.StartAsync"/> and
    /// <see cref="PausableFtpService.ContinueAsync"/> race a <see cref="Progress{T}"/> callback's
    /// <see cref="SemaphoreSlim.Release()"/> against the enclosing <c>using</c> block's disposal
    /// of that same semaphore. In production this depends on real ThreadPool scheduling and a
    /// client disconnecting at exactly the wrong moment, which makes it unreliable to reproduce
    /// end-to-end. Here, a capturing <see cref="SynchronizationContext"/> pins down the ordering
    /// deterministically: it records the <see cref="Progress{T}"/> callback instead of running
    /// it, so the test can invoke that callback itself only after <see cref="StartAsync"/> has
    /// already thrown and disposed the semaphore - reproducing the crash on demand, every time.
    /// </summary>
    public class PausableFtpServiceTests
    {
        [Fact]
        public async Task StartAsync_StatusCallbackFiresAfterCancellationDisposesSemaphore_DoesNotThrow()
        {
            var capturingContext = new CapturingSynchronizationContext();
            var previousContext = SynchronizationContext.Current;
            SynchronizationContext.SetSynchronizationContext(capturingContext);

            try
            {
                using var alreadyCancelled = new CancellationTokenSource();
                alreadyCancelled.Cancel();

                var service = new ImmediateCompletionFtpService(CancellationToken.None);

                // The token is already cancelled, so WaitAsync throws immediately (as a
                // TaskCanceledException, a subclass of OperationCanceledException) and the
                // `using`-scoped semaphore inside StartAsync is disposed as it unwinds - exactly
                // as it is when a client's connection is torn down mid pause/resume.
                await Assert.ThrowsAnyAsync<OperationCanceledException>(
                    () => service.StartAsync(alreadyCancelled.Token));
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(previousContext);
            }

            Assert.True(
                capturingContext.Captured.Count > 0,
                "the status Progress<T> should have posted its 'Running' callback to the ambient context");

            // This callback was captured, not invoked, above - simulating it being posted to the
            // real ThreadPool and running after the semaphore was already disposed. Invoking it
            // now reproduces the crash trigger on demand: a Progress<T> callback that outlives
            // the semaphore it reports to must not crash the process.
            var invokeCapturedCallback = capturingContext.Captured.Dequeue();
            invokeCapturedCallback();
        }

        private sealed class CapturingSynchronizationContext : SynchronizationContext
        {
            public Queue<Action> Captured { get; } = new Queue<Action>();

            public override void Post(SendOrPostCallback d, object? state) => Captured.Enqueue(() => d(state));
        }

        private sealed class ImmediateCompletionFtpService : PausableFtpService
        {
            public ImmediateCompletionFtpService(CancellationToken connectionClosed)
                : base(connectionClosed)
            {
            }

            protected override Task ExecuteAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        }
    }
}
