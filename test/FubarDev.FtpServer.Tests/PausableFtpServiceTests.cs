// <copyright file="PausableFtpServiceTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Collections.Generic;
using System.Runtime.ExceptionServices;
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
    /// it, so the test can invoke that callback itself only after the method under test has
    /// already thrown and disposed the semaphore - reproducing the crash on demand, every time.
    ///
    /// The capturing context is installed on a dedicated, throwaway <see cref="Thread"/> rather
    /// than the ambient thread-pool thread the test method itself runs on: xUnit runs test
    /// classes in separate collections concurrently by default, and
    /// <see cref="SynchronizationContext"/> is thread-local state that outlives a single
    /// `await` - installing it on a shared pool thread let it leak into unrelated,
    /// concurrently-running integration tests the first time this was tried (their own awaits
    /// got silently captured into this context's queue instead of running, timing out). A thread
    /// that is never returned to any pool cannot leak into anything else.
    /// </summary>
    public class PausableFtpServiceTests
    {
        [Fact]
        public void StartAsync_StatusCallbackFiresAfterCancellationDisposesSemaphore_DoesNotThrow()
        {
            RunOnIsolatedThread(capturingContext =>
            {
                using var alreadyCancelled = new CancellationTokenSource();
                alreadyCancelled.Cancel();

                var service = new ImmediateCompletionFtpService(CancellationToken.None);

                // The token is already cancelled, so WaitAsync throws immediately (as a
                // TaskCanceledException, a subclass of OperationCanceledException) and the
                // `using`-scoped semaphore inside StartAsync is disposed as it unwinds - exactly
                // as it is when a client's connection is torn down mid pause/resume.
                Assert.ThrowsAny<OperationCanceledException>(
                    () => service.StartAsync(alreadyCancelled.Token).GetAwaiter().GetResult());

                AssertCapturedCallbackDoesNotThrow(capturingContext);
            });
        }

        [Fact]
        public async Task ContinueAsync_StatusCallbackFiresAfterCancellationDisposesSemaphore_DoesNotThrow()
        {
            // ContinueAsync requires Status == Paused, so drive the service through a real
            // Start -> Pause cycle first, on the default (ThreadPool) context, before moving to
            // the isolated thread for the ContinueAsync call under test.
            var service = new ControllableFtpService(CancellationToken.None);
            await service.StartAsync(CancellationToken.None);
            await service.PauseAsync(CancellationToken.None);

            RunOnIsolatedThread(capturingContext =>
            {
                using var alreadyCancelled = new CancellationTokenSource();
                alreadyCancelled.Cancel();

                // Same race as StartAsync, in ContinueAsync's own using-scoped semaphore.
                Assert.ThrowsAny<OperationCanceledException>(
                    () => service.ContinueAsync(alreadyCancelled.Token).GetAwaiter().GetResult());

                AssertCapturedCallbackDoesNotThrow(capturingContext);
            });
        }

        private static void AssertCapturedCallbackDoesNotThrow(CapturingSynchronizationContext capturingContext)
        {
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

        /// <summary>
        /// Runs <paramref name="body"/> on a brand-new, joined-and-discarded thread with a
        /// <see cref="CapturingSynchronizationContext"/> installed as that thread's ambient
        /// context - never a pooled thread, so the context can't leak into any other test.
        /// </summary>
        private static void RunOnIsolatedThread(Action<CapturingSynchronizationContext> body)
        {
            ExceptionDispatchInfo? failure = null;
            var thread = new Thread(() =>
            {
                var capturingContext = new CapturingSynchronizationContext();
                SynchronizationContext.SetSynchronizationContext(capturingContext);
                try
                {
                    body(capturingContext);
                }
                catch (Exception ex)
                {
                    failure = ExceptionDispatchInfo.Capture(ex);
                }
            });
            thread.Start();
            thread.Join();
            failure?.Throw();
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

        /// <summary>
        /// A service whose ExecuteAsync blocks until either released explicitly or its
        /// cancellation token fires - lets a test drive a real Start/Pause/Continue lifecycle
        /// instead of completing every phase instantaneously.
        /// </summary>
        private sealed class ControllableFtpService : PausableFtpService
        {
            public ControllableFtpService(CancellationToken connectionClosed)
                : base(connectionClosed)
            {
            }

            protected override async Task ExecuteAsync(CancellationToken cancellationToken)
            {
                var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                using (cancellationToken.Register(() => gate.TrySetResult()))
                {
                    await gate.Task.ConfigureAwait(false);
                }
            }
        }
    }
}
