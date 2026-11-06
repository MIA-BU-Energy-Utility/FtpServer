// <copyright file="PauseConnectionServerCommand.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System.Threading.Tasks;

namespace FubarDev.FtpServer.ServerCommands
{
    /// <summary>
    /// Pauses the connection (only RX).
    /// </summary>
    public class PauseConnectionServerCommand : IServerCommand
    {
        private readonly TaskCompletionSource<bool> _paused =
            new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>
        /// Gets a task resolving to <see langword="true"/> once the receiver is actually paused,
        /// or <see langword="false"/> if pausing it failed.
        /// </summary>
        public Task<bool> Paused => _paused.Task;

        /// <summary>
        /// Resolves <see cref="Paused"/>.
        /// </summary>
        /// <param name="paused">Whether the receiver is actually paused.</param>
        public void SignalPaused(bool paused) => _paused.TrySetResult(paused);
    }
}
