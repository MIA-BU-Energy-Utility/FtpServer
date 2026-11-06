// <copyright file="TlsEnableServerCommand.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System.Threading.Tasks;

namespace FubarDev.FtpServer.ServerCommands
{
    /// <summary>
    /// Command to be sent to enable TLS for the control connection.
    /// </summary>
    public class TlsEnableServerCommand : IServerCommand
    {
        private readonly TaskCompletionSource<object?> _completion =
            new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>
        /// Gets a task that completes once the handler has finished trying to enable TLS
        /// (successfully or not). <c>AUTH TLS</c> awaits this before returning its own
        /// response, so the command dispatcher cannot move on to the next already-collected
        /// command until the control connection is actually secured.
        /// </summary>
        public Task Completion => _completion.Task;

        /// <summary>
        /// Signals that the handler has finished processing this command.
        /// </summary>
        public void SignalCompletion() => _completion.TrySetResult(null);
    }
}
