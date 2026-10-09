// <copyright file="StreamPipeWriterServiceTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using FubarDev.FtpServer.Networking;

using Microsoft.Extensions.Logging;

using Xunit;

namespace FubarDev.FtpServer.Tests
{
    /// <summary>
    /// Regression test for upstream FubarDevelopment/FtpServer#166: when a client (e.g. a TCP
    /// health probe) resets or aborts the connection while the server is writing to it (commonly
    /// while sending the 220 banner), the write fails with an <see cref="IOException"/> wrapping
    /// a <see cref="SocketException"/>. That is a client-initiated event, not a server problem, so
    /// it should be logged at Debug level, not Warning - and the send loop should simply end
    /// instead of rethrowing.
    /// </summary>
    public class StreamPipeWriterServiceTests
    {
        [Theory]
        [InlineData(SocketError.ConnectionReset)]
        [InlineData(SocketError.ConnectionAborted)]
        [InlineData(SocketError.Shutdown)]
        public async Task ExecuteAsync_PeerResetWhileSending_LogsAtDebugNotWarningAsync(SocketError socketError)
        {
            var pipe = new Pipe();
            await pipe.Writer.WriteAsync(Encoding.ASCII.GetBytes("220 test banner\r\n"));
            await pipe.Writer.CompleteAsync();

            var logger = new RecordingLogger();
            var stream = new PeerResetStream(socketError);
            var service = new StreamPipeWriterService(stream, pipe.Reader, CancellationToken.None, logger);

            await service.StartAsync(CancellationToken.None);
            await WaitUntilStoppedAsync(service);

            Assert.DoesNotContain(logger.Entries, e => e.Level >= LogLevel.Warning);
            Assert.Contains(
                logger.Entries,
                e => e.Level == LogLevel.Debug
                    && e.Message.Contains("remote peer closed the connection", StringComparison.OrdinalIgnoreCase));
        }

        private static async Task WaitUntilStoppedAsync(IPausableFtpService service)
        {
            var stopwatch = Stopwatch.StartNew();
            while (service.Status != FtpServiceStatus.Stopped && stopwatch.Elapsed < TimeSpan.FromSeconds(5))
            {
                await Task.Delay(10);
            }

            Assert.Equal(FtpServiceStatus.Stopped, service.Status);
        }

        /// <summary>
        /// A stream whose writes always fail the way a real socket does when the peer has
        /// reset/aborted the connection (verified empirically: on Linux/macOS this surfaces as an
        /// <see cref="IOException"/> wrapping a <see cref="SocketException"/> with
        /// <see cref="SocketError.Shutdown"/> ("Broken pipe"); on Windows it is typically
        /// <see cref="SocketError.ConnectionReset"/>).
        /// </summary>
        private sealed class PeerResetStream : Stream
        {
            private readonly SocketError _socketError;

            public PeerResetStream(SocketError socketError)
            {
                _socketError = socketError;
            }

            public override bool CanRead => false;

            public override bool CanSeek => false;

            public override bool CanWrite => true;

            public override long Length => throw new NotSupportedException();

            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                throw new IOException(
                    "Unable to write data to the transport connection.",
                    new SocketException((int)_socketError));
            }

            public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

            public override void Flush()
            {
            }

            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

            public override void SetLength(long value) => throw new NotSupportedException();

            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }

        private sealed class RecordingLogger : ILogger
        {
            public List<(LogLevel Level, string Message)> Entries { get; } = new List<(LogLevel, string)>();

            public IDisposable BeginScope<TState>(TState state)
                where TState : notnull
                => NullScope.Instance;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                Entries.Add((logLevel, formatter(state, exception)));
            }

            private sealed class NullScope : IDisposable
            {
                public static readonly NullScope Instance = new NullScope();

                public void Dispose()
                {
                }
            }
        }
    }
}
