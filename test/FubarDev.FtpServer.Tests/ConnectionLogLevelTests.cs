// <copyright file="ConnectionLogLevelTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading.Tasks;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using Xunit;
using Xunit.Abstractions;

namespace FubarDev.FtpServer.Tests
{
    public class ConnectionLogLevelTests : FtpServerTestsBase
    {
        private readonly RecordingLoggerProvider _loggerProvider = new RecordingLoggerProvider();

        public ConnectionLogLevelTests(ITestOutputHelper testOutputHelper)
            : base(testOutputHelper)
        {
        }

        /// <summary>
        /// An ordinary connect/disconnect (e.g. a health probe) must not be logged at
        /// Information level or higher for the per-connection <see cref="FtpConnection"/>
        /// category, so that frequent probes don't flood Information-level logging.
        /// </summary>
        /// <returns>The task.</returns>
        [Fact]
        public async Task OrdinaryDisconnectIsNotLoggedAtInformationLevelAsync()
        {
            using (var client = new TcpClient())
            {
                await client.ConnectAsync("127.0.0.1", Server.Port);
                client.Close();
            }

            await WaitUntilAsync(() => Server.Statistics.TotalConnections >= 1);
            await WaitUntilAsync(() => Server.Statistics.ActiveConnections == 0);

            Assert.Equal(0, Server.Statistics.ActiveConnections);

            var offendingEntries = _loggerProvider.Entries.FindAll(
                e => e.Category == "FubarDev.FtpServer.FtpConnection" && e.Level >= LogLevel.Information);

            Assert.Empty(offendingEntries);
        }

        /// <inheritdoc />
        protected override IServiceCollection Configure(IServiceCollection services)
        {
            services = base.Configure(services);
            services.AddSingleton<ILoggerProvider>(_loggerProvider);
            return services;
        }

        private static async Task WaitUntilAsync(Func<bool> condition)
        {
            var stopwatch = Stopwatch.StartNew();
            while (!condition() && stopwatch.Elapsed < TimeSpan.FromSeconds(10))
            {
                await Task.Delay(50);
            }
        }

        private sealed class LogEntry
        {
            public LogEntry(string category, LogLevel level, string message)
            {
                Category = category;
                Level = level;
                Message = message;
            }

            public string Category { get; }

            public LogLevel Level { get; }

            public string Message { get; }
        }

        private sealed class RecordingLoggerProvider : ILoggerProvider
        {
            private readonly ConcurrentBag<LogEntry> _entries = new ConcurrentBag<LogEntry>();

            public List<LogEntry> Entries => new List<LogEntry>(_entries);

            public ILogger CreateLogger(string categoryName)
            {
                return new RecordingLogger(categoryName, _entries);
            }

            public void Dispose()
            {
            }

            private sealed class RecordingLogger : ILogger
            {
                private readonly string _categoryName;
                private readonly ConcurrentBag<LogEntry> _entries;

                public RecordingLogger(string categoryName, ConcurrentBag<LogEntry> entries)
                {
                    _categoryName = categoryName;
                    _entries = entries;
                }

                public IDisposable BeginScope<TState>(TState state)
                    where TState : notnull
                {
                    return NullScope.Instance;
                }

                public bool IsEnabled(LogLevel logLevel)
                {
                    return true;
                }

                public void Log<TState>(
                    LogLevel logLevel,
                    EventId eventId,
                    TState state,
                    Exception? exception,
                    Func<TState, Exception?, string> formatter)
                {
                    _entries.Add(new LogEntry(_categoryName, logLevel, formatter(state, exception)));
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
}
