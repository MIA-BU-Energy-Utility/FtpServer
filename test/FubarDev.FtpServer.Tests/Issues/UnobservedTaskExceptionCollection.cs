// <copyright file="UnobservedTaskExceptionCollection.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System.Threading.Tasks;

using Xunit;

namespace FubarDev.FtpServer.Tests.Issues
{
    /// <summary>
    /// Collection definition used to ensure tests observing the process-global
    /// <see cref="TaskScheduler.UnobservedTaskException"/> event don't run concurrently with
    /// each other.
    /// </summary>
    [CollectionDefinition(nameof(UnobservedTaskExceptionCollection), DisableParallelization = true)]
    public class UnobservedTaskExceptionCollection
    {
    }
}
