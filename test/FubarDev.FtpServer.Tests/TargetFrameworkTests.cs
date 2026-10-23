// <copyright file="TargetFrameworkTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System.Runtime.Versioning;

using FubarDev.FtpServer.Authentication;

using Xunit;

namespace FubarDev.FtpServer.Tests
{
    /// <summary>
    /// Guards against reintroducing multi-targeting of the shipped libraries: the
    /// shipped assemblies must only ever target net10.0.
    /// </summary>
    public class TargetFrameworkTests
    {
        [Fact]
        public void FtpServerAssembly_TargetsNet10()
        {
            AssertTargetsNet10(typeof(DefaultSslStreamWrapperFactory).Assembly);
        }

        [Fact]
        public void FtpServerAbstractionsAssembly_TargetsNet10()
        {
            AssertTargetsNet10(typeof(IFtpConnection).Assembly);
        }

        private static void AssertTargetsNet10(System.Reflection.Assembly assembly)
        {
            var attribute = assembly.GetCustomAttributes(typeof(TargetFrameworkAttribute), false);
            var targetFramework = Assert.Single(attribute) as TargetFrameworkAttribute;
            Assert.NotNull(targetFramework);
            Assert.Equal(".NETCoreApp,Version=v10.0", targetFramework!.FrameworkName);
        }
    }
}
