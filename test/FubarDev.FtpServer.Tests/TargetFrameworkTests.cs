// <copyright file="TargetFrameworkTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System.Runtime.Versioning;

using FubarDev.FtpServer.Authentication;

using Xunit;

namespace FubarDev.FtpServer.Tests
{
    /// <summary>
    /// Guards against reintroducing multi-targeting of the shipped libraries.
    /// </summary>
    /// <remarks>
    /// Multi-targeting (netstandard2.0/2.1) plus framework-conditional <c>#if</c> blocks
    /// is how the close_notify fix in <see cref="DefaultSslStreamWrapperFactory"/> was
    /// silently dead code for years: the TLS-shutdown branch was guarded by
    /// <c>NETCOREAPP || NET47</c>, which is never defined for a netstandard build. These
    /// tests make sure the shipped assemblies only ever target net10.0.
    /// </remarks>
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
