// <copyright file="AuthTlsBarrierFeature.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

namespace FubarDev.FtpServer.Features.Impl
{
    internal sealed class AuthTlsBarrierFeature : IAuthTlsBarrierFeature
    {
        public AuthTlsBarrierFeature(FtpConnection.AuthBarrierInfo barrier)
        {
            Barrier = barrier;
        }

        /// <inheritdoc />
        public FtpConnection.AuthBarrierInfo Barrier { get; }
    }
}
