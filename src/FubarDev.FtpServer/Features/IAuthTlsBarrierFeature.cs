// <copyright file="IAuthTlsBarrierFeature.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

namespace FubarDev.FtpServer.Features
{
    // Carries the reader's verdict for the one AUTH command currently being dispatched.
    internal interface IAuthTlsBarrierFeature
    {
        FtpConnection.AuthBarrierInfo Barrier { get; }
    }
}
