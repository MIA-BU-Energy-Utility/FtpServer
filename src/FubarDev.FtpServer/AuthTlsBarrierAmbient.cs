// <copyright file="AuthTlsBarrierAmbient.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System.Threading;

namespace FubarDev.FtpServer
{
    // Carries the reader's verdict for the one AUTH command currently being dispatched, scoped to that async call chain.
    internal static class AuthTlsBarrierAmbient
    {
        private static readonly AsyncLocal<FtpConnection.AuthBarrierInfo?> _current = new AsyncLocal<FtpConnection.AuthBarrierInfo?>();

        public static FtpConnection.AuthBarrierInfo? Current
        {
            get => _current.Value;
            set => _current.Value = value;
        }
    }
}
