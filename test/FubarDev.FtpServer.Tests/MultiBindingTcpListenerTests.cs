// <copyright file="MultiBindingTcpListenerTests.cs" company="Fubar Development Junker">
// Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

using Xunit;

namespace FubarDev.FtpServer.Tests
{
    /// <summary>
    /// Regression test for the FTP server becoming "alive but deaf": a remote peer can reset a
    /// connection while it is still being accepted (e.g. during the TCP handshake), which makes
    /// <see cref="TcpListener.AcceptTcpClientAsync()"/> throw a <see cref="SocketException"/>
    /// instead of returning a client. Before the fix, <see cref="MultiBindingTcpListener"/> only
    /// caught <see cref="ObjectDisposedException"/> around that call, so the faulted accept task
    /// propagated out of <see cref="MultiBindingTcpListener.WaitAnyTcpClientAsync"/> and the
    /// listener stopped accepting any further connections for good, even though the process kept
    /// running (see upstream FubarDevelopment/FtpServer#165 and #90).
    ///
    /// Reproducing the real race (a peer resetting a connection mid-handshake) deterministically
    /// via actual sockets is not practical, so this test uses the <see
    /// cref="MultiBindingTcpListener.AcceptTcpClientOverride"/> test seam to simulate exactly one
    /// transient <see cref="SocketException"/> on the first accept, then asserts the listener
    /// still accepts the next (real) client instead of throwing.
    /// </summary>
    public class MultiBindingTcpListenerTests
    {
        [Fact]
        public async Task WaitAnyTcpClientAsync_SocketExceptionDuringAccept_StillAcceptsNextClient()
        {
            var listener = new MultiBindingTcpListener(IPAddress.Loopback.ToString(), 0);

            var acceptCalls = 0;
            listener.AcceptTcpClientOverride = tcpListener =>
            {
                if (Interlocked.Increment(ref acceptCalls) == 1)
                {
                    // Simulate a peer that reset the connection while it was being accepted.
                    throw new SocketException((int)SocketError.ConnectionReset);
                }

                return tcpListener.AcceptTcpClientAsync();
            };

            await listener.StartAsync();
            listener.StartAccepting();

            try
            {
                using var connectingClient = new TcpClient();
                await connectingClient.ConnectAsync(IPAddress.Loopback, listener.Port);

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

                // Before the fix, the simulated SocketException from the first (synthetic)
                // accept attempt faults the acceptor task, and that fault surfaces here
                // instead of the loop re-arming and waiting for a real client.
                using var acceptedClient = await listener.WaitAnyTcpClientAsync(cts.Token);

                Assert.True(acceptedClient.Connected);
                Assert.True(acceptCalls >= 2);
            }
            finally
            {
                listener.Stop();
            }
        }

        // A SocketException that is not one of the known per-client accept failures (e.g.
        // SocketError.TooManyOpenSockets, which indicates the process is out of file
        // descriptors) is a listener-level problem, not a transient per-connection one.
        // Silently swallowing and retrying it would turn a persistent failure into a hot
        // spin loop instead of surfacing it, so it must still propagate.
        [Fact]
        public async Task WaitAnyTcpClientAsync_NonPerClientSocketException_Propagates()
        {
            var listener = new MultiBindingTcpListener(IPAddress.Loopback.ToString(), 0);

            listener.AcceptTcpClientOverride =
                _ => throw new SocketException((int)SocketError.TooManyOpenSockets);

            await listener.StartAsync();
            listener.StartAccepting();

            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

                var aggregate = await Assert.ThrowsAsync<AggregateException>(
                    () => listener.WaitAnyTcpClientAsync(cts.Token));

                var socketException = Assert.IsType<SocketException>(aggregate.InnerException);
                Assert.Equal(SocketError.TooManyOpenSockets, socketException.SocketErrorCode);
            }
            finally
            {
                listener.Stop();
            }
        }
    }
}
