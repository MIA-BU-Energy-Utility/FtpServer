//-----------------------------------------------------------------------
// <copyright file="Program.cs" company="Fubar Development Junker">
//     Copyright (c) Fubar Development Junker. All rights reserved.
// </copyright>
// <author>Mark Junker</author>
//-----------------------------------------------------------------------

using System.Threading;
using System.Threading.Tasks;

using FubarDev.FtpServer;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace QuickStart.AspNetCoreHost
{
    internal static class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services
               .AddFtpServer(
                    ftpBuilder => ftpBuilder
                       .UseDotNetFileSystem()
                       .EnableAnonymousAuthentication())
               .AddHostedService<HostedFtpService>();

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.Run(context => context.Response.WriteAsync("Hello World!"));

            app.Run();
        }

        /// <summary>
        /// Generic host for the FTP server.
        /// </summary>
        private class HostedFtpService : IHostedService
        {
            private readonly IFtpServerHost _ftpServerHost;

            /// <summary>
            /// Initializes a new instance of the <see cref="HostedFtpService"/> class.
            /// </summary>
            /// <param name="ftpServerHost">The FTP server host that gets wrapped as a hosted service.</param>
            public HostedFtpService(
                IFtpServerHost ftpServerHost)
            {
                _ftpServerHost = ftpServerHost;
            }

            /// <inheritdoc />
            public Task StartAsync(CancellationToken cancellationToken)
            {
                return _ftpServerHost.StartAsync(cancellationToken);
            }

            /// <inheritdoc />
            public Task StopAsync(CancellationToken cancellationToken)
            {
                return _ftpServerHost.StopAsync(cancellationToken);
            }
        }
    }
}
