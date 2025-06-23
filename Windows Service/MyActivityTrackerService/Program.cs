using ActivityTrackerService; // Namespace of your worker service
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;

namespace ActivityTrackerService
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseWindowsService() // This is crucial for running as a Windows Service
                .ConfigureServices((hostContext, services) =>
                {
                    services.AddHostedService<Worker>(); // Register your Worker as a hosted service
                });
    }
}