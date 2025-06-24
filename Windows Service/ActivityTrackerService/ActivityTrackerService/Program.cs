using System.ServiceProcess;

namespace ActivityTrackerService
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        static void Main()
        {
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new ActivityTrackerService()
            };
            ServiceBase.Run(ServicesToRun);
        }
    }
}