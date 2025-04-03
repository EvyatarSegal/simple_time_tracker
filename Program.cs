using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NAudio.CoreAudioApi;

class Program
{
    private static readonly string LogFilePath = "activity_log.txt";
    private static string _lastActiveWindow = "";
    private static readonly CancellationTokenSource Cts = new CancellationTokenSource();

    static async Task Main(string[] args)
    {
        Console.WriteLine("Activity Tracker Service Started...");
        InitializeLogFile();

        Task windowTrackingTask = StartActiveWindowTracking(Cts.Token);
        Task resourceMonitoringTask = StartResourceMonitoring(Cts.Token);

        Console.WriteLine("Press ENTER to stop...");
        Console.ReadLine();

        Cts.Cancel();
        await Task.WhenAll(windowTrackingTask, resourceMonitoringTask);

        Console.WriteLine("Activity Tracker Stopped.");
    }

    private static void InitializeLogFile()
    {
        if (!File.Exists(LogFilePath))
        {
            File.WriteAllText(LogFilePath, "Timestamp, Process Name, Window Title, Memory Usage (MB), CPU Usage (%), Process Audio Usage, IsActive, IsVisible\n");
        }
    }

    private static async Task StartActiveWindowTracking(CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                string activeWindow = GetActiveWindowTitle();
                if (activeWindow != _lastActiveWindow)
                {
                    _lastActiveWindow = activeWindow;
                    await LogActiveWindow(activeWindow);
                }
                await Task.Delay(1000, token);
            }
        }
        catch (TaskCanceledException)
        {
            Console.WriteLine("[INFO] Active window tracking stopped.");
        }
    }

    private static string GetActiveWindowTitle()
    {
        const int nChars = 256;
        IntPtr handle = GetForegroundWindow();
        StringBuilder buffer = new StringBuilder(nChars);
        return GetWindowText(handle, buffer, nChars) > 0 ? buffer.ToString() : "Unknown";
    }

    private static async Task LogActiveWindow(string windowTitle)
    {
        string processName = GetActiveProcessName();
        IntPtr hwnd = GetForegroundWindow();
        GetWindowThreadProcessId(hwnd, out uint processId);
        bool isActive = (hwnd == GetForegroundWindow());
        bool isVisible = IsWindowVisible(hwnd);
        float memoryUsageMB = 0;
        float cpuUsagePercentage = 0;
        Dictionary<int, bool> audioUsage = GetAudioUsage();
        bool processAudioUsage = audioUsage.GetValueOrDefault((int)processId, false);

        try
        {
            Process process = Process.GetProcessById((int)processId);
            memoryUsageMB = process.WorkingSet64 / (1024f * 1024f);
            cpuUsagePercentage = GetCpuUsage(process);
        }
        catch (Exception) { }

        string logEntry = $"{DateTime.Now}, {processName}, {windowTitle}, {memoryUsageMB:F2}, {cpuUsagePercentage:F2}, {processAudioUsage}, {isActive}, {isVisible}\n";

        int retryCount = 3;
        while (retryCount > 0)
        {
            try
            {
                await File.AppendAllTextAsync(LogFilePath, logEntry);
                Console.WriteLine($"Process: {processName}, Mb:{memoryUsageMB:F2}, CPU:{cpuUsagePercentage:F2}, Audio:{processAudioUsage}, Active:{isActive}, Visible:{isVisible}");
                return;
            }
            catch (IOException ex)
            {
                if (IsFileLocked(ex))
                {
                    retryCount--;
                    Console.WriteLine($"Log file locked. Retrying in 1 second... (Retries left: {retryCount})");
                    await Task.Delay(1000);
                }
                else
                {
                    Console.WriteLine($"Error writing to log file: {ex.Message}");
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error writing to log file: {ex.Message}");
                return;
            }
        }

        Console.WriteLine($"Failed to write to log file after multiple retries.");
    }

    private static string GetActiveProcessName()
    {
        IntPtr hwnd = GetForegroundWindow();
        GetWindowThreadProcessId(hwnd, out uint processId);
        try
        {
            return Process.GetProcessById((int)processId).ProcessName;
        }
        catch
        {
            return "Unknown";
        }
    }

    private static async Task StartResourceMonitoring(CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                await CheckResourceUsage();
                await Task.Delay(60 * 1000, token);
            }
        }
        catch (TaskCanceledException)
        {
            Console.WriteLine("[INFO] Resource monitoring stopped.");
        }
    }

    private static async Task CheckResourceUsage()
    {
        Dictionary<int, bool> audioUsage = GetAudioUsage();
        Dictionary<string, ResourceUsage> appUsage = new Dictionary<string, ResourceUsage>(); // Aggregate usage per app

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                bool processAudioUsage = audioUsage.GetValueOrDefault(process.Id, false);
                if ((process.ProcessName == "System" || process.ProcessName == "Idle" || string.IsNullOrEmpty(process.ProcessName) || process.MainWindowHandle == IntPtr.Zero) && !processAudioUsage)
                {
                    continue;
                }
                string ProcessName = process.ProcessName;
                IntPtr hwnd = process.MainWindowHandle;
                string windowTitle = process.MainWindowTitle; // Use MainWindowTitle to group by window
                bool isActive = (hwnd == GetForegroundWindow());
                bool isVisible = IsWindowVisible(hwnd);
                float memoryUsageMB = process.WorkingSet64 / (1024f * 1024f);
                float cpuUsagePercentage = GetCpuUsage(process);

                if (appUsage.ContainsKey(ProcessName))
                {
                    continue;
                }
                else
                {
                    appUsage[ProcessName] = new ResourceUsage
                    {
                        ProcessName = ProcessName,
                        WindowName = windowTitle,
                        MemoryUsageMB = memoryUsageMB,
                        CpuUsagePercentage = cpuUsagePercentage,
                        ProcessAudioUsage = processAudioUsage,
                        IsActive = isActive,
                        IsVisible = isVisible
                    };
                }
            }
            catch (Exception) { }
        }
        foreach (var process2 in Process.GetProcesses())
        {
            if (process2.ProcessName == "System" || process2.ProcessName == "Idle" || string.IsNullOrEmpty(process2.ProcessName))
            {
                continue;
            }
            string ProcessName = process2.ProcessName;

            if (appUsage.ContainsKey(ProcessName))
            {
                bool processAudioUsage = audioUsage.GetValueOrDefault(process2.Id, false);

                IntPtr hwnd = process2.MainWindowHandle;
                string windowTitle = process2.MainWindowTitle; // Use MainWindowTitle to group by window
                bool isActive = (hwnd == GetForegroundWindow());
                bool isVisible = IsWindowVisible(hwnd);
                float memoryUsageMB = process2.WorkingSet64 / (1024f * 1024f);
                float cpuUsagePercentage = GetCpuUsage(process2);
                appUsage[ProcessName].MemoryUsageMB += memoryUsageMB; // Aggregate memory
                appUsage[ProcessName].CpuUsagePercentage += cpuUsagePercentage; // Aggregate CPU
                appUsage[ProcessName].IsActive = isActive || appUsage[ProcessName].IsActive;
                appUsage[ProcessName].IsVisible = isVisible || appUsage[ProcessName].IsVisible;
                appUsage[ProcessName].ProcessAudioUsage = processAudioUsage || appUsage[ProcessName].ProcessAudioUsage;
            }
        }

        foreach (var usage in appUsage)
        {
            string logEntry = $"{DateTime.Now}, {usage.Value.ProcessName}, {usage.Key}, {usage.Value.MemoryUsageMB:F2}, {usage.Value.CpuUsagePercentage:F2}, {usage.Value.ProcessAudioUsage}, {usage.Value.IsActive}, {usage.Value.IsVisible}\n";
            int retryCount = 3;
            while (retryCount > 0)
            {
                try
                {
                    await File.AppendAllTextAsync(LogFilePath, logEntry);
                    Console.WriteLine($"{usage.Value.ProcessName}, {usage.Value.MemoryUsageMB:F2}MB, {usage.Value.CpuUsagePercentage:F2}%, Audio:{usage.Value.ProcessAudioUsage}, Active:{usage.Value.IsActive}, Visible:{usage.Value.IsVisible}");
                    break;
                }
                catch (IOException ex)
                {
                    if (IsFileLocked(ex))
                    {
                        retryCount--;
                        Console.WriteLine($"Log file locked. Retrying in 1 second... (Retries left: {retryCount})");
                        await Task.Delay(1000);
                    }
                    else
                    {
                        Console.WriteLine($"Error writing to log file: {ex.Message}");
                        break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error writing to log file: {ex.Message}");
                    break;
                }
            }

            if (retryCount == 0)
            {
                Console.WriteLine($"Failed to write to log file for process {usage.Value.ProcessName} after multiple retries.");
            }
        }
    }

    public class ResourceUsage
    {
        public string WindowName { get; set; }
        public string ProcessName { get; set; }
        public float MemoryUsageMB { get; set; }
        public float CpuUsagePercentage { get; set; }
        public bool ProcessAudioUsage { get; set; }
        public bool IsActive { get; set; }
        public bool IsVisible { get; set; }
    }

    private static float GetCpuUsage(Process process)
    {
        try
        {
            using (var cpuCounter = new PerformanceCounter("Process", "% Processor Time", process.ProcessName))
            {
                cpuCounter.NextValue();
                Thread.Sleep(100);
                return cpuCounter.NextValue() / Environment.ProcessorCount;
            }
        }
        catch (Exception)
        {
            return 0;
        }
    }

    private static Dictionary<int, bool> GetAudioUsage()
    {
        var audioUsage = new Dictionary<int, bool>();
        try
        {
            var enumerator = new NAudio.CoreAudioApi.MMDeviceEnumerator();
            var devices = enumerator.EnumerateAudioEndPoints(NAudio.CoreAudioApi.DataFlow.Render, NAudio.CoreAudioApi.DeviceState.Active);

            foreach (var device in devices)
            {
                var sessionManager = device.AudioSessionManager;
                if (sessionManager == null) continue;
                var sessions = sessionManager.Sessions;
                if (sessions == null) continue;

                for (int i = 0; i < sessions.Count; i++)
                {
                    var session = sessions[i];
                    try
                    {
                        var audioSessionProcessId = session.GetProcessID;
                        if (audioSessionProcessId != 0 && (!audioUsage.ContainsKey((int)audioSessionProcessId) || audioUsage[(int)audioSessionProcessId] == false) && session.SimpleAudioVolume.Volume > 0.21)
                        {
                            audioUsage[(int)audioSessionProcessId] = true;
                        }
                    }
                    catch (ArgumentException)
                    {
                        // Process ID is invalid (process has exited).
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error checking audio: {ex.Message}");
        }
        return audioUsage;
    }

    private static bool IsFileLocked(IOException exception)
    {
        int errorCode = Marshal.GetHRForException(exception) & ((1 << 16) - 1);
        return errorCode == 32 || errorCode == 33;
    }

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);
}