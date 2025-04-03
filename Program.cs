using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
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
            File.WriteAllText(LogFilePath, "Timestamp, Process Name, Window Title, Memory Usage (MB), CPU Usage (%), Process Audio Level, IsActive, IsVisible\n");
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
        bool isVisible = IsWindowTrulyVisible(hwnd);
        float memoryUsageMB = 0;
        float cpuUsagePercentage = 0;

        // Get audio activity - 1 if active, 0 if not
        Dictionary<int, bool> activeAudio = GetActiveAudioProcesses();
        bool processAudioActive = activeAudio.GetValueOrDefault((int)processId, false);
        int audioLevel = processAudioActive ? 1 : 0;

        try
        {
            Process process = Process.GetProcessById((int)processId);
            memoryUsageMB = process.WorkingSet64 / (1024f * 1024f);
            cpuUsagePercentage = GetCpuUsage(process);
        }
        catch (Exception) { }

        string logEntry = $"{DateTime.Now}, {processName}, {windowTitle}, {memoryUsageMB:F2}, {cpuUsagePercentage:F2}, {audioLevel}, {isActive}, {isVisible}\n";

        int retryCount = 3;
        while (retryCount > 0)
        {
            try
            {
                await File.AppendAllTextAsync(LogFilePath, logEntry);
                Console.WriteLine($"Process: {processName}, Mb:{memoryUsageMB:F2}, CPU:{cpuUsagePercentage:F2}, Audio:{audioLevel}, Active:{isActive}, Visible:{isVisible}");
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
                await Task.Delay(5 * 1000, token);
            }
        }
        catch (TaskCanceledException)
        {
            Console.WriteLine("[INFO] Resource monitoring stopped.");
        }
    }

    private static async Task CheckResourceUsage()
    {
        Dictionary<int, bool> activeAudio = GetActiveAudioProcesses();
        Dictionary<string, ResourceUsage> appUsage = new Dictionary<string, ResourceUsage>(); // Aggregate usage per app

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                bool processAudioActive = activeAudio.GetValueOrDefault(process.Id, false);
                int audioLevel = processAudioActive ? 1 : 0;

                if ((process.ProcessName == "System" || process.ProcessName == "Idle" || string.IsNullOrEmpty(process.ProcessName) || process.MainWindowHandle == IntPtr.Zero) && audioLevel == 0)
                {
                    continue;
                }
                string ProcessName = process.ProcessName;
                IntPtr hwnd = process.MainWindowHandle;
                string windowTitle = process.MainWindowTitle; // Use MainWindowTitle to group by window
                bool isActive = (hwnd == GetForegroundWindow());
                bool isVisible = IsWindowTrulyVisible(hwnd);
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
                        AudioLevel = audioLevel,
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
                bool processAudioActive = activeAudio.GetValueOrDefault(process2.Id, false);
                int audioLevel = processAudioActive ? 1 : 0;

                IntPtr hwnd = process2.MainWindowHandle;
                string windowTitle = process2.MainWindowTitle; // Use MainWindowTitle to group by window
                bool isActive = (hwnd == GetForegroundWindow());
                bool isVisible = IsWindowTrulyVisible(hwnd);
                float memoryUsageMB = process2.WorkingSet64 / (1024f * 1024f);
                float cpuUsagePercentage = GetCpuUsage(process2);
                appUsage[ProcessName].MemoryUsageMB += memoryUsageMB; // Aggregate memory
                appUsage[ProcessName].CpuUsagePercentage += cpuUsagePercentage; // Aggregate CPU
                appUsage[ProcessName].IsActive = isActive || appUsage[ProcessName].IsActive;
                appUsage[ProcessName].IsVisible = isVisible || appUsage[ProcessName].IsVisible;
                appUsage[ProcessName].AudioLevel = Math.Max(appUsage[ProcessName].AudioLevel, audioLevel); // Any instance making sound = 1
            }
        }

        foreach (var usage in appUsage)
        {
            string logEntry = $"{DateTime.Now}, {usage.Value.ProcessName}, {usage.Key}, {usage.Value.MemoryUsageMB:F2}, {usage.Value.CpuUsagePercentage:F2}, {usage.Value.AudioLevel}, {usage.Value.IsActive}, {usage.Value.IsVisible}\n";
            int retryCount = 3;
            while (retryCount > 0)
            {
                try
                {
                    await File.AppendAllTextAsync(LogFilePath, logEntry);
                    Console.WriteLine($"{usage.Value.ProcessName}, {usage.Value.MemoryUsageMB:F2}MB, {usage.Value.CpuUsagePercentage:F2}%, Audio:{usage.Value.AudioLevel}, Active:{usage.Value.IsActive}, Visible:{usage.Value.IsVisible}");
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
        public int AudioLevel { get; set; } = 0; // Binary flag: 1 = playing audio, 0 = not playing
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

    private static Dictionary<int, bool> GetActiveAudioProcesses()
    {
        var activeAudio = new Dictionary<int, bool>();
        float volumeThreshold = 0.1f; // 10% volume threshold
        float peakThreshold = 0.01f; // Using peak meter to detect actual sound

        try
        {
            var enumerator = new MMDeviceEnumerator();
            var devices = enumerator.EnumerateAudioEndPoints(DataFlow.Render, DeviceState.Active);

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
                        uint audioSessionProcessId = session.GetProcessID;
                        if (audioSessionProcessId != 0)
                        {
                            // Volume must be above threshold
                            float volume = session.SimpleAudioVolume.Volume;
                            if (volume < volumeThreshold) continue;

                            // Check if sound is actually playing by checking peak values
                            bool isActive = false;
                            try
                            {
                                // Get the peak meter
                                var audioMeterInformation = session.AudioMeterInformation;
                                if (audioMeterInformation != null)
                                {
                                    float peak = audioMeterInformation.MasterPeakValue;
                                    isActive = peak > peakThreshold;
                                }
                            }
                            catch
                            {
                                // Fall back to just using volume if peak meter fails
                                isActive = volume > volumeThreshold;
                            }

                            // Mark the process as active or not
                            if (isActive || activeAudio.GetValueOrDefault((int)audioSessionProcessId, false))
                            {
                                activeAudio[(int)audioSessionProcessId] = true;
                            }
                            else if (!activeAudio.ContainsKey((int)audioSessionProcessId))
                            {
                                activeAudio[(int)audioSessionProcessId] = false;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        if (!(ex is ArgumentException)) // Ignore expected process ID exceptions
                        {
                            Console.WriteLine($"Error processing audio session: {ex.Message}");
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error checking audio: {ex.Message}");
        }
        return activeAudio;
    }

    private static bool IsFileLocked(IOException exception)
    {
        int errorCode = Marshal.GetHRForException(exception) & ((1 << 16) - 1);
        return errorCode == 32 || errorCode == 33;
    }

    // New function to check if a window is truly visible to the user
    private static bool IsWindowTrulyVisible(IntPtr hWnd)
    {
        // Check if the window is visible at all using the Windows API
        if (!IsWindowVisible(hWnd))
        {
            return false;
        }

        try
        {
            // Get window rectangle
            RECT windowRect = new RECT();
            if (!GetWindowRect(hWnd, ref windowRect))
            {
                return false; // Failed to get window dimensions
            }

            // Get screen dimensions
            int screenWidth = GetSystemMetrics(SM_CXSCREEN);
            int screenHeight = GetSystemMetrics(SM_CYSCREEN);

            // Calculate window dimensions
            int windowWidth = windowRect.Right - windowRect.Left;
            int windowHeight = windowRect.Bottom - windowRect.Top;

            // Calculate visible area
            Rectangle screenRect = new Rectangle(0, 0, screenWidth, screenHeight);
            Rectangle windowRectangle = new Rectangle(windowRect.Left, windowRect.Top, windowWidth, windowHeight);
            Rectangle intersection = Rectangle.Intersect(screenRect, windowRectangle);

            // Calculate percentage of window visible
            double windowArea = windowWidth * windowHeight;
            if (windowArea <= 0)
            {
                return false; // Invalid window size
            }

            double visibleArea = intersection.Width * intersection.Height;
            double visiblePercentage = visibleArea / windowArea * 100;

            // Calculate percentage of screen occupied
            double screenArea = screenWidth * screenHeight;
            double screenOccupiedPercentage = visibleArea / screenArea * 100;

            // Check if window meets both criteria
            return visiblePercentage >= 50 && screenOccupiedPercentage >= 10;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error checking window visibility: {ex.Message}");
            return false;
        }
    }

    // Required structures and Win32 API imports
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
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

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hWnd, ref RECT lpRect);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    // System metric constants
    private const int SM_CXSCREEN = 0;
    private const int SM_CYSCREEN = 1;
}