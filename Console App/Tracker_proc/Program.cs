using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices; // Added for DllImport
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NAudio.CoreAudioApi;
using static Vanara.PInvoke.Gdi32;
using static Vanara.PInvoke.Kernel32;
using Microsoft.Data.SqlClient;


class Program
{
    // Connection string for your SQL Server LocalDB instance
    // Replace '(localdb)\\MSSQLLocalDB' if your instance name is different
    private static readonly string ConnectionString = "Server=(localdb)\\MSSQLLocalDB;Database=TimeTrackerDB;Integrated Security=True;TrustServerCertificate=True;";
    // private static readonly string LogFilePath = "activity_log.txt"; // REMOVED: No longer logging to file
    private static string _lastActiveWindow = "";
    private static readonly CancellationTokenSource Cts = new CancellationTokenSource();

    // --- P/Invoke for Console Window Hiding ---
    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    const int SW_HIDE = 0; // Command to hide the window
    // const int SW_SHOW = 5; // Use this if you want to show it later for debugging

    // --- Main Entry Point ---
    static async Task Main(string[] args)
    {
        // Get a handle to the console window
        IntPtr handle = GetConsoleWindow();
        // Hide the console window if a handle is found
        if (handle != IntPtr.Zero)
        {
            ShowWindow(handle, SW_HIDE);
        }

        // Initialize the database table if it doesn't exist
        await InitializeDatabase();

        // Start the background tasks
        Task windowTrackingTask = StartActiveWindowTracking(Cts.Token);
        Task resourceMonitoringTask = StartResourceMonitoring(Cts.Token);

        // Keep the application running indefinitely in the background
        // It will only stop if the process is killed, or Cts.Cancel() is called externally
        await Task.Delay(Timeout.Infinite, Cts.Token);
    }

    // --- Database Initialization ---
    private static async Task InitializeDatabase()
    {
        try
        {
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                await connection.OpenAsync();
                string createTableQuery = @"
                    IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='ActivityLogs' and xtype='U')
                    CREATE TABLE ActivityLogs (
                        Id INT IDENTITY(1,1) PRIMARY KEY,
                        Timestamp DATETIME,
                        ProcessName NVARCHAR(255),
                        WindowName NVARCHAR(MAX),
                        MemoryUsageMB DECIMAL(18, 2),
                        CpuUsagePercentage DECIMAL(18, 2),
                        AudioLevel INT,
                        IsActive BIT,
                        IsVisible BIT,
                        IsCloaked BIT
                    );";
                using (SqlCommand command = new SqlCommand(createTableQuery, connection))
                {
                    await command.ExecuteNonQueryAsync();
                }
            }
            // If you want a minimal log to file for critical startup, you can enable this temporarily
            // File.AppendAllText("startup_log.txt", $"{DateTime.UtcNow}: Database initialized successfully.\n");
        }
        catch (Exception ex)
        {
            // Log this critical error to a file if database init fails
            // Since there's no console, a file log is important here.
            File.AppendAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "startup_error.log"),
                $"{DateTime.UtcNow}: ERROR - Database initialization failed: {ex.Message}\nStack Trace:\n{ex.StackTrace}\n");
            // Optionally, consider throwing the exception if database is mandatory for operation
            // throw;
        }
    }


    // --- Active Window Tracking ---
    static async Task StartActiveWindowTracking(CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                await LogActiveWindow();
                await Task.Delay(1000, token); // Check every 1 second
            }
        }
        catch (TaskCanceledException)
        {
            // Task was canceled, normal shutdown
        }
        catch (Exception ex)
        {
            await LogActivityToDatabase(DateTime.UtcNow, "ERROR", $"Active Window Tracking Error: {ex.Message}", 0, 0, 0, false, false, false);
            // Consider logging to a separate error file if database is unavailable
            File.AppendAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "runtime_error.log"),
                $"{DateTime.UtcNow}: ERROR in Active Window Tracking: {ex.Message}\nStack Trace:\n{ex.StackTrace}\n");
        }
    }

    static async Task LogActiveWindow()
    {
        IntPtr hwnd = GetForegroundWindow();
        string windowTitle = "";
        string processName = "";
        uint processId = 0;
        bool isActive = false;
        bool isVisible = false;
        bool isCloaked = false;
        float memoryUsageMB = 0;
        float cpuUsagePercentage = 0;
        int audioLevel = 0;

        try
        {
            if (hwnd == IntPtr.Zero)
            {
                windowTitle = "[Idle]";
                processName = "[Idle]";
                // Only log if it's a state change to idle, to avoid excessive logs
                if (_lastActiveWindow != windowTitle)
                {
                    await LogActivityToDatabase(DateTime.UtcNow, processName, windowTitle, 0, 0, 0, false, false, false);
                    _lastActiveWindow = windowTitle;
                }
                return;
            }

            // Get window title
            const int nChars = 256;
            StringBuilder buffer = new StringBuilder(nChars);
            int textLength = GetWindowText(hwnd, buffer, nChars);
            windowTitle = (textLength > 0) ? buffer.ToString() : "[No Title]";


            // Get process name and ID
            GetWindowThreadProcessId(hwnd, out processId);
            try
            {
                Process process = Process.GetProcessById((int)processId);
                processName = process.ProcessName;
                memoryUsageMB = process.WorkingSet64 / (1024f * 1024f);
                cpuUsagePercentage = GetCpuUsage(process);
            }
            catch (ArgumentException)
            {
                processName = "[Process Not Found]";
            }
            catch (InvalidOperationException)
            {
                processName = "[Process Exited]";
            }
            catch (Exception ex)
            {
                processName = "[Error Getting Process]";
                await LogActivityToDatabase(DateTime.UtcNow, "ERROR", $"Process Info Error for PID {processId}: {ex.Message}", 0, 0, 0, false, false, false);
            }

            // Check visibility and cloaked status
            isVisible = IsWindowTrulyVisible(hwnd);
            isCloaked = IsCloaked(hwnd);
            isActive = (hwnd == GetForegroundWindow()); // Re-check to ensure it's still foreground


            // Get audio activity
            Dictionary<int, bool> activeAudio = GetActiveAudioProcesses();
            bool processAudioActive = activeAudio.GetValueOrDefault((int)processId, false);
            audioLevel = processAudioActive ? 1 : 0;

            // Only log if it's a new active window, or if it was previously "No Title" or "Idle"
            // and now has a title (or process name changed for "No Title")
            if (windowTitle != _lastActiveWindow ||
                (windowTitle == "[No Title]" && processName != _lastActiveWindow) || // If title is still "No Title" but process changed
                (windowTitle == "[Idle]" && _lastActiveWindow != "[Idle]")) // If it transitioned back to idle
            {
                _lastActiveWindow = windowTitle; // Update last active window
                await LogActivityToDatabase(
                    DateTime.UtcNow,
                    processName,
                    windowTitle,
                    memoryUsageMB,
                    cpuUsagePercentage,
                    audioLevel,
                    isActive,
                    isVisible,
                    isCloaked
                );
            }
        }
        catch (Exception ex)
        {
            await LogActivityToDatabase(DateTime.UtcNow, "ERROR", $"General LogActiveWindow Error: {ex.Message}", 0, 0, 0, false, false, false);
            File.AppendAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "runtime_error.log"),
                $"{DateTime.UtcNow}: ERROR in LogActiveWindow: {ex.Message}\nStack Trace:\n{ex.StackTrace}\n");
        }
    }

    // --- Resource Monitoring ---
    static async Task StartResourceMonitoring(CancellationToken token)
    {
        try
        {
            PerformanceCounter cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
            cpuCounter.NextValue(); // Call once to initialize

            while (!token.IsCancellationRequested)
            {
                await CheckResourceUsage(cpuCounter);
                await Task.Delay(5 * 60 * 1000, token); // Log every 5 minutes
            }
        }
        catch (TaskCanceledException)
        {
            // Task was canceled, normal shutdown
        }
        catch (Exception ex)
        {
            await LogActivityToDatabase(DateTime.UtcNow, "ERROR", $"Resource Monitoring Task Error: {ex.Message}", 0, 0, 0, false, false, false);
            File.AppendAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "runtime_error.log"),
                $"{DateTime.UtcNow}: ERROR in Resource Monitoring: {ex.Message}\nStack Trace:\n{ex.StackTrace}\n");
        }
    }

    static async Task CheckResourceUsage(PerformanceCounter totalCpuCounter)
    {
        Dictionary<int, bool> activeAudio = GetActiveAudioProcesses();
        Dictionary<string, ResourceUsage> appUsage = new Dictionary<string, ResourceUsage>();

        // Log total CPU usage first
        double totalCpuUsage = GetCpuUsage(totalCpuCounter);
        await LogActivityToDatabase(DateTime.UtcNow, "SYSTEM", $"Total CPU: {totalCpuUsage:F2}%", 0, totalCpuUsage, 0, false, true, false); // No specific window for system CPU

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                // Skip system/idle/empty processes unless they have audio activity
                if ((process.ProcessName == "System" || process.ProcessName == "Idle" || string.IsNullOrEmpty(process.ProcessName) || process.MainWindowHandle == IntPtr.Zero) && !activeAudio.GetValueOrDefault(process.Id, false))
                {
                    continue;
                }

                string currentProcessName = process.ProcessName;
                IntPtr hwnd = process.MainWindowHandle;
                string windowTitle = process.MainWindowTitle;
                bool isActive = (hwnd == GetForegroundWindow());
                bool isVisible = IsWindowTrulyVisible(hwnd);
                bool isCloaked = IsCloaked(hwnd);

                float memoryUsageMB = 0;
                float cpuUsagePercentage = 0;

                try
                {
                    memoryUsageMB = process.WorkingSet64 / (1024f * 1024f);
                    cpuUsagePercentage = GetCpuUsage(process);
                }
                catch (Exception ex)
                {
                    // Log process-specific resource fetching errors, but don't stop the loop
                    await LogActivityToDatabase(DateTime.UtcNow, "ERROR_RESOURCE", $"Process '{currentProcessName}' (PID {process.Id}) resource error: {ex.Message}", 0, 0, 0, false, false, false);
                }

                int audioLevel = activeAudio.GetValueOrDefault(process.Id, false) ? 1 : 0;

                // Aggregate usage
                if (appUsage.ContainsKey(currentProcessName))
                {
                    appUsage[currentProcessName].MemoryUsageMB += memoryUsageMB;
                    appUsage[currentProcessName].CpuUsagePercentage += cpuUsagePercentage;
                    appUsage[currentProcessName].IsActive = isActive || appUsage[currentProcessName].IsActive;
                    appUsage[currentProcessName].IsVisible = isVisible || appUsage[currentProcessName].IsVisible;
                    appUsage[currentProcessName].IsCloaked = isCloaked && appUsage[currentProcessName].IsCloaked; // If any instance is not cloaked, then overall is not
                    appUsage[currentProcessName].AudioLevel = Math.Max(appUsage[currentProcessName].AudioLevel, audioLevel);
                    if (!string.IsNullOrEmpty(windowTitle) && !appUsage[currentProcessName].WindowName.Contains(windowTitle))
                    {
                        appUsage[currentProcessName].WindowName += (string.IsNullOrEmpty(appUsage[currentProcessName].WindowName) ? "" : "; ") + windowTitle;
                    }
                }
                else
                {
                    appUsage[currentProcessName] = new ResourceUsage
                    {
                        MainWindowHandle = hwnd,
                        ProcessName = currentProcessName,
                        WindowName = windowTitle,
                        MemoryUsageMB = memoryUsageMB,
                        CpuUsagePercentage = cpuUsagePercentage,
                        AudioLevel = audioLevel,
                        IsActive = isActive,
                        IsVisible = isVisible,
                        IsCloaked = isCloaked
                    };
                }
            }
            catch (Exception ex)
            {
                // Catch general errors for processing a single process
                await LogActivityToDatabase(DateTime.UtcNow, "ERROR_PROCESS_LOOP", $"Error processing process in CheckResourceUsage: {ex.Message}", 0, 0, 0, false, false, false);
            }
        }

        foreach (var usage in appUsage.Values)
        {
            // You can add filtering here if you only want to log visible/non-cloaked apps
            // For example:
            // if (string.IsNullOrEmpty(usage.WindowName) || usage.IsCloaked || !usage.IsVisible)
            // {
            //     continue;
            // }

            await LogActivityToDatabase(
                DateTime.UtcNow,
                usage.ProcessName,
                usage.WindowName,
                usage.MemoryUsageMB,
                usage.CpuUsagePercentage,
                usage.AudioLevel,
                usage.IsActive,
                usage.IsVisible,
                usage.IsCloaked
            );
        }
    }

    // --- CPU Usage Methods ---
    static float GetCpuUsage(Process process)
    {
        try
        {
            using (var cpuCounter = new PerformanceCounter("Process", "% Processor Time", process.ProcessName))
            {
                cpuCounter.NextValue();
                Thread.Sleep(100); // Give it time to calculate
                return cpuCounter.NextValue() / Environment.ProcessorCount;
            }
        }
        catch (Exception ex)
        {
            // Log specific CPU counter errors for processes
            LogActivityToDatabase(DateTime.UtcNow, "ERROR_CPU_PROCESS", $"Error getting CPU for '{process.ProcessName}': {ex.Message}", 0, 0, 0, false, false, false).Wait();
            return 0;
        }
    }

    static double GetCpuUsage(PerformanceCounter cpuCounter)
    {
        try
        {
            return cpuCounter.NextValue();
        }
        catch (Exception ex)
        {
            LogActivityToDatabase(DateTime.UtcNow, "ERROR_CPU_TOTAL", $"Error getting total CPU usage: {ex.Message}", 0, 0, 0, false, false, false).Wait();
            return 0;
        }
    }

    // --- Audio Activity Monitoring ---
    static Dictionary<int, bool> GetActiveAudioProcesses()
    {
        var activeAudio = new Dictionary<int, bool>();
        float volumeThreshold = 0.1f;
        float peakThreshold = 0.01f;

        try
        {
            using (var enumerator = new MMDeviceEnumerator())
            {
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
                                float volume = session.SimpleAudioVolume.Volume;
                                if (volume < volumeThreshold) continue;

                                bool isActive = false;
                                try
                                {
                                    var audioMeterInformation = session.AudioMeterInformation;
                                    if (audioMeterInformation != null)
                                    {
                                        float peak = audioMeterInformation.MasterPeakValue;
                                        isActive = peak > peakThreshold;
                                    }
                                }
                                catch { isActive = volume > volumeThreshold; } // Fallback if AudioMeterInformation fails

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
                            if (!(ex is ArgumentException)) // Ignore "Process not found" type ArgumentExceptions
                            {
                                LogActivityToDatabase(DateTime.UtcNow, "ERROR_AUDIO_SESSION", $"Error processing audio session: {ex.Message}", 0, 0, 0, false, false, false).Wait();
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            LogActivityToDatabase(DateTime.UtcNow, "ERROR_AUDIO_GLOBAL", $"Global error checking audio: {ex.Message}", 0, 0, 0, false, false, false).Wait();
        }
        return activeAudio;
    }

    // --- Database Logging ---
    private static async Task LogActivityToDatabase(
        DateTime timestamp,
        string processName,
        string windowName,
        double memoryUsage,
        double cpuUsage,
        int audioLevel,
        bool isActive,
        bool isVisible,
        bool isCloaked)
    {
        try
        {
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                await connection.OpenAsync();
                string insertQuery = @"
                    INSERT INTO ActivityLogs (Timestamp, ProcessName, WindowName, MemoryUsageMB, CpuUsagePercentage, AudioLevel, IsActive, IsVisible, IsCloaked)
                    VALUES (@Timestamp, @ProcessName, @WindowName, @MemoryUsageMB, @CpuUsagePercentage, @AudioLevel, @IsActive, @IsVisible, @IsCloaked)";

                using (SqlCommand command = new SqlCommand(insertQuery, connection))
                {
                    command.Parameters.AddWithValue("@Timestamp", timestamp);
                    command.Parameters.AddWithValue("@ProcessName", processName);
                    command.Parameters.AddWithValue("@WindowName", windowName);
                    command.Parameters.AddWithValue("@MemoryUsageMB", memoryUsage);
                    command.Parameters.AddWithValue("@CpuUsagePercentage", cpuUsage);
                    command.Parameters.AddWithValue("@AudioLevel", audioLevel);
                    command.Parameters.AddWithValue("@IsActive", isActive);
                    command.Parameters.AddWithValue("@IsVisible", isVisible);
                    command.Parameters.AddWithValue("@IsCloaked", isCloaked);

                    await command.ExecuteNonQueryAsync();
                }
            }
        }
        catch (Exception ex)
        {
            // IMPORTANT: If database logging fails, log to a file as a fallback
            File.AppendAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "database_error_fallback.log"),
                $"{DateTime.UtcNow}: CRITICAL DATABASE ERROR - Could not log activity: {ex.Message}\n" +
                $"Data: P:{processName}, W:{windowName}, Mem:{memoryUsage}, CPU:{cpuUsage}, Audio:{audioLevel}, Active:{isActive}, Visible:{isVisible}, Cloaked:{isCloaked}\n" +
                $"Stack Trace:\n{ex.StackTrace}\n");
        }
    }


    // --- P/Invoke Structures and Win32 API Imports ---
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

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(IntPtr hWnd); // Checks if window is minimized

    [DllImport("user32.dll")]
    private static extern IntPtr GetTopWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr GetWindow(IntPtr hWnd, uint uCmd);

    [DllImport("user32.dll")]
    private static extern IntPtr GetAncestor(IntPtr hWnd, uint gaFlags);

    [DllImport("user32.dll")]
    private static extern IntPtr GetDesktopWindow();

    [DllImport("user32.dll")]
    private static extern IntPtr GetShellWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IntersectRect(ref RECT lprcDst, ref RECT lprcSrc1, ref RECT lprcSrc2);

    [DllImport("user32.dll")]
    private static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, MonitorEnumProcDelegate lpfnEnum, ref MonitorInfo dwData);


    [DllImport("gdi32.dll")]
    private static extern IntPtr CreateRectRgn(int nLeftRect, int nTopRect, int nRightRect, int nBottomRect);

    [DllImport("gdi32.dll")]
    private static extern int CombineRgn(IntPtr hrgnDest, IntPtr hrgnSrc1, IntPtr hrgnSrc2, int fnCombineMode);

    [DllImport("gdi32.dll")]
    private static extern bool DeleteObject(IntPtr hObject);

    [DllImport("gdi32.dll")]
    private static extern int GetRegionData(IntPtr hRgn, int dwCount, IntPtr lpRgnData);

    [DllImport("dwmapi.dll")]
    static extern int DwmGetWindowAttribute(IntPtr hwnd, int dwAttribute, out int pvAttribute, int cbAttribute);


    // System metric constants
    private const int SM_CXSCREEN = 0;
    private const int SM_CYSCREEN = 1;
    private const uint GA_PARENT = 1;
    private const uint GW_HWNDNEXT = 2;
    private const int RGN_DIFF = 4;
    const int DWMWA_CLOAKED = 14;

    // checking if cloaked
    static bool IsCloaked(IntPtr hWnd)
    {
        if (hWnd == IntPtr.Zero) return false;
        try
        {
            int isCloaked = 0;
            // DwmGetWindowAttribute returns 0 on success
            if (DwmGetWindowAttribute(hWnd, DWMWA_CLOAKED, out isCloaked, sizeof(int)) == 0)
            {
                return isCloaked != 0;
            }
            return false; // If DwmGetWindowAttribute fails, assume not cloaked
        }
        catch (Exception ex)
        {
            // Log this exception if DWMAPI call itself fails
            LogActivityToDatabase(DateTime.UtcNow, "ERROR_ISCLOAKED_API", $"Error calling DwmGetWindowAttribute for HWND {hWnd}: {ex.Message}", 0, 0, 0, false, false, false).Wait();
            return false; // On error, assume not cloaked to avoid filtering
        }
    }

    static bool IsWindowTrulyVisible(IntPtr hWnd)
    {
        if (hWnd == IntPtr.Zero) return false;

        try
        {
            if (!IsWindowVisible(hWnd) || IsIconic(hWnd))
            {
                return false;
            }

            RECT windowRect = new RECT();
            if (!GetWindowRect(hWnd, ref windowRect))
            {
                return false;
            }

            int windowWidth = windowRect.Right - windowRect.Left;
            int windowHeight = windowRect.Bottom - windowRect.Top;

            if (windowWidth <= 20 || windowHeight <= 20 || windowWidth <= 0 || windowHeight <= 0)
            {
                return false;
            }

            // Check if window is on any monitor
            MonitorInfo monitorInfo = new MonitorInfo();
            monitorInfo.WindowRect = windowRect;
            monitorInfo.IsWindowOnAnyMonitor = false;

            EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, MonitorEnumProc, ref monitorInfo);

            if (!monitorInfo.IsWindowOnAnyMonitor)
            {
                return false;
            }

            // Check if a significant portion of the window is visible (not completely covered)
            IntPtr windowRegion = CreateRectRgn(windowRect.Left, windowRect.Top, windowRect.Right, windowRect.Bottom);
            if (windowRegion == IntPtr.Zero) return false;

            IntPtr visibleRegion = GetVisibleRegion(hWnd);
            if (visibleRegion == IntPtr.Zero)
            {
                DeleteObject(windowRegion);
                return false;
            }

            int windowArea = GetRegionArea(windowRegion);
            int visibleArea = GetRegionArea(visibleRegion);

            DeleteObject(windowRegion);
            DeleteObject(visibleRegion);

            if (windowArea <= 0)
            {
                return false;
            }

            double visiblePercentage = (double)visibleArea / windowArea * 100;
            return visiblePercentage >= 30; // At least 30% of the window must be visible
        }
        catch (Exception ex)
        {
            // Log exceptions related to visibility checks
            LogActivityToDatabase(DateTime.UtcNow, "ERROR_TRULY_VISIBLE_CHECK", $"Error in IsWindowTrulyVisible for HWND {hWnd}: {ex.Message}", 0, 0, 0, false, false, false).Wait();
            return false;
        }
    }

    private class MonitorInfo
    {
        public RECT WindowRect;
        public bool IsWindowOnAnyMonitor;
    }

    private static bool MonitorEnumProc(IntPtr hMonitor, IntPtr hdcMonitor, ref RECT lprcMonitor, ref MonitorInfo dwData)
    {
        RECT monitorRect = lprcMonitor;
        RECT windowRect = dwData.WindowRect;
        RECT intersection = new RECT();

        if (IntersectRect(ref intersection, ref monitorRect, ref windowRect))
        {
            dwData.IsWindowOnAnyMonitor = true;
            return false; // Stop enumeration once on a monitor
        }

        return true; // Continue enumeration
    }

    private static IntPtr GetVisibleRegion(IntPtr hWnd)
    {
        try
        {
            RECT windowRect = new RECT();
            if (!GetWindowRect(hWnd, ref windowRect))
            {
                return IntPtr.Zero;
            }

            IntPtr regionHandle = CreateRectRgn(
                windowRect.Left, windowRect.Top,
                windowRect.Right, windowRect.Bottom);

            if (regionHandle == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            // Get the parent window chain
            IntPtr hParentWnd = GetAncestor(hWnd, GA_PARENT);
            IntPtr hChildWnd = hWnd;

            while (hChildWnd != IntPtr.Zero && !IsDesktopWindow(hChildWnd))
            {
                // Enumerate sibling windows (windows at the same Z-order level)
                IntPtr topWnd = GetTopWindow(hParentWnd);

                while (topWnd != IntPtr.Zero)
                {
                    if (topWnd == hChildWnd)
                    {
                        break; // Reached the target window
                    }

                    RECT topWndRect = new RECT();
                    if (IsWindowVisible(topWnd) && !IsIconic(topWnd) && // Only consider visible, non-minimized windows
                        GetWindowRect(topWnd, ref topWndRect))
                    {
                        RECT tempRect = new RECT();
                        // If the sibling window intersects with our target window
                        if (IntersectRect(ref tempRect, ref topWndRect, ref windowRect))
                        {
                            // Create a region for the overlapping part
                            IntPtr topWndRgn = CreateRectRgn(
                                topWndRect.Left, topWndRect.Top,
                                topWndRect.Right, topWndRect.Bottom);

                            if (topWndRgn != IntPtr.Zero)
                            {
                                // Subtract the overlapping region from our target window's region
                                CombineRgn(regionHandle, regionHandle, topWndRgn, RGN_DIFF);
                                DeleteObject(topWndRgn);
                            }
                        }
                    }
                    topWnd = GetWindow(topWnd, GW_HWNDNEXT); // Move to the next sibling
                }

                hChildWnd = hParentWnd; // Move up to the parent
                hParentWnd = GetAncestor(hParentWnd, GA_PARENT); // Get the next parent
            }

            return regionHandle;
        }
        catch (Exception ex)
        {
            LogActivityToDatabase(DateTime.UtcNow, "ERROR_GET_VISIBLE_REGION", $"Error in GetVisibleRegion for HWND {hWnd}: {ex.Message}", 0, 0, 0, false, false, false).Wait();
            return IntPtr.Zero;
        }
    }

    private static int GetRegionArea(IntPtr region)
    {
        int dataSize = GetRegionData(region, 0, IntPtr.Zero);
        if (dataSize <= 0)
        {
            return 0;
        }

        IntPtr dataBuffer = Marshal.AllocHGlobal(dataSize);
        try
        {
            GetRegionData(region, dataSize, dataBuffer);
            RGNDATA regionData = (RGNDATA)Marshal.PtrToStructure(dataBuffer, typeof(RGNDATA));
            int rectCount = regionData.rdh.nCount;
            int area = 0;

            IntPtr rectBuffer = new IntPtr(dataBuffer.ToInt64() + Marshal.SizeOf(typeof(RGNDATAHEADER)));
            for (int i = 0; i < rectCount; i++)
            {
                RECT rect = (RECT)Marshal.PtrToStructure(
                    new IntPtr(rectBuffer.ToInt64() + i * Marshal.SizeOf(typeof(RECT))),
                    typeof(RECT));

                area += (rect.Right - rect.Left) * (rect.Bottom - rect.Top);
            }

            return area;
        }
        finally
        {
            Marshal.FreeHGlobal(dataBuffer);
        }
    }

    private static bool IsDesktopWindow(IntPtr hWnd)
    {
        return hWnd == GetDesktopWindow() || hWnd == GetShellWindow();
    }

    // Delegate and structures for GetVisibleRegion
    private delegate bool MonitorEnumProcDelegate(IntPtr hMonitor, IntPtr hdcMonitor, ref RECT lprcMonitor, ref MonitorInfo dwData);

    [StructLayout(LayoutKind.Sequential)]
    public struct RGNDATAHEADER
    {
        public int dwSize;
        public int iType;
        public int nCount;
        public int nRgnSize;
        public RECT rcBound;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RGNDATA
    {
        public RGNDATAHEADER rdh;
    }

    // --- Helper Class for Resource Usage ---
    public class ResourceUsage
    {
        public nint MainWindowHandle { get; set; }
        public string WindowName { get; set; }
        public string ProcessName { get; set; }
        public float MemoryUsageMB { get; set; }
        public float CpuUsagePercentage { get; set; }
        public int AudioLevel { get; set; } = 0;
        public bool IsActive { get; set; }
        public bool IsVisible { get; set; }
        public bool IsCloaked { get; set; }
    }
}