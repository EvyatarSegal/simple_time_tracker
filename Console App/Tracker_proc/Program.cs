﻿using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
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
    private static readonly string ConnectionString = "Server=(localdb)\\TimeTrackerInstance;Database=TimeTrackerDB2;Integrated Security=True;TrustServerCertificate=True;";   
   
    // private static readonly string LogFilePath = "activity_log.txt"; // REMOVED: No longer logging to file
    private static string _lastActiveWindow = "";
    private static readonly CancellationTokenSource Cts = new CancellationTokenSource();

    static async Task Main(string[] args)
    {
        Console.WriteLine("Activity Tracker Service Started...");

        // InitializeLogFile(); // REMOVED: No longer logging to file

        Task windowTrackingTask = StartActiveWindowTracking(Cts.Token);
        Task resourceMonitoringTask = StartResourceMonitoring(Cts.Token);

        Console.WriteLine("Press ENTER to stop...");
        Console.ReadLine();

        Cts.Cancel();
        await Task.WhenAll(windowTrackingTask, resourceMonitoringTask);

        Console.WriteLine("Activity Tracker Stopped.");
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
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error in StartActiveWindowTracking: {ex.Message}");
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
        catch (Exception)
        {
            // Ignore if process not found or other issues during resource fetching for this process
        }

        // Log to database
        await LogActivityToDatabase(
            DateTime.UtcNow, // Use UtcNow for consistency
            processName,
            windowTitle,
            memoryUsageMB,
            cpuUsagePercentage,
            audioLevel,
            isActive,
            isCloaked: IsCloaked(hwnd), // Check cloaked status for the window
            isVisible
        );

        Console.WriteLine("###############################");
        Console.WriteLine($"Process: {processName}, Mb:{memoryUsageMB:F2}, CPU:{cpuUsagePercentage:F2}, Audio:{audioLevel}, Active:{isActive}, Visible:{isVisible}");
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
                await Task.Delay(5 * 60 * 1000, token); // Log every 5 minutes
            }
        }
        catch (TaskCanceledException)
        {
            Console.WriteLine("[INFO] Resource monitoring stopped.");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error in StartResourceMonitoring: {ex.Message}");
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

                string currentProcessName = process.ProcessName;
                IntPtr hwnd = process.MainWindowHandle;
                string windowTitle = process.MainWindowTitle;
                bool isActive = (hwnd == GetForegroundWindow());
                bool isVisible = IsWindowTrulyVisible(hwnd);
                float memoryUsageMB = process.WorkingSet64 / (1024f * 1024f);
                float cpuUsagePercentage = GetCpuUsage(process);

                if (appUsage.ContainsKey(currentProcessName))
                {
                    // If process name already exists, aggregate resources from other instances of the same app
                    appUsage[currentProcessName].MemoryUsageMB += memoryUsageMB;
                    appUsage[currentProcessName].CpuUsagePercentage += cpuUsagePercentage;
                    appUsage[currentProcessName].IsActive = isActive || appUsage[currentProcessName].IsActive;
                    appUsage[currentProcessName].IsVisible = isVisible || appUsage[currentProcessName].IsVisible;
                    appUsage[currentProcessName].AudioLevel = Math.Max(appUsage[currentProcessName].AudioLevel, audioLevel);
                    // Aggregate window titles, avoiding duplicates and empty titles
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
                        IsVisible = isVisible
                    };
                }
            }
            catch (Exception)
            {
                // Ignore processes that might throw errors (e.g., access denied, process exited)
            }
        }

        foreach (var usage in appUsage.Values) // Iterate over values as we've aggregated by ProcessName
        {
            // Get rid of windows without a name or cloaked windows
            // Use the MainWindowHandle from the ResourceUsage object for IsCloaked check
            if (string.IsNullOrEmpty(usage.WindowName) || IsCloaked(usage.MainWindowHandle))
            {
                continue;
            }

            // Log to database
            await LogActivityToDatabase(
                DateTime.UtcNow, // Use UtcNow for consistency
                usage.ProcessName,
                usage.WindowName, // The aggregated window title
                usage.MemoryUsageMB,
                usage.CpuUsagePercentage,
                usage.AudioLevel,
                usage.IsActive,
                usage.IsCloaked,
                usage.IsVisible
            );

            Console.WriteLine($"{DateTime.Now}, **************************************************************");
            Console.WriteLine($"{usage.ProcessName}, {usage.MemoryUsageMB:F2}MB, {usage.CpuUsagePercentage:F2}%, Audio:{usage.AudioLevel}, Active:{usage.IsActive}, Visible:{usage.IsVisible}\n\n\n");
        }
    }


    // NEW: Centralized method for logging activity to the database with async and error handling
    private static async Task LogActivityToDatabase(
        DateTime timestamp,
        string processName,
        string windowTitle,
        double memoryUsage,
        double cpuUsage,
        int audioLevel,
        bool isActive,
        bool isCloaked,
        bool isVisible) // Note: isVisible from LogActiveWindow and IsCloaked from CheckResourceUsage are combined here
    {
        try
        {
            using (var connection = new SqlConnection(ConnectionString))
            {
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText =
                @"
                INSERT INTO ActivityLog (Timestamp, ProcessName, WindowTitle, MemoryUsageMB, CpuUsage, ProcessAudioLevel, IsActive, IsCloaked, IsVisible)
                VALUES (@Timestamp, @ProcessName, @WindowTitle, @MemoryUsageMB, @CpuUsage, @ProcessAudioLevel, @IsActive, @IsCloaked, @IsVisible);
                ";

                command.Parameters.AddWithValue("@Timestamp", timestamp);
                command.Parameters.AddWithValue("@ProcessName", (object)processName ?? DBNull.Value);
                command.Parameters.AddWithValue("@WindowTitle", (object)windowTitle ?? DBNull.Value);
                command.Parameters.AddWithValue("@MemoryUsageMB", memoryUsage);
                command.Parameters.AddWithValue("@CpuUsage", cpuUsage);
                command.Parameters.AddWithValue("@ProcessAudioLevel", audioLevel);
                command.Parameters.AddWithValue("@IsActive", isActive);
                command.Parameters.AddWithValue("@IsCloaked", isCloaked);
                command.Parameters.AddWithValue("@IsVisible", isVisible);

                await command.ExecuteNonQueryAsync();
            }
        }
        catch (SqlException ex)
        {
            Console.Error.WriteLine($"Database error logging activity: {ex.Message}");
            // In a real application, you'd log this more robustly (e.g., to a file, system log, error monitoring)
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"An unexpected error occurred logging activity: {ex.Message}");
        }
    }


    public class ResourceUsage
    {
        public nint MainWindowHandle { get; set; }
        public string WindowName { get; set; }
        public string ProcessName { get; set; }
        public float MemoryUsageMB { get; set; }
        public float CpuUsagePercentage { get; set; }
        public int AudioLevel { get; set; } = 0; // Binary flag: 1 = playing audio, 0 = not playing
        public bool IsActive { get; set; }
        public bool IsCloaked { get; set; }
        public bool IsVisible { get; set; } // Renamed from IsCloaked in previous context for clarity
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

    // private static bool IsFileLocked(IOException exception) // REMOVED: No longer logging to file
    // {
    //     int errorCode = Marshal.GetHRForException(exception) & ((1 << 16) - 1);
    //     return errorCode == 32 || errorCode == 33;
    // }

    private static bool IsWindowTrulyVisible(IntPtr hWnd)
    {
        // Return false for null handles
        if (hWnd == IntPtr.Zero)
        {
            return false;
        }

        // Check basics first
        if (!IsWindowVisible(hWnd) || IsIconic(hWnd))
        {
            return false;
        }

        try
        {
            // Get window rectangle
            RECT windowRect = new RECT();
            if (!GetWindowRect(hWnd, ref windowRect))
            {
                return false;
            }

            // Calculate window dimensions
            int windowWidth = windowRect.Right - windowRect.Left;
            int windowHeight = windowRect.Bottom - windowRect.Top;

            // Check if window is too small or has invalid dimensions
            if (windowWidth <= 20 || windowHeight <= 20 || windowWidth <= 0 || windowHeight <= 0)
            {
                return false;
            }

            // Check if window is visible on any monitor
            MonitorInfo monitorInfo = new MonitorInfo();
            monitorInfo.WindowRect = windowRect;
            monitorInfo.IsWindowOnAnyMonitor = false;

            EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, MonitorEnumProc, ref monitorInfo);

            if (!monitorInfo.IsWindowOnAnyMonitor)
            {
                return false;  // Window is not on any monitor
            }

            // Create region for window
            IntPtr windowRegion = CreateRectRgn(windowRect.Left, windowRect.Top, windowRect.Right, windowRect.Bottom);
            if (windowRegion == IntPtr.Zero)
            {
                return false;
            }

            // Get the visible region
            IntPtr visibleRegion = GetVisibleRegion(hWnd);
            if (visibleRegion == IntPtr.Zero)
            {
                DeleteObject(windowRegion);
                return false;
            }

            // Get region data to calculate area
            int windowArea = GetRegionArea(windowRegion);
            int visibleArea = GetRegionArea(visibleRegion);

            // Clean up regions
            DeleteObject(windowRegion);
            DeleteObject(visibleRegion);

            // Check if window has sufficient visible area (at least 30%)
            if (windowArea <= 0)
            {
                return false;
            }

            double visiblePercentage = (double)visibleArea / windowArea * 100;
            return visiblePercentage >= 30;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in IsWindowTrulyVisible: {ex.Message}");
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
        // Check if window intersects with this monitor
        RECT monitorRect = lprcMonitor;
        RECT windowRect = dwData.WindowRect;
        RECT intersection = new RECT();

        if (IntersectRect(ref intersection, ref monitorRect, ref windowRect))
        {
            dwData.IsWindowOnAnyMonitor = true;
            return false;  // Stop enumeration, we found a monitor
        }

        return true;  // Continue enumeration
    }

    private static IntPtr GetVisibleRegion(IntPtr hWnd)
    {
        try
        {
            // Get window rectangle
            RECT windowRect = new RECT();
            if (!GetWindowRect(hWnd, ref windowRect))
            {
                return IntPtr.Zero;
            }

            // Create initial region representing the entire window
            IntPtr regionHandle = CreateRectRgn(
                windowRect.Left, windowRect.Top,
                windowRect.Right, windowRect.Bottom);

            if (regionHandle == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            // Get parent window
            IntPtr hParentWnd = GetAncestor(hWnd, GA_PARENT);
            IntPtr hChildWnd = hWnd;

            // Process window hierarchy until we reach desktop
            while (hChildWnd != IntPtr.Zero && !IsDesktopWindow(hChildWnd))
            {
                // Get the top window (the most recently activated/created window)
                IntPtr topWnd = GetTopWindow(hParentWnd);

                // Process all siblings that are above our window
                while (topWnd != IntPtr.Zero)
                {
                    // If we reach our window, exit the loop
                    if (topWnd == hChildWnd)
                    {
                        break;
                    }

                    // Get window rectangle for the top window
                    RECT topWndRect = new RECT();
                    if (IsWindowVisible(topWnd) && !IsIconic(topWnd) &&
                        GetWindowRect(topWnd, ref topWndRect))
                    {
                        // Check if the windows intersect
                        RECT tempRect = new RECT();
                        if (IntersectRect(ref tempRect, ref topWndRect, ref windowRect))
                        {
                            // Create region for overlapping window
                            IntPtr topWndRgn = CreateRectRgn(
                                topWndRect.Left, topWndRect.Top,
                                topWndRect.Right, topWndRect.Bottom);

                            if (topWndRgn != IntPtr.Zero)
                            {
                                // Subtract the overlapping region
                                CombineRgn(regionHandle, regionHandle, topWndRgn, RGN_DIFF);
                                DeleteObject(topWndRgn);
                            }
                        }
                    }

                    // Move to the next window
                    topWnd = GetWindow(topWnd, GW_HWNDNEXT);
                }

                // Move up the hierarchy
                hChildWnd = hParentWnd;
                hParentWnd = GetAncestor(hParentWnd, GA_PARENT);
            }

            return regionHandle;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in GetVisibleRegion: {ex.Message}");
            return IntPtr.Zero;
        }
    }

    private static int GetRegionArea(IntPtr region)
    {
        // Get the region data to calculate area
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

            // Calculate area by summing up all rectangles
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

    // Renamed delegate to fix the conflict
    private delegate bool MonitorEnumProcDelegate(IntPtr hMonitor, IntPtr hdcMonitor, ref RECT lprcMonitor, ref MonitorInfo dwData);

    [DllImport("user32.dll")]
    private static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, MonitorEnumProcDelegate lpfnEnum, ref MonitorInfo dwData);

    // Additional structures for region operations
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
        // Followed by array of RECT structures
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(IntPtr hWnd);

    // Additional API imports
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

    [DllImport("gdi32.dll")]
    private static extern IntPtr CreateRectRgn(int nLeftRect, int nTopRect, int nRightRect, int nBottomRect);

    [DllImport("gdi32.dll")]
    private static extern int CombineRgn(IntPtr hrgnDest, IntPtr hrgnSrc1, IntPtr hrgnSrc2, int fnCombineMode);

    [DllImport("gdi32.dll")]
    private static extern bool DeleteObject(IntPtr hObject);

    [DllImport("gdi32.dll")]
    private static extern int GetRegionData(IntPtr hRgn, int dwCount, IntPtr lpRgnData);

    // Constants for window relationships and region operations
    private const uint GA_PARENT = 1;
    private const uint GW_HWNDNEXT = 2;
    private const int RGN_DIFF = 4;

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
    const int DWMWA_CLOAKED = 14;

    // checking if cloaked

    static bool IsCloaked(IntPtr hWnd)
    {
        int isCloaked = 0;
        return DwmGetWindowAttribute(hWnd, DWMWA_CLOAKED, out isCloaked, sizeof(int)) == 0 && isCloaked != 0;
    }

    [DllImport("dwmapi.dll")]
    static extern int DwmGetWindowAttribute(IntPtr hwnd, int dwAttribute, out int pvAttribute, int cbAttribute);


}