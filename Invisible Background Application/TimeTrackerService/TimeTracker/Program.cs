using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using Microsoft.Win32;
using NAudio.CoreAudioApi;
using static Vanara.PInvoke.Gdi32;
using static Vanara.PInvoke.Kernel32;

class Program
{
    private static readonly string ConnectionString = "Server=(localdb)\\TimeTrackerInstance;Database=TimeTrackerDB2;Integrated Security=True;TrustServerCertificate=True;";
    private static string _lastActiveWindow = "";
    private static CancellationTokenSource _cts;

    static async Task Main(string[] args)
    {
        // Hide the console window immediately
        var handle = GetConsoleWindow();
        ShowWindow(handle, SW_HIDE);

        // Register to run at startup (only if not already registered)
        AddToStartup();

        _cts = new CancellationTokenSource();
        AppDomain.CurrentDomain.ProcessExit += (s, e) => _cts.Cancel();
        
        try
        {
            await RunService(_cts.Token);
        }
        catch (Exception ex)
        {
            System.IO.File.AppendAllText("TimeTrackerError.log", $"{DateTime.Now}: FATAL ERROR - {ex}\n");
        }
    }

    private static async Task RunService(CancellationToken token)
    {
        Task windowTrackingTask = StartActiveWindowTracking(token);
        Task resourceMonitoringTask = StartResourceMonitoring(token);

        await Task.WhenAll(windowTrackingTask, resourceMonitoringTask);
    }

    private static void AddToStartup()
    {
        try
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true))
            {
                string appPath = $"\"{System.Reflection.Assembly.GetExecutingAssembly().Location}\"";
                string currentValue = key.GetValue("TimeTracker") as string;
                
                if (currentValue != appPath)
                {
                    key.SetValue("TimeTracker", appPath);
                    System.IO.File.AppendAllText("TimeTrackerError.log", $"{DateTime.Now}: Added to startup registry\n");
                }
            }
        }
        catch (Exception ex)
        {
            System.IO.File.AppendAllText("TimeTrackerError.log", $"{DateTime.Now}: Failed to add to startup - {ex}\n");
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
            System.IO.File.AppendAllText("TimeTrackerError.log", $"{DateTime.Now}: Window tracking stopped\n");
        }
        catch (Exception ex)
        {
            System.IO.File.AppendAllText("TimeTrackerError.log", $"{DateTime.Now}: Window tracking error - {ex}\n");
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
            // Ignore if process not found
        }

        await LogActivityToDatabase(
            DateTime.UtcNow,
            processName,
            windowTitle,
            memoryUsageMB,
            cpuUsagePercentage,
            audioLevel,
            isActive,
            isCloaked: IsCloaked(hwnd)
        );
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
            System.IO.File.AppendAllText("TimeTrackerError.log", $"{DateTime.Now}: Resource monitoring stopped\n");
        }
        catch (Exception ex)
        {
            System.IO.File.AppendAllText("TimeTrackerError.log", $"{DateTime.Now}: Resource monitoring error - {ex}\n");
        }
    }

    private static async Task CheckResourceUsage()
    {
        Dictionary<int, bool> activeAudio = GetActiveAudioProcesses();
        Dictionary<string, ResourceUsage> appUsage = new Dictionary<string, ResourceUsage>();

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
                    appUsage[currentProcessName].MemoryUsageMB += memoryUsageMB;
                    appUsage[currentProcessName].CpuUsagePercentage += cpuUsagePercentage;
                    appUsage[currentProcessName].IsActive = isActive || appUsage[currentProcessName].IsActive;
                    appUsage[currentProcessName].IsVisible = isVisible || appUsage[currentProcessName].IsVisible;
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
                        IsVisible = isVisible
                    };
                }
            }
            catch (Exception)
            {
                // Ignore processes that might throw errors
            }
        }

        foreach (var usage in appUsage.Values)
        {
            if (string.IsNullOrEmpty(usage.WindowName) || IsCloaked(usage.MainWindowHandle))
            {
                continue;
            }

            await LogActivityToDatabase(
                DateTime.UtcNow,
                usage.ProcessName,
                usage.WindowName,
                usage.MemoryUsageMB,
                usage.CpuUsagePercentage,
                usage.AudioLevel,
                usage.IsActive,
                usage.IsVisible
            );
        }
    }

    private static async Task LogActivityToDatabase(
        DateTime timestamp,
        string processName,
        string windowTitle,
        double memoryUsage,
        double cpuUsage,
        int audioLevel,
        bool isActive,
        bool isCloaked)
    {
        try
        {
            using (var connection = new SqlConnection(ConnectionString))
            {
                await connection.OpenAsync();

                var command = connection.CreateCommand();
                command.CommandText =
                @"
                INSERT INTO ActivityLog (Timestamp, ProcessName, WindowTitle, MemoryUsageMB, CpuUsage, ProcessAudioLevel, IsActive, IsCloaked)
                VALUES (@Timestamp, @ProcessName, @WindowTitle, @MemoryUsageMB, @CpuUsage, @ProcessAudioLevel, @IsActive, @IsCloaked);
                ";

                command.Parameters.AddWithValue("@Timestamp", timestamp);
                command.Parameters.AddWithValue("@ProcessName", (object)processName ?? DBNull.Value);
                command.Parameters.AddWithValue("@WindowTitle", (object)windowTitle ?? DBNull.Value);
                command.Parameters.AddWithValue("@MemoryUsageMB", memoryUsage);
                command.Parameters.AddWithValue("@CpuUsage", cpuUsage);
                command.Parameters.AddWithValue("@ProcessAudioLevel", audioLevel);
                command.Parameters.AddWithValue("@IsActive", isActive);
                command.Parameters.AddWithValue("@IsCloaked", isCloaked);

                await command.ExecuteNonQueryAsync();
            }
        }
        catch (Exception ex)
        {
            System.IO.File.AppendAllText("TimeTrackerError.log", $"{DateTime.Now}: Database error - {ex.Message}\n");
        }
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
        float volumeThreshold = 0.1f;
        float peakThreshold = 0.01f;

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
                            catch
                            {
                                isActive = volume > volumeThreshold;
                            }

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
                        if (!(ex is ArgumentException))
                        {
                            System.IO.File.AppendAllText("TimeTrackerError.log", $"{DateTime.Now}: Audio session error - {ex.Message}\n");
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            System.IO.File.AppendAllText("TimeTrackerError.log", $"{DateTime.Now}: Audio device error - {ex.Message}\n");
        }
        return activeAudio;
    }

    private static bool IsWindowTrulyVisible(IntPtr hWnd)
    {
        if (hWnd == IntPtr.Zero) return false;
        if (!IsWindowVisible(hWnd) || IsIconic(hWnd)) return false;

        try
        {
            RECT windowRect = new RECT();
            if (!GetWindowRect(hWnd, ref windowRect)) return false;

            int windowWidth = windowRect.Right - windowRect.Left;
            int windowHeight = windowRect.Bottom - windowRect.Top;
            if (windowWidth <= 20 || windowHeight <= 20) return false;

            MonitorInfo monitorInfo = new MonitorInfo();
            monitorInfo.WindowRect = windowRect;
            monitorInfo.IsWindowOnAnyMonitor = false;
            EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, MonitorEnumProc, ref monitorInfo);
            if (!monitorInfo.IsWindowOnAnyMonitor) return false;

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

            if (windowArea <= 0) return false;
            return ((double)visibleArea / windowArea * 100) >= 30;
        }
        catch (Exception ex)
        {
            System.IO.File.AppendAllText("TimeTrackerError.log", $"{DateTime.Now}: Window visibility error - {ex.Message}\n");
            return false;
        }
    }

    private static IntPtr GetVisibleRegion(IntPtr hWnd)
    {
        try
        {
            RECT windowRect = new RECT();
            if (!GetWindowRect(hWnd, ref windowRect)) return IntPtr.Zero;

            IntPtr regionHandle = CreateRectRgn(windowRect.Left, windowRect.Top, windowRect.Right, windowRect.Bottom);
            if (regionHandle == IntPtr.Zero) return IntPtr.Zero;

            IntPtr hParentWnd = GetAncestor(hWnd, GA_PARENT);
            IntPtr hChildWnd = hWnd;

            while (hChildWnd != IntPtr.Zero && !IsDesktopWindow(hChildWnd))
            {
                IntPtr topWnd = GetTopWindow(hParentWnd);
                while (topWnd != IntPtr.Zero)
                {
                    if (topWnd == hChildWnd) break;

                    RECT topWndRect = new RECT();
                    if (IsWindowVisible(topWnd) && !IsIconic(topWnd) && GetWindowRect(topWnd, ref topWndRect))
                    {
                        RECT tempRect = new RECT();
                        if (IntersectRect(ref tempRect, ref topWndRect, ref windowRect))
                        {
                            IntPtr topWndRgn = CreateRectRgn(topWndRect.Left, topWndRect.Top, topWndRect.Right, topWndRect.Bottom);
                            if (topWndRgn != IntPtr.Zero)
                            {
                                CombineRgn(regionHandle, regionHandle, topWndRgn, RGN_DIFF);
                                DeleteObject(topWndRgn);
                            }
                        }
                    }
                    topWnd = GetWindow(topWnd, GW_HWNDNEXT);
                }
                hChildWnd = hParentWnd;
                hParentWnd = GetAncestor(hParentWnd, GA_PARENT);
            }
            return regionHandle;
        }
        catch (Exception ex)
        {
            System.IO.File.AppendAllText("TimeTrackerError.log", $"{DateTime.Now}: Visible region error - {ex.Message}\n");
            return IntPtr.Zero;
        }
    }

    private static int GetRegionArea(IntPtr region)
    {
        int dataSize = GetRegionData(region, 0, IntPtr.Zero);
        if (dataSize <= 0) return 0;

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

    static bool IsCloaked(IntPtr hWnd)
    {
        int isCloaked = 0;
        return DwmGetWindowAttribute(hWnd, DWMWA_CLOAKED, out isCloaked, sizeof(int)) == 0 && isCloaked != 0;
    }

    public class ResourceUsage
    {
        public IntPtr MainWindowHandle { get; set; }
        public string WindowName { get; set; }
        public string ProcessName { get; set; }
        public float MemoryUsageMB { get; set; }
        public float CpuUsagePercentage { get; set; }
        public int AudioLevel { get; set; } = 0;
        public bool IsActive { get; set; }
        public bool IsVisible { get; set; }
    }

    private class MonitorInfo
    {
        public RECT WindowRect;
        public bool IsWindowOnAnyMonitor;
    }

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

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    // Win32 API declarations
    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

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
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(IntPtr hWnd);

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

    [DllImport("dwmapi.dll")]
    static extern int DwmGetWindowAttribute(IntPtr hwnd, int dwAttribute, out int pvAttribute, int cbAttribute);

    private delegate bool MonitorEnumProcDelegate(IntPtr hMonitor, IntPtr hdcMonitor, ref RECT lprcMonitor, ref MonitorInfo dwData);

    [DllImport("user32.dll")]
    private static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, MonitorEnumProcDelegate lpfnEnum, ref MonitorInfo dwData);

    private const int SW_HIDE = 0;
    private const int SW_SHOW = 5;
    private const uint GA_PARENT = 1;
    private const uint GW_HWNDNEXT = 2;
    private const int RGN_DIFF = 4;
    private const int DWMWA_CLOAKED = 14;

    private static bool MonitorEnumProc(IntPtr hMonitor, IntPtr hdcMonitor, ref RECT lprcMonitor, ref MonitorInfo dwData)
    {
        RECT monitorRect = lprcMonitor;
        RECT windowRect = dwData.WindowRect;
        RECT intersection = new RECT();

        if (IntersectRect(ref intersection, ref monitorRect, ref windowRect))
        {
            dwData.IsWindowOnAnyMonitor = true;
            return false;
        }
        return true;
    }
}