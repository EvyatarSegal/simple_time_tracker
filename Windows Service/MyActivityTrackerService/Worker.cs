using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NAudio.CoreAudioApi;
using Microsoft.Data.SqlClient;

namespace ActivityTrackerService
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private static readonly string ConnectionString = "Server=(localdb)\\MSSQLLocalDB;Database=TimeTrackerDB;Integrated Security=True;TrustServerCertificate=True;";
        private string _lastActiveWindow = "";

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Activity Tracker Service Started at: {time}", DateTimeOffset.Now);

            try
            {
                // Create tasks for active window tracking and resource monitoring
                Task windowTrackingTask = StartActiveWindowTracking(stoppingToken);
                Task resourceMonitoringTask = StartResourceMonitoring(stoppingToken);

                // Wait for both tasks to complete or for cancellation
                await Task.WhenAll(windowTrackingTask, resourceMonitoringTask);
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Activity Tracker Service is stopping due to cancellation.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unhandled exception occurred in the Activity Tracker Service.");
            }

            _logger.LogInformation("Activity Tracker Service Stopped at: {time}", DateTimeOffset.Now);
        }

        private async Task StartActiveWindowTracking(CancellationToken token)
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
                _logger.LogInformation("[INFO] Active window tracking stopped.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in StartActiveWindowTracking.");
            }
        }

        private string GetActiveWindowTitle()
        {
            const int nChars = 256;
            IntPtr handle = GetForegroundWindow();
            StringBuilder buffer = new StringBuilder(nChars);
            return GetWindowText(handle, buffer, nChars) > 0 ? buffer.ToString() : "Unknown";
        }

        private async Task LogActiveWindow(string windowTitle)
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
            catch (Exception ex)
            {
                _logger.LogWarning(ex, $"Could not get resource usage for process ID {processId}.");
                // Ignore if process not found or other issues during resource fetching for this process
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

            _logger.LogInformation("###############################");
            _logger.LogInformation($"Process: {processName}, Mb:{memoryUsageMB:F2}, CPU:{cpuUsagePercentage:F2}, Audio:{audioLevel}, Active:{isActive}, Visible:{isVisible}");
        }

        private string GetActiveProcessName()
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

        private async Task StartResourceMonitoring(CancellationToken token)
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
                _logger.LogInformation("[INFO] Resource monitoring stopped.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in StartResourceMonitoring.");
            }
        }

        private async Task CheckResourceUsage()
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
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, $"Could not process resource usage for a process.");
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

                _logger.LogInformation($"{DateTime.Now}, **************************************************************");
                _logger.LogInformation($"{usage.ProcessName}, {usage.MemoryUsageMB:F2}MB, {usage.CpuUsagePercentage:F2}%, Audio:{usage.AudioLevel}, Active:{usage.IsActive}, Visible:{usage.IsVisible}");
            }
        }

        private async Task LogActivityToDatabase(
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
            catch (SqlException ex)
            {
                _logger.LogError(ex, $"Database error logging activity: {ex.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"An unexpected error occurred logging activity: {ex.Message}");
            }
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

        private float GetCpuUsage(Process process)
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
            catch (Exception ex)
            {
                _logger.LogWarning(ex, $"Could not get CPU usage for process {process.ProcessName}.");
                return 0;
            }
        }

        private Dictionary<int, bool> GetActiveAudioProcesses()
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
                                _logger.LogWarning(ex, $"Error processing audio session.");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error checking audio.");
            }
            return activeAudio;
        }

        private bool IsWindowTrulyVisible(IntPtr hWnd)
        {
            if (hWnd == IntPtr.Zero)
            {
                return false;
            }

            if (!IsWindowVisible(hWnd) || IsIconic(hWnd))
            {
                return false;
            }

            try
            {
                RECT windowRect = new RECT();
                if (!GetWindowRect(hWnd, out windowRect))
                {
                    return false;
                }

                int windowWidth = windowRect.Right - windowRect.Left;
                int windowHeight = windowRect.Bottom - windowRect.Top;

                if (windowWidth <= 20 || windowHeight <= 20 || windowWidth <= 0 || windowHeight <= 0)
                {
                    return false;
                }

                // Create a MonitorInfo instance to track the result
                MonitorInfo monitorInfo = new MonitorInfo();
                monitorInfo.WindowRect = windowRect;
                monitorInfo.IsWindowOnAnyMonitor = false;

                // Use a lambda that captures the monitorInfo variable
                bool result = EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, 
                    (hMonitor, hdcMonitor, lprcMonitor, dwData) => 
                    {
                        RECT monitorRect = Marshal.PtrToStructure<RECT>(lprcMonitor);
                        RECT intersection = new RECT();

                        if (IntersectRect(out intersection, ref monitorRect, ref windowRect))
                        {
                            monitorInfo.IsWindowOnAnyMonitor = true;
                            return false; // Stop enumeration
                        }
                        return true; // Continue enumeration
                    }, 
                    IntPtr.Zero);

                if (!monitorInfo.IsWindowOnAnyMonitor)
                {
                    return false;
                }

                IntPtr windowRegion = CreateRectRgn(windowRect.Left, windowRect.Top, windowRect.Right, windowRect.Bottom);
                if (windowRegion == IntPtr.Zero)
                {
                    return false;
                }

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
                return visiblePercentage >= 30;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error in IsWindowTrulyVisible for window {hWnd}.");
                return false;
            }
        }

        private class MonitorInfo
        {
            public RECT WindowRect;
            public bool IsWindowOnAnyMonitor;
        }

        private IntPtr GetVisibleRegion(IntPtr hWnd)
        {
            try
            {
                RECT windowRect = new RECT();
                if (!GetWindowRect(hWnd, out windowRect))
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

                IntPtr hParentWnd = GetAncestor(hWnd, GetAncestorFlags.GA_PARENT);
                IntPtr hChildWnd = hWnd;

                while (hChildWnd != IntPtr.Zero && !IsDesktopWindow(hChildWnd))
                {
                    IntPtr topWnd = GetTopWindow(hParentWnd);

                    while (topWnd != IntPtr.Zero)
                    {
                        if (topWnd == hChildWnd)
                        {
                            break;
                        }

                        RECT topWndRect = new RECT();
                        if (IsWindowVisible(topWnd) && !IsIconic(topWnd) &&
                            GetWindowRect(topWnd, out topWndRect))
                        {
                            RECT tempRect = new RECT();
                            if (IntersectRect(out tempRect, ref topWndRect, ref windowRect))
                            {
                                IntPtr topWndRgn = CreateRectRgn(
                                    topWndRect.Left, topWndRect.Top,
                                    topWndRect.Right, topWndRect.Bottom);

                                if (topWndRgn != IntPtr.Zero)
                                {
                                    CombineRgn(regionHandle, regionHandle, topWndRgn, CombineRgnStyles.RGN_DIFF);
                                    DeleteObject(topWndRgn);
                                }
                            }
                        }

                        topWnd = GetWindow(topWnd, GetWindowType.GW_HWNDNEXT);
                    }

                    hChildWnd = hParentWnd;
                    hParentWnd = GetAncestor(hParentWnd, GetAncestorFlags.GA_PARENT);
                }

                return regionHandle;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error in GetVisibleRegion for window {hWnd}.");
                return IntPtr.Zero;
            }
        }

        private int GetRegionArea(IntPtr region)
        {
            uint dataSize = GetRegionData(region, 0, IntPtr.Zero);
            if (dataSize <= 0)
            {
                return 0;
            }

            IntPtr dataBuffer = Marshal.AllocHGlobal((int)dataSize);
            try
            {
                GetRegionData(region, dataSize, dataBuffer);
                RGNDATA regionData = Marshal.PtrToStructure<RGNDATA>(dataBuffer);
                uint rectCount = regionData.rdh.nCount;
                int area = 0;

                IntPtr rectBuffer = new IntPtr(dataBuffer.ToInt64() + Marshal.SizeOf(typeof(RGNDATAHEADER)));
                for (int i = 0; i < rectCount; i++)
                {
                    RECT rect = Marshal.PtrToStructure<RECT>(
                        new IntPtr(rectBuffer.ToInt64() + i * Marshal.SizeOf(typeof(RECT))));

                    area += (rect.Right - rect.Left) * (rect.Bottom - rect.Top);
                }

                return area;
            }
            finally
            {
                Marshal.FreeHGlobal(dataBuffer);
            }
        }

        private bool IsDesktopWindow(IntPtr hWnd)
        {
            return hWnd == GetDesktopWindow() || hWnd == GetShellWindow();
        }

        // Windows API P/Invoke declarations
        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll")]
        private static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, 
            Func<IntPtr, IntPtr, IntPtr, IntPtr, bool> lpfnEnum, IntPtr dwData);

        [DllImport("gdi32.dll")]
        private static extern IntPtr CreateRectRgn(int nLeftRect, int nTopRect, int nRightRect, int nBottomRect);

        [DllImport("gdi32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteObject(IntPtr hObject);

        [DllImport("gdi32.dll")]
        private static extern int CombineRgn(IntPtr hrgnDest, IntPtr hrgnSrc1, IntPtr hrgnSrc2, CombineRgnStyles fnCombineMode);

        [DllImport("gdi32.dll")]
        private static extern uint GetRegionData(IntPtr hRgn, uint dwCount, IntPtr lpRgnData);

        [DllImport("user32.dll")]
        private static extern IntPtr GetAncestor(IntPtr hwnd, GetAncestorFlags gaFlags);

        [DllImport("user32.dll")]
        private static extern IntPtr GetTopWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern IntPtr GetWindow(IntPtr hWnd, GetWindowType uCmd);

        [DllImport("user32.dll")]
        private static extern IntPtr GetDesktopWindow();

        [DllImport("user32.dll")]
        private static extern IntPtr GetShellWindow();

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IntersectRect(out RECT lprcDst, ref RECT lprcSrc1, ref RECT lprcSrc2);

        [DllImport("dwmapi.dll")]
        private static extern int DwmGetWindowAttribute(IntPtr hwnd, int dwAttribute, out int pvAttribute, int cbAttribute);

        // Enums and Structs
        [StructLayout(LayoutKind.Sequential)]
        public struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RGNDATAHEADER
        {
            public uint dwSize;
            public uint iType;
            public uint nCount;
            public uint nRgnSize;
            public RECT rcBound;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RGNDATA
        {
            public RGNDATAHEADER rdh;
        }

        public enum GetAncestorFlags : uint
        {
            GA_PARENT = 1,
            GA_ROOT = 2,
            GA_ROOTOWNER = 3
        }

        public enum GetWindowType : uint
        {
            GW_HWNDFIRST = 0,
            GW_HWNDLAST = 1,
            GW_HWNDNEXT = 2,
            GW_HWNDPREV = 3,
            GW_OWNER = 4,
            GW_CHILD = 5,
            GW_ENABLEDPOPUP = 6
        }

        public enum CombineRgnStyles : int
        {
            RGN_AND = 1,
            RGN_OR = 2,
            RGN_XOR = 3,
            RGN_DIFF = 4,
            RGN_COPY = 5
        }

        private const int DWMWA_CLOAKED = 14;

        static bool IsCloaked(IntPtr hWnd)
        {
            int isCloaked = 0;
            return DwmGetWindowAttribute(hWnd, DWMWA_CLOAKED, out isCloaked, sizeof(int)) == 0 && isCloaked != 0;
        }
    }
}