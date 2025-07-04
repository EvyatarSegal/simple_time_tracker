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
        // IMPORTANT: Updated to use Windows Authentication for local development
        // This connection string points to your default SQL Server instance and uses Windows Authentication.
        private static readonly string ConnectionString = "Server=.;Database=TimeTrackerDB;Integrated Security=True;TrustServerCertificate=True;";
        private string _lastActiveWindow = "";

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
            // *** NEW DEBUG LOG: Worker constructor entered ***
            _logger.LogInformation("[DEBUG] Worker constructor entered. Logger should be active.");
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
                    // *** DEBUG LOG ***
                    _logger.LogInformation($"[DEBUG] Current Active Window Detected: '{activeWindow}' | Last Logged Window: '{_lastActiveWindow}'");

                    if (activeWindow != _lastActiveWindow)
                    {
                        _lastActiveWindow = activeWindow;
                        // *** DEBUG LOG ***
                        _logger.LogInformation($"[DEBUG] Active window changed to: '{activeWindow}'. Calling LogActiveWindow.");
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
            int charsCopied = GetWindowText(handle, buffer, nChars);
            string title = charsCopied > 0 ? buffer.ToString() : "Unknown or no title";
            // *** DEBUG LOG ***
            _logger.LogInformation($"[DEBUG] GetActiveWindowTitle: Handle={handle}, Title='{title}'");
            return title;
        }

        private async Task LogActiveWindow(string windowTitle)
        {
            // *** DEBUG LOG ***
            _logger.LogInformation($"[DEBUG] Entering LogActiveWindow for: '{windowTitle}'");

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
            }

            bool isCloakedStatus = IsCloaked(hwnd); // Capture status for logging

            // *** DEBUG LOG ***
            _logger.LogInformation($"[DEBUG] LogActiveWindow - Before DB Call: Process='{processName}', Window='{windowTitle}', IsActive={isActive}, IsVisible={isVisible}, IsCloaked={isCloakedStatus}");

            await LogActivityToDatabase(
                DateTime.UtcNow,
                processName,
                windowTitle,
                memoryUsageMB,
                cpuUsagePercentage,
                audioLevel,
                isActive,
                isCloaked: isCloakedStatus
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
                string pName = Process.GetProcessById((int)processId).ProcessName;
                // *** DEBUG LOG ***
                _logger.LogInformation($"[DEBUG] GetActiveProcessName: Process ID={processId}, Name='{pName}'");
                return pName;
            }
            catch (Exception ex)
            {
                // *** DEBUG LOG ***
                _logger.LogWarning(ex, $"[DEBUG] Could not get process name for ID {processId}.");
                return "Unknown";
            }
        }

        private async Task StartResourceMonitoring(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    // *** DEBUG LOG ***
                    _logger.LogInformation("[DEBUG] Entering CheckResourceUsage (5-minute interval).");
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
                        // *** DEBUG LOG ***
                        _logger.LogInformation($"[DEBUG] Skipping process '{process.ProcessName}' due to filter (System/Idle/NoMainWindow/NoAudio).");
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
                    _logger.LogWarning(ex, $"[DEBUG] Could not process resource usage for a process during 5-minute check.");
                }
            }

            foreach (var usage in appUsage.Values)
            {
                bool isCloakedStatus = IsCloaked(usage.MainWindowHandle); // Capture status for logging
                // Filters: If window name is empty or window is cloaked (e.g., minimized to tray, background app)
                if (string.IsNullOrEmpty(usage.WindowName) || isCloakedStatus)
                {
                    // *** DEBUG LOG ***
                    _logger.LogInformation($"[DEBUG] Skipping app '{usage.ProcessName}' (Window='{usage.WindowName}') due to filter (Empty Window Name or Cloaked={isCloakedStatus}).");
                    continue;
                }

                // *** DEBUG LOG ***
                _logger.LogInformation($"[DEBUG] CheckResourceUsage - Before DB Call: Process='{usage.ProcessName}', Window='{usage.WindowName}', IsActive={usage.IsActive}, IsVisible={usage.IsVisible}, IsCloaked={isCloakedStatus}");


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
                    INSERT INTO ActivityLog (Timestamp, ProcessName, WindowTitle, MemoryUsageMB, CpuUsagePercent, AudioLevel, IsActive, IsCloaked)
                    VALUES (@Timestamp, @ProcessName, @WindowTitle, @MemoryUsageMB, @CpuUsage, @AudioLevel, @IsActive, @IsCloaked);
                    ";

                    command.Parameters.AddWithValue("@Timestamp", timestamp);
                    command.Parameters.AddWithValue("@ProcessName", (object)processName ?? DBNull.Value);
                    command.Parameters.AddWithValue("@WindowTitle", (object)windowTitle ?? DBNull.Value);
                    command.Parameters.AddWithValue("@MemoryUsageMB", memoryUsage);
                    command.Parameters.AddWithValue("@CpuUsage", cpuUsage);
                    command.Parameters.AddWithValue("@AudioLevel", audioLevel);
                    command.Parameters.AddWithValue("@IsActive", isActive);
                    command.Parameters.AddWithValue("@IsCloaked", isCloaked);

                    await command.ExecuteNonQueryAsync();
                    // *** DEBUG LOG ***
                    _logger.LogInformation($"[DEBUG] Successfully logged to DB: Process='{processName}', Window='{windowTitle}'");
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
            // *** DEBUG LOG ***
            _logger.LogInformation($"[DEBUG] Entering IsWindowTrulyVisible for handle: {hWnd}");

            if (hWnd == IntPtr.Zero)
            {
                _logger.LogInformation("[DEBUG] IsWindowTrulyVisible: hWnd is Zero.");
                return false;
            }

            if (!IsWindowVisible(hWnd))
            {
                _logger.LogInformation($"[DEBUG] IsWindowTrulyVisible: Window {hWnd} is not visible (IsWindowVisible returned false).");
                return false;
            }

            if (IsIconic(hWnd))
            {
                _logger.LogInformation($"[DEBUG] IsWindowTrulyVisible: Window {hWnd} is iconic (minimized).");
                return false;
            }

            try
            {
                RECT windowRect = new RECT();
                if (!GetWindowRect(hWnd, out windowRect))
                {
                    _logger.LogInformation($"[DEBUG] IsWindowTrulyVisible: GetWindowRect failed for {hWnd}.");
                    return false;
                }
                // *** DEBUG LOG ***
                _logger.LogInformation($"[DEBUG] IsWindowTrulyVisible: Window {hWnd} Rect: L={windowRect.Left}, T={windowRect.Top}, R={windowRect.Right}, B={windowRect.Bottom}");


                int windowWidth = windowRect.Right - windowRect.Left;
                int windowHeight = windowRect.Bottom - windowRect.Top;

                if (windowWidth <= 20 || windowHeight <= 20 || windowWidth <= 0 || windowHeight <= 0)
                {
                    _logger.LogInformation($"[DEBUG] IsWindowTrulyVisible: Window {hWnd} too small/invalid dimensions: W={windowWidth}, H={windowHeight}.");
                    return false;
                }

                MonitorInfo monitorInfo = new MonitorInfo();
                monitorInfo.WindowRect = windowRect;
                monitorInfo.IsWindowOnAnyMonitor = false;

                GCHandle handle = GCHandle.Alloc(monitorInfo);
                try
                {
                    IntPtr monitorInfoPtr = GCHandle.ToIntPtr(handle);
                    bool enumResult = EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, MonitorEnumProc, monitorInfoPtr);
                    // *** DEBUG LOG ***
                    _logger.LogInformation($"[DEBUG] IsWindowTrulyVisible: EnumDisplayMonitors for {hWnd} returned {enumResult}, IsWindowOnAnyMonitor={monitorInfo.IsWindowOnAnyMonitor}");

                    if (!monitorInfo.IsWindowOnAnyMonitor)
                    {
                        _logger.LogInformation($"[DEBUG] IsWindowTrulyVisible: Window {hWnd} not on any monitor.");
                        return false;
                    }
                }
                finally
                {
                    handle.Free();
                }

                IntPtr windowRegion = CreateRectRgn(windowRect.Left, windowRect.Top, windowRect.Right, windowRect.Bottom);
                if (windowRegion == IntPtr.Zero)
                {
                    _logger.LogInformation($"[DEBUG] IsWindowTrulyVisible: CreateRectRgn failed for {hWnd}.");
                    return false;
                }
                // *** DEBUG LOG ***
                _logger.LogInformation($"[DEBUG] IsWindowTrulyVisible: Created window region for {hWnd}.");


                IntPtr visibleRegion = GetVisibleRegion(hWnd);
                if (visibleRegion == IntPtr.Zero)
                {
                    DeleteObject(windowRegion);
                    _logger.LogInformation($"[DEBUG] IsWindowTrulyVisible: GetVisibleRegion returned Zero for {hWnd}.");
                    return false;
                }
                // *** DEBUG LOG ***
                _logger.LogInformation($"[DEBUG] IsWindowTrulyVisible: Obtained visible region for {hWnd}.");


                int windowArea = GetRegionArea(windowRegion);
                int visibleArea = GetRegionArea(visibleRegion);

                DeleteObject(windowRegion);
                DeleteObject(visibleRegion);

                if (windowArea <= 0)
                {
                    _logger.LogInformation($"[DEBUG] IsWindowTrulyVisible: Window area is zero or less for {hWnd}.");
                    return false;
                }

                double visiblePercentage = (double)visibleArea / windowArea * 100;
                // *** DEBUG LOG ***
                _logger.LogInformation($"[DEBUG] IsWindowTrulyVisible: Window {hWnd} - Area: {windowArea}, Visible Area: {visibleArea}, Visible %: {visiblePercentage:F2}");

                return visiblePercentage >= 30;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error in IsWindowTrulyVisible for window {hWnd}.");
                return false;
            }
        }

        // Static callback method for EnumDisplayMonitors
        private static bool MonitorEnumProc(IntPtr hMonitor, IntPtr hdcMonitor, IntPtr lprcMonitor, IntPtr dwData)
        {
            try
            {
                GCHandle handle = GCHandle.FromIntPtr(dwData);
                MonitorInfo monitorInfo = (MonitorInfo)handle.Target;

                RECT monitorRect = Marshal.PtrToStructure<RECT>(lprcMonitor);
                RECT intersection = new RECT();

                bool intersects = IntersectRect(out intersection, ref monitorRect, ref monitorInfo.WindowRect);
                // _logger.LogInformation($"[DEBUG] MonitorEnumProc: Intersects={intersects} for monitor {hMonitor} and window rect {monitorInfo.WindowRect.Left},{monitorInfo.WindowRect.Top}"); // Uncomment if needed, can be chatty

                if (intersects)
                {
                    monitorInfo.IsWindowOnAnyMonitor = true;
                    return false; // Stop enumeration
                }

                return true; // Continue enumeration
            }
            catch (Exception ex)
            {
                // _logger.LogError(ex, $"[DEBUG] Error in MonitorEnumProc."); // Uncomment if needed
                return false; // Stop enumeration on error
            }
        }

        private class MonitorInfo
        {
            public RECT WindowRect;
            public bool IsWindowOnAnyMonitor;
        }

        private IntPtr GetVisibleRegion(IntPtr hWnd)
        {
            // *** DEBUG LOG ***
            _logger.LogInformation($"[DEBUG] Entering GetVisibleRegion for handle: {hWnd}");
            try
            {
                RECT windowRect = new RECT();
                if (!GetWindowRect(hWnd, out windowRect))
                {
                    _logger.LogInformation($"[DEBUG] GetVisibleRegion: GetWindowRect failed for {hWnd}.");
                    return IntPtr.Zero;
                }

                IntPtr regionHandle = CreateRectRgn(
                    windowRect.Left, windowRect.Top,
                    windowRect.Right, windowRect.Bottom);

                if (regionHandle == IntPtr.Zero)
                {
                    _logger.LogInformation($"[DEBUG] GetVisibleRegion: CreateRectRgn failed for {hWnd}.");
                    return IntPtr.Zero;
                }

                IntPtr hParentWnd = GetAncestor(hWnd, GetAncestorFlags.GA_PARENT);
                IntPtr hChildWnd = hWnd;
                int overlayCount = 0; // For debug logging

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
                                    overlayCount++; // Increment count for debug
                                }
                            }
                        }

                        topWnd = GetWindow(topWnd, GetWindowType.GW_HWNDNEXT);
                    }

                    hChildWnd = hParentWnd;
                    hParentWnd = GetAncestor(hParentWnd, GetAncestorFlags.GA_PARENT);
                }
                // *** DEBUG LOG ***
                _logger.LogInformation($"[DEBUG] GetVisibleRegion for {hWnd} completed. Overlapping windows processed: {overlayCount}");

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
                _logger.LogInformation($"[DEBUG] GetRegionArea: dataSize is zero or less for region {region}.");
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
                // *** DEBUG LOG ***
                _logger.LogInformation($"[DEBUG] GetRegionArea: Region {region} has {rectCount} rectangles, total area: {area}.");
                return area;
            }
            finally
            {
                Marshal.FreeHGlobal(dataBuffer);
            }
        }

        private bool IsDesktopWindow(IntPtr hWnd)
        {
            bool isDesktop = hWnd == GetDesktopWindow() || hWnd == GetShellWindow();
            // _logger.LogInformation($"[DEBUG] IsDesktopWindow: {hWnd} is desktop? {isDesktop}"); // Can be very chatty
            return isDesktop;
        }

        public delegate bool MonitorEnumProcDelegate(IntPtr hMonitor, IntPtr hdcMonitor, IntPtr lprcMonitor, IntPtr dwData);

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
            MonitorEnumProcDelegate lpfnEnum, IntPtr dwData);

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
            // *** DEBUG LOG ***
            int result = DwmGetWindowAttribute(hWnd, DWMWA_CLOAKED, out isCloaked, sizeof(int));
            // _logger.LogInformation($"[DEBUG] IsCloaked for {hWnd}: Result={result}, IsCloakedValue={isCloaked}"); // Uncomment if too chatty
            return result == 0 && isCloaked != 0;
        }
    }
}