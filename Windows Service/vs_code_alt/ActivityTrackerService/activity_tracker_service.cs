using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NAudio.CoreAudioApi;
using static Vanara.PInvoke.Gdi32; // Assuming you still need these, otherwise consider removing
using static Vanara.PInvoke.Kernel32; // Assuming you still need these, otherwise consider removing

namespace ActivityTrackerService
{
    public partial class ActivityTrackerService : System.ServiceProcess.ServiceBase
    {
        private static readonly string LogFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ActivityLog.txt");
        private static string _lastActiveWindow = "";
        private static CancellationTokenSource _cts;
        private Task _windowTrackingTask;
        private Task _resourceMonitoringTask;

        public ActivityTrackerService()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            try
            {
                _cts = new CancellationTokenSource();

                _windowTrackingTask = StartActiveWindowTracking(_cts.Token);
                _resourceMonitoringTask = StartResourceMonitoring(_cts.Token);

                // Now calling the static WriteToEventLog
                WriteToEventLog("Activity Tracker Service Started", EventLogEntryType.Information);
                // Initial log to ensure file is written and service is starting debug output
                LogActivityToFile(DateTime.UtcNow, "Service", "Service started successfully. Initiating debug logging.", 0, 0, 0, false, false, false).Wait();
            }
            catch (Exception ex)
            {
                // Now calling the static WriteToEventLog
                WriteToEventLog($"Error during service start: {ex.Message}", EventLogEntryType.Error);
                // Log to file as well if possible, for debugging startup issues
                try { File.AppendAllText(LogFilePath, $"{DateTime.UtcNow}: ERROR - Service Start Failed: {ex.Message}\n"); } catch { /* Ignore if file logging itself fails here */ }
            }
        }

        protected override void OnStop()
        {
            try
            {
                // Now calling the static WriteToEventLog
                WriteToEventLog("Activity Tracker Service Stopping...", EventLogEntryType.Information);

                _cts?.Cancel();

                // Wait for tasks to complete with timeout
                if (_windowTrackingTask != null) _windowTrackingTask.Wait(5000);
                if (_resourceMonitoringTask != null) _resourceMonitoringTask.Wait(5000);

                _cts?.Dispose();
                // Now calling the static WriteToEventLog
                WriteToEventLog("Activity Tracker Service Stopped", EventLogEntryType.Information);
                LogActivityToFile(DateTime.UtcNow, "Service", "Service stopped successfully.", 0, 0, 0, false, false, false).Wait();
            }
            catch (Exception ex)
            {
                // Now calling the static WriteToEventLog
                WriteToEventLog($"Error stopping service: {ex.Message}", EventLogEntryType.Error);
                try { File.AppendAllText(LogFilePath, $"{DateTime.UtcNow}: ERROR - Service Stop Failed: {ex.Message}\n"); } catch { }
            }
        }

        private static async Task StartActiveWindowTracking(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    await LogActiveWindow(); // Call this directly, it will handle window details
                    await Task.Delay(1000, token); // Check every 1 second
                }
            }
            catch (TaskCanceledException)
            {
                // Normal cancellation, no need to log here usually
            }
            catch (Exception ex)
            {
                // Now calling the static WriteToEventLog
                WriteToEventLog($"Error in StartActiveWindowTracking: {ex.Message}", EventLogEntryType.Error);
                await LogActivityToFile(DateTime.UtcNow, "ERROR", $"Active Window Tracking Error: {ex.Message}", 0, 0, 0, false, false, false);
            }
        }

        private static async Task LogActiveWindow()
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
                // Debugging: Always log foreground window handle status
                await LogActivityToFile(DateTime.UtcNow, "DEBUG_ACTIVE_WINDOW", $"Raw Foreground HWND: {hwnd}", 0, 0, 0, false, false, false);

                if (hwnd == IntPtr.Zero)
                {
                    windowTitle = "[Idle]";
                    processName = "[Idle]";
                    await LogActivityToFile(DateTime.UtcNow, processName, windowTitle, 0, 0, 0, false, false, false);
                    return; // No active window, nothing more to do for this iteration
                }

                // Get title
                const int nChars = 256;
                StringBuilder buffer = new StringBuilder(nChars);
                int textLength = GetWindowText(hwnd, buffer, nChars);
                windowTitle = (textLength > 0) ? buffer.ToString() : "[No Title]";
                await LogActivityToFile(DateTime.UtcNow, "DEBUG_ACTIVE_WINDOW", $"HWND: {hwnd}, Raw Title: '{windowTitle}'", 0, 0, 0, false, false, false);

                // Get process name and ID
                GetWindowThreadProcessId(hwnd, out processId);
                try
                {
                    Process process = Process.GetProcessById((int)processId);
                    processName = process.ProcessName;
                    memoryUsageMB = process.WorkingSet64 / (1024f * 1024f);
                    cpuUsagePercentage = GetCpuUsage(process);
                    await LogActivityToFile(DateTime.UtcNow, "DEBUG_ACTIVE_WINDOW", $"HWND: {hwnd}, ProcessName: '{processName}', PID: {processId}", 0, 0, 0, false, false, false);
                }
                catch (ArgumentException)
                {
                    processName = "[Process Not Found]";
                    await LogActivityToFile(DateTime.UtcNow, "DEBUG_ACTIVE_WINDOW", $"HWND: {hwnd}, Process Not Found for PID: {processId}", 0, 0, 0, false, false, false);
                }
                catch (InvalidOperationException)
                {
                    processName = "[Process Exited]";
                    await LogActivityToFile(DateTime.UtcNow, "DEBUG_ACTIVE_WINDOW", $"HWND: {hwnd}, Process Exited for PID: {processId}", 0, 0, 0, false, false, false);
                }
                catch (Exception ex)
                {
                    processName = "[Error Getting Process]";
                    await LogActivityToFile(DateTime.UtcNow, "ERROR", $"HWND: {hwnd}, Process Name/Resource Error for PID {processId}: {ex.Message}", 0, 0, 0, false, false, false);
                }

                // Check visibility and cloaked status
                isVisible = IsWindowTrulyVisible(hwnd);
                isCloaked = IsCloaked(hwnd);
                isActive = (hwnd == GetForegroundWindow()); // Re-check to ensure it's still foreground

                await LogActivityToFile(DateTime.UtcNow, "DEBUG_ACTIVE_WINDOW", $"HWND: {hwnd}, IsVisible: {isVisible}, IsCloaked: {isCloaked}, IsActive (re-check): {isActive}", 0, 0, 0, false, false, false);

                // Get audio activity
                Dictionary<int, bool> activeAudio = GetActiveAudioProcesses();
                bool processAudioActive = activeAudio.GetValueOrDefault((int)processId, false);
                audioLevel = processAudioActive ? 1 : 0;

                // --- ACTUAL LOGGING OF ACTIVITY ---
                // Log only if it's a new active window or for debugging purposes log everything
                if (windowTitle != _lastActiveWindow || string.IsNullOrWhiteSpace(_lastActiveWindow))
                {
                    _lastActiveWindow = windowTitle; // Update last active window only if new
                    await LogActivityToFile(
                        DateTime.UtcNow,
                        processName,
                        windowTitle,
                        memoryUsageMB,
                        cpuUsagePercentage,
                        audioLevel,
                        isActive,
                        isVisible, // Log true visibility from IsWindowTrulyVisible
                        isCloaked // Log the cloaked status
                    );
                }
            }
            catch (Exception ex)
            {
                // Now calling the static WriteToEventLog
                WriteToEventLog($"General Error in LogActiveWindow: {ex.Message}", EventLogEntryType.Error);
                await LogActivityToFile(DateTime.UtcNow, "ERROR", $"General LogActiveWindow Error: {ex.Message}", 0, 0, 0, false, false, false);
            }
        }

        // --- Resource Monitoring ---
        private static async Task StartResourceMonitoring(CancellationToken token)
        {
            try
            {
                PerformanceCounter cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                cpuCounter.NextValue(); // Call once to initialize

                while (!token.IsCancellationRequested)
                {
                    await CheckResourceUsage(cpuCounter); // Pass the counter
                    await Task.Delay(5 * 60 * 1000, token); // Log every 5 minutes
                }
            }
            catch (TaskCanceledException)
            {
                // Normal cancellation
            }
            catch (Exception ex)
            {
                // Now calling the static WriteToEventLog
                WriteToEventLog($"Error in StartResourceMonitoring: {ex.Message}", EventLogEntryType.Error);
                await LogActivityToFile(DateTime.UtcNow, "ERROR", $"Resource Monitoring Task Error: {ex.Message}", 0, 0, 0, false, false, false);
            }
        }

        // Modified to accept cpuCounter
        private static async Task CheckResourceUsage(PerformanceCounter totalCpuCounter)
        {
            Dictionary<int, bool> activeAudio = GetActiveAudioProcesses();
            Dictionary<string, ResourceUsage> appUsage = new Dictionary<string, ResourceUsage>();

            // Log total CPU usage first
            double totalCpuUsage = GetCpuUsage(totalCpuCounter);
            await LogActivityToFile(DateTime.UtcNow, "SYSTEM", $"Total CPU: {totalCpuUsage:F2}%", 0, totalCpuUsage, 0, false, false, false);


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
                    bool isCloaked = IsCloaked(hwnd); // Check cloaked status here

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
                        await LogActivityToFile(DateTime.UtcNow, "ERROR_RESOURCE", $"Process '{currentProcessName}' (PID {process.Id}) resource error: {ex.Message}", 0, 0, 0, false, false, false);
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
                            IsCloaked = isCloaked // Store cloaked status
                        };
                    }
                }
                catch (Exception ex)
                {
                    // Catch general errors for processing a single process
                    await LogActivityToFile(DateTime.UtcNow, "ERROR_PROCESS_LOOP", $"Error processing process in CheckResourceUsage: {ex.Message}", 0, 0, 0, false, false, false);
                }
            }

            foreach (var usage in appUsage.Values)
            {
                // Temporarily disable the cloaked filter for debugging, enable once we understand the logs
                // if (string.IsNullOrEmpty(usage.WindowName) || usage.IsCloaked)
                // {
                //     await LogActivityToFile(DateTime.UtcNow, "DEBUG_FILTERED", $"Filtered out '{usage.ProcessName}' (Window: '{usage.WindowName}', Cloaked: {usage.IsCloaked})", 0, 0, 0, false, false, false);
                //     continue;
                // }

                await LogActivityToFile(
                    DateTime.UtcNow,
                    usage.ProcessName,
                    usage.WindowName,
                    usage.MemoryUsageMB,
                    usage.CpuUsagePercentage,
                    usage.AudioLevel,
                    usage.IsActive,
                    usage.IsVisible,
                    usage.IsCloaked // Log the cloaked status for debugging
                );
            }
        }

        private static float GetCpuUsage(Process process)
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
                LogActivityToFile(DateTime.UtcNow, "ERROR_CPU_PROCESS", $"Error getting CPU for '{process.ProcessName}': {ex.Message}", 0, 0, 0, false, false, false).Wait();
                return 0;
            }
        }

        // Overload for total CPU usage
        private static double GetCpuUsage(PerformanceCounter cpuCounter)
        {
            try
            {
                return cpuCounter.NextValue();
            }
            catch (Exception ex)
            {
                LogActivityToFile(DateTime.UtcNow, "ERROR_CPU_TOTAL", $"Error getting total CPU usage: {ex.Message}", 0, 0, 0, false, false, false).Wait();
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
                                    catch { isActive = volume > volumeThreshold; }

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
                                    // Log this to file, not just event log, for easier debugging
                                    LogActivityToFile(DateTime.UtcNow, "ERROR_AUDIO_SESSION", $"Error processing audio session: {ex.Message}", 0, 0, 0, false, false, false).Wait();
                                    // Now calling the static WriteToEventLog
                                    WriteToEventLog($"Error processing audio session: {ex.Message}", EventLogEntryType.Warning);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogActivityToFile(DateTime.UtcNow, "ERROR_AUDIO_GLOBAL", $"Global error checking audio: {ex.Message}", 0, 0, 0, false, false, false).Wait();
                // Now calling the static WriteToEventLog
                WriteToEventLog($"Error checking audio: {ex.Message}", EventLogEntryType.Warning);
            }
            return activeAudio;
        }

        private static async Task LogActivityToFile(
            DateTime timestamp,
            string processName,
            string windowTitle,
            double memoryUsage,
            double cpuUsage,
            int audioLevel,
            bool isActive,
            bool isVisible, // Renamed parameter from `isCloaked` to `isVisible` for clarity here
            bool isCloaked // Added a separate parameter for `isCloaked`
        )
        {
            try
            {
                string logEntry = $"{timestamp:yyyy-MM-dd HH:mm:ss} | " +
                                  $"Process: {processName} | " +
                                  $"Window: {windowTitle} | " +
                                  $"Mem: {memoryUsage:F2} MB | " +
                                  $"CPU: {cpuUsage:F2}% | " +
                                  $"Audio: {(audioLevel == 1 ? "Active" : "Inactive")} | " +
                                  $"IsActive: {isActive} | " +
                                  $"IsVisible: {isVisible} | " + // Log IsVisible explicitly
                                  $"IsCloaked: {isCloaked}";     // Log IsCloaked explicitly

                using (StreamWriter writer = new StreamWriter(LogFilePath, true))
                {
                    await writer.WriteLineAsync(logEntry);
                }
            }
            catch (Exception ex)
            {
                // This catch is vital: if file logging itself fails, log to Event Viewer
                string errorMsg = $"CRITICAL ERROR: Could not write to log file {LogFilePath}: {ex.Message}";
                // Now calling the static WriteToEventLog
                WriteToEventLog(errorMsg, EventLogEntryType.Error);
                // Also attempt to write to console for immediate visibility if debugging locally
                Console.WriteLine(errorMsg);
            }
        }

        // Changed to static
        private static void WriteToEventLog(string message, EventLogEntryType entryType)
        {
            try
            {
                using (EventLog eventLog = new EventLog("Application"))
                {
                    eventLog.Source = "ActivityTrackerService";
                    eventLog.WriteEntry(message, entryType);
                }
            }
            catch (Exception ex)
            {
                // Fallback for EventLog errors (e.g., source not registered, permissions)
                Console.WriteLine($"ERROR: Could not write to EventLog: {ex.Message}. Original Message: {message}");
            }
        }

        public class ResourceUsage
        {
            public nint MainWindowHandle { get; set; }
            public string WindowName { get; set; }
            public string ProcessName { get; set; }
            public float MemoryUsageMB { get; set; }
            public float CpuUsagePercentage { get; set; }
            public int AudioLevel { get; set; } = 0;
            public bool IsActive { get; set; }
            public bool IsVisible { get; set; } // Reflects IsWindowTrulyVisible
            public bool IsCloaked { get; set; } // Reflects DWMWA_CLOAKED status
        }

        // --- P/Invoke and Helper Methods (rest of your existing code below this) ---
        // These methods remain largely the same, just ensure they are within the class
        // as they were.

        // DllImports
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

        // Constants
        private const uint GA_PARENT = 1;
        private const uint GW_HWNDNEXT = 2;
        private const int RGN_DIFF = 4;
        private const int DWMWA_CLOAKED = 14;

        // Moved from Program.cs, ensure these are correct.
        // It's possible IsWindowTrulyVisible or IsCloaked are overly aggressive.
        // Temporarily commented out their usage in GetActiveWindowTitle for debugging.
        private static bool IsCloaked(IntPtr hWnd)
        {
            if (hWnd == IntPtr.Zero) return false;
            try
            {
                int isCloaked = 0;
                // Using sizeof(int) directly is fine, but Marshal.SizeOf(typeof(int)) is also an option.
                // It's crucial to check the return value of DwmGetWindowAttribute. 0 means success.
                if (DwmGetWindowAttribute(hWnd, DWMWA_CLOAKED, out isCloaked, sizeof(int)) == 0)
                {
                    return isCloaked != 0;
                }
                // If DwmGetWindowAttribute fails, assume not cloaked to not filter out too much.
                LogActivityToFile(DateTime.UtcNow, "DEBUG_CLOAKED_FAIL", $"DwmGetWindowAttribute failed for HWND {hWnd}. Assuming not cloaked.", 0, 0, 0, false, false, false).Wait();
                return false;
            }
            catch (Exception ex)
            {
                LogActivityToFile(DateTime.UtcNow, "ERROR_ISCLOAKED", $"Error in IsCloaked for HWND {hWnd}: {ex.Message}", 0, 0, 0, false, false, false).Wait();
                return false; // On error, assume not cloaked to not filter
            }
        }

        private static bool IsWindowTrulyVisible(IntPtr hWnd)
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

                MonitorInfo monitorInfo = new MonitorInfo();
                monitorInfo.WindowRect = windowRect;
                monitorInfo.IsWindowOnAnyMonitor = false;

                EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, MonitorEnumProc, ref monitorInfo);

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
                LogActivityToFile(DateTime.UtcNow, "ERROR_TRULY_VISIBLE", $"Error in IsWindowTrulyVisible for HWND {hWnd}: {ex.Message}", 0, 0, 0, false, false, false).Wait();
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
                return false;
            }

            return true;
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

                IntPtr hParentWnd = GetAncestor(hWnd, GA_PARENT);
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
                            GetWindowRect(topWnd, ref topWndRect))
                        {
                            RECT tempRect = new RECT();
                            if (IntersectRect(ref tempRect, ref topWndRect, ref windowRect))
                            {
                                IntPtr topWndRgn = CreateRectRgn(
                                    topWndRect.Left, topWndRect.Top,
                                    topWndRect.Right, topWndRect.Bottom);

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
                LogActivityToFile(DateTime.UtcNow, "ERROR_VISIBLE_REGION", $"Error in GetVisibleRegion for HWND {hWnd}: {ex.Message}", 0, 0, 0, false, false, false).Wait();
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

        // Delegate and structures
        private delegate bool MonitorEnumProcDelegate(IntPtr hMonitor, IntPtr hdcMonitor, ref RECT lprcMonitor, ref MonitorInfo dwData);

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
    }

    static class Program
    {
        static void Main()
        {
            System.ServiceProcess.ServiceBase[] ServicesToRun;
            ServicesToRun = new System.ServiceProcess.ServiceBase[]
            {
                new ActivityTrackerService()
            };
            System.ServiceProcess.ServiceBase.Run(ServicesToRun);
        }
    }

    partial class ActivityTrackerService
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.ServiceName = "ActivityTrackerService";
        }
    }
}