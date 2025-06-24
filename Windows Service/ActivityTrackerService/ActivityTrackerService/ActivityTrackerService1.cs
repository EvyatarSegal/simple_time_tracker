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
using static Vanara.PInvoke.Gdi32;
using static Vanara.PInvoke.Kernel32;
using Microsoft.Data.SqlClient;

namespace ActivityTrackerService
{
    public partial class ActivityTrackerService : ServiceBase
    {
        // Connection string for your SQL Server LocalDB instance
        private static readonly string ConnectionString = "Server=(localdb)\\TimeTrackerInstance;Database=TimeTrackerDB2;Integrated Security=True;TrustServerCertificate=True;";   
   
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

                WriteToEventLog("Activity Tracker Service Started", EventLogEntryType.Information);
            }
            catch (Exception ex)
            {
                WriteToEventLog($"Error starting service: {ex.Message}", EventLogEntryType.Error);
                throw;
            }
        }

        protected override void OnStop()
        {
            try
            {
                WriteToEventLog("Activity Tracker Service Stopping...", EventLogEntryType.Information);
                
                _cts?.Cancel();
                
                // Wait for tasks to complete with timeout
                if (_windowTrackingTask != null && _resourceMonitoringTask != null)
                {
                    Task.WaitAll(new[] { _windowTrackingTask, _resourceMonitoringTask }, TimeSpan.FromSeconds(30));
                }

                _cts?.Dispose();
                WriteToEventLog("Activity Tracker Service Stopped", EventLogEntryType.Information);
            }
            catch (Exception ex)
            {
                WriteToEventLog($"Error stopping service: {ex.Message}", EventLogEntryType.Error);
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
                // Normal cancellation, no need to log
            }
            catch (Exception ex)
            {
                WriteToEventLog($"Error in StartActiveWindowTracking: {ex.Message}", EventLogEntryType.Error);
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
                // Normal cancellation, no need to log
            }
            catch (Exception ex)
            {
                WriteToEventLog($"Error in StartResourceMonitoring: {ex.Message}", EventLogEntryType.Error);
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
            catch (SqlException ex)
            {
                WriteToEventLog($"Database error logging activity: {ex.Message}", EventLogEntryType.Error);
            }
            catch (Exception ex)
            {
                WriteToEventLog($"An unexpected error occurred logging activity: {ex.Message}", EventLogEntryType.Error);
            }
        }

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
            catch
            {
                // If we can't write to event log, silently continue
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
                                WriteToEventLog($"Error processing audio session: {ex.Message}", EventLogEntryType.Warning);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WriteToEventLog($"Error checking audio: {ex.Message}", EventLogEntryType.Warning);
            }
            return activeAudio;
        }

        // All the Windows API methods and supporting code remain the same
        private static bool IsWindowTrulyVisible(IntPtr hWnd)
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
                WriteToEventLog($"Error in IsWindowTrulyVisible: {ex.Message}", EventLogEntryType.Warning);
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
                WriteToEventLog($"Error in GetVisibleRegion: {ex.Message}", EventLogEntryType.Warning);
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

        static bool IsCloaked(IntPtr hWnd)
        {
            int isCloaked = 0;
            return DwmGetWindowAttribute(hWnd, DWMWA_CLOAKED, out isCloaked, sizeof(int)) == 0 && isCloaked != 0;
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

        // DLL Imports
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
    }

    static class Program
    {
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