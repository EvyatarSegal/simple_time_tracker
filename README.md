# Activity Tracker (C# Console Application)

This C# console application is designed to track and log active window information and system resource usage (CPU, Memory, Audio) to a local file. It continuously monitors the foreground window and periodically logs detailed information about active processes.

## Features

* **Active Window Tracking:** Monitors and logs changes in the foreground window title and the associated process name.
* **Resource Monitoring:** Periodically checks and logs CPU usage, memory consumption, and audio activity for running processes.
* **Visibility Detection:** Attempts to determine if a window is truly visible on the screen, even accounting for overlaps and cloaked windows.
* **Audio Activity Detection:** Identifies processes that are actively playing audio.
* **Persistent Logging:** All activity and resource usage data are logged to a CSV-formatted text file (`activity_log.txt`).
* **Robust Logging:** Includes retry mechanisms for file locking issues during logging.

## Log File Format

The `activity_log.txt` file is a comma-separated values (CSV) file with the following columns:

* `Timestamp`: Date and time of the log entry.
* `Process Name`: The name of the executable process.
* `Window Title`: The title of the active window.
* `Memory Usage (MB)`: Memory consumed by the process in megabytes.
* `CPU Usage (%)`: CPU utilization of the process as a percentage.
* `Process Audio Level`: Binary flag (1 if playing audio, 0 otherwise).
* `IsActive`: Boolean (True if the window is the foreground window, False otherwise).
* `IsVisible`: Boolean (True if the window is truly visible on screen, False otherwise).

## Getting Started

### Prerequisites

* .NET (e.g., .NET Framework or .NET Core/5+)
* Visual Studio (or any compatible C# IDE)

### Build and Run

1.  **Clone or Download:** Get the `Program.cs` file.
2.  **Create a New Project:** Open Visual Studio (or your preferred IDE), create a new C# Console Application project.
3.  **Add `Program.cs`:** Replace the default `Program.cs` in your new project with the provided `Program.cs` file.
4.  **Add NuGet Packages:** This project uses the `NAudio.CoreAudioApi` and `Vanara.PInvoke` NuGet packages. You'll need to install them:
    * Right-click on your project in Solution Explorer -> `Manage NuGet Packages...`
    * Search for and install `NAudio.CoreAudioApi`
    * Search for and install `Vanara.PInvoke.Gdi32`
    * Search for and install `Vanara.PInvoke.Kernel32`
    * Search for and install `Vanara.PInvoke.User32`
    * Search for and install `Vanara.PInvoke.DwmApi`
5.  **Build:** Build the solution (Build -> Build Solution or `Ctrl+Shift+B`).
6.  **Run:** Run the application (Debug -> Start Debugging or `F5`, or `Ctrl+F5` for Start Without Debugging).

    The application will start logging activity. To stop it, press `ENTER` in the console window where the application is running.

## How it Works

The application operates with two main asynchronous tasks:

1.  **`StartActiveWindowTracking`**: Runs every second, fetches the foreground window's title and associated process, and logs it if it's different from the last logged active window.
2.  **`StartResourceMonitoring`**: Runs every 5 minutes, iterates through all active processes, gathers their memory, CPU, audio, and visibility metrics, and logs them. This task aggregates resource usage for processes with the same name.

### Core Logic

* **Win32 API Interop:** The application heavily relies on `P/Invoke` (Platform Invoke) to call various Win32 API functions from `user32.dll`, `gdi32.dll`, and `dwmapi.dll` for window information, visibility checks, and cloaked window detection.
* **Audio Monitoring:** `NAudio.CoreAudioApi` is used to enumerate audio sessions and determine which processes are actively producing sound above a certain volume and peak threshold.
* **Performance Counters:** Standard .NET `PerformanceCounter` objects are used to measure CPU usage per process.
* **Window Visibility:** The `IsWindowTrulyVisible` function attempts to determine if a window is genuinely visible to the user, considering factors like:
    * Being minimized (`IsIconic`).
    * Being off-screen or not intersecting with any display monitor.
    * Being completely obscured by other windows.
    * Being a "cloaked" window (often used by UWP apps or system processes).
    It achieves this by using GDI region operations (`CreateRectRgn`, `CombineRgn`, `GetRegionData`) to calculate the visible area of a window after subtracting overlapping windows.
* **Error Handling:** Includes `try-catch` blocks and retry logic for robust file writing.

## Contributing

Feel free to suggest improvements or report issues!