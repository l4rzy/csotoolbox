using System;
using System.Collections.Generic;
using System.IO;
using System.Diagnostics;

namespace CSOToolbox.Client.Helpers;

/// <summary>
/// Helper class for sending cross-platform native notifications.
/// Uses PowerShell with WinRT on Windows, and falls back to notify-send on Linux.
/// No external C# dependencies.
/// Uses conditional compilation.
/// </summary>
public static class NativeNotification
{
    private static string? _appIconPath;
    private static readonly Dictionary<string, Action> _callbacks = new();

    static NativeNotification()
    {
        Initialize("CSOToolbox");
    }

    /// <summary>
    /// Initializes the native notification helper.
    /// </summary>
    public static void Initialize(string appName, string? appIconPath = null)
    {
        _appIconPath = appIconPath;
#if WINDOWS_PLATFORM
        ShellLinkHelper.RegisterShortcutIfNeeded();
#endif
    }

    /// <summary>
    /// Executes a registered callback by ID.
    /// </summary>
    public static void ExecuteCallback(string id)
    {
        if (_callbacks.TryGetValue(id, out var callback))
        {
            try
            {
                callback();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[NativeNotification] Callback execution failed: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Shows a standard cross-platform native notification.
    /// </summary>
    public static void Show(
        string title,
        string message,
        TimeSpan? duration = null,
        string? imagePath = null,
        Action? onClick = null)
    {
#if WINDOWS_PLATFORM
        ShowWindowsNotification(title, message, duration, imagePath, onClick);
#elif LINUX_PLATFORM
        ShowLinuxNotification(title, message, duration, imagePath, onClick);
#endif
    }

#if WINDOWS_PLATFORM
    private static void ShowWindowsNotification(
        string title,
        string message,
        TimeSpan? duration,
        string? imagePath,
        Action? onClick)
    {
        try
        {
            var builder = new Microsoft.Toolkit.Uwp.Notifications.ToastContentBuilder()
                .AddText(title)
                .AddText(message);

            if (onClick != null)
            {
                var clickId = Guid.NewGuid().ToString("N");
                _callbacks[clickId] = onClick;
                builder.AddArgument("action", "click")
                       .AddArgument("id", clickId);
            }

            var displayImage = !string.IsNullOrEmpty(imagePath) ? imagePath : _appIconPath;
            if (!string.IsNullOrEmpty(displayImage) && File.Exists(displayImage))
            {
                var absPath = Path.GetFullPath(displayImage);
                builder.AddAppLogoOverride(new Uri(absPath), Microsoft.Toolkit.Uwp.Notifications.ToastGenericAppLogoCrop.Default);
            }

            var xml = builder.GetXml();
            var toast = new Windows.UI.Notifications.ToastNotification(xml);
            Windows.UI.Notifications.ToastNotificationManager.CreateToastNotifier("CSOToolbox").Show(toast);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[NativeNotification] Failed to show Windows notification: {ex.Message}");
        }
    }
#endif

#if LINUX_PLATFORM
    private static void ShowLinuxNotification(
        string title,
        string message,
        TimeSpan? duration,
        string? imagePath,
        Action? onClick)
    {
        try
        {
            var args = new List<string>();
            var displayImage = !string.IsNullOrEmpty(imagePath) ? imagePath : _appIconPath;
            if (!string.IsNullOrEmpty(displayImage) && File.Exists(displayImage))
            {
                args.Add("-i");
                args.Add(Path.GetFullPath(displayImage));
            }

            if (duration.HasValue)
            {
                args.Add("-t");
                args.Add(((int)duration.Value.TotalMilliseconds).ToString());
            }

            args.Add(title);
            args.Add(message);

            var processStartInfo = new ProcessStartInfo
            {
                FileName = "notify-send",
                Arguments = string.Join(" ", System.Linq.Enumerable.Select(args, EscapeShellArg)),
                UseShellExecute = false,
                CreateNoWindow = true
            };
            Process.Start(processStartInfo);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[NativeNotification] Failed to show Linux notification: {ex.Message}");
        }
    }

    private static string EscapeShellArg(string arg)
    {
        return "\"" + arg.Replace("\"", "\\\"") + "\"";
    }
#endif

    /// <summary>
    /// Removes/clears all delivered notifications from the Windows action center.
    /// </summary>
    public static void ClearAll()
    {
#if WINDOWS_PLATFORM
        try
        {
            Windows.UI.Notifications.ToastNotificationManager.History.Clear("CSOToolbox");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[NativeNotification] Failed to clear notifications: {ex.Message}");
        }
#endif
    }
}
