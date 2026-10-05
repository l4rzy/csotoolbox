using System;
using System.IO;
using Avalonia.Controls;
using CSOToolbox.Client.ViewModels;
using Microsoft.Extensions.Logging;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private string FormatDateTime(string? rawDate, bool showAge = false, bool isPast = true)
        {
            if (string.IsNullOrEmpty(rawDate)) return "N/A";

            bool useUtc = _config.GetUseUtc();

            if (DateTime.TryParse(rawDate, null, System.Globalization.DateTimeStyles.RoundtripKind, out var dt))
            {
                dt = dt.ToUniversalTime();
                var displayDate = useUtc ? dt : dt.ToLocalTime();
                string tz = useUtc ? "UTC" : GetTimezoneAbbreviation();
                var formatted = displayDate.ToString("yyyy-MM-dd HH:mm:ss") + " " + tz;

                if (showAge)
                {
                    var now = DateTime.UtcNow;
                    var diff = isPast ? now - dt : dt - now;
                    string ageStr;
                    if (diff.TotalSeconds < 0)
                    {
                        var absDiff = isPast ? dt - now : now - dt;
                        if (absDiff.TotalDays >= 365)
                            ageStr = $"expired {(int)(absDiff.TotalDays / 365)}y";
                        else if (absDiff.TotalDays >= 30)
                            ageStr = $"expired {(int)(absDiff.TotalDays / 30)}mo";
                        else
                            ageStr = $"expired {(int)absDiff.TotalDays}d";
                    }
                    else if (diff.TotalDays >= 365)
                        ageStr = $"{(int)(diff.TotalDays / 365)}y {(int)(diff.TotalDays % 365 / 30)}mo";
                    else if (diff.TotalDays >= 30)
                        ageStr = $"{(int)(diff.TotalDays / 30)}mo {(int)(diff.TotalDays % 30)}d";
                    else if (diff.TotalHours >= 1)
                        ageStr = $"{(int)diff.TotalHours}h {diff.Minutes}m";
                    else
                        ageStr = $"{(int)diff.TotalMinutes}m";

                    return $"{formatted} ({ageStr} {(isPast ? "ago" : "from now")})";
                }

                return formatted;
            }

            return rawDate;
        }

        private string GetTimezoneAbbreviation()
        {
            var zone = TimeZoneInfo.Local;
            var now = DateTime.Now;
            bool isDst = zone.IsDaylightSavingTime(now);
            var name = isDst ? zone.DaylightName : zone.StandardName;

            // Build abbreviation from capital letters only
            var abbr = string.Concat(Array.FindAll(name.ToCharArray(), c => char.IsUpper(c)));
            if (abbr.Length < 2)
                abbr = zone.GetUtcOffset(now) >= TimeSpan.Zero
                    ? $"UTC+{zone.GetUtcOffset(now).Hours}"
                    : $"UTC{zone.GetUtcOffset(now).Hours}";

            return abbr;
        }

        private static string GetCompartmentColor(string compartment, LogLevel level)
        {
            var levelColor = level switch
            {
                LogLevel.Error or LogLevel.Critical => "#ff5555",
                LogLevel.Warning => "#ffb86c",
                _ => null
            };
            if (levelColor != null) return levelColor;

            return compartment.ToLowerInvariant() switch
            {
                "system" => "#50fa7b",
                "ui" => "#8be9fd",
                "worker" => "#ffb86c",
                "switch" => "#bd93f9",
                "config" => "#f1fa8c",
                "state" => "#ff79c6",
                "dns" => "#ff79c6",
                _ => "#E0E0E0"
            };
        }

        private void AddLogRow(string compartment, string message, LogLevel level = LogLevel.Information)
        {
            if (!_isLogTabEnabled) return;
            if (level > LogLevel.Warning) return;

            bool useUtc = _config != null && _config.GetUseUtc();
            DateTime dt = useUtc ? DateTime.UtcNow : DateTime.Now;
            string timestamp = dt.ToString("HH:mm:ss.fff") + " " + (useUtc ? "UTC" : GetTimezoneAbbreviation());

            var newRow = new LogRowViewModel
            {
                TimeDisplay = timestamp,
                Compartment = compartment.ToUpperInvariant(),
                Message = message,
                CompartmentColor = GetCompartmentColor(compartment, level),
                Level = level
            };

            _allLogs.Insert(0, newRow);

            while (_allLogs.Count > 1000)
            {
                var removed = _allLogs[^1];
                _allLogs.RemoveAt(_allLogs.Count - 1);
                _logViewModels.Remove(removed);
            }

            var filterText = _txtLogFilter?.Text;
            if (!string.IsNullOrEmpty(filterText))
            {
                ApplyLogFilter(filterText);
            }
            else
            {
                _logViewModels.Insert(0, newRow);
            }
        }

        private void OpenBrowser(string url)
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to open URL in browser");
            }
        }

        private static string GetConfigPath()
        {
            if (File.Exists("config.json")) return "config.json";
            if (File.Exists("../config.json")) return "../config.json";

            string appBase = AppDomain.CurrentDomain.BaseDirectory;
            string path = Path.Combine(appBase, "config.json");
            if (File.Exists(path)) return path;

            path = Path.Combine(appBase, "../config.json");
            if (File.Exists(path)) return Path.GetFullPath(path);

            path = Path.Combine(appBase, "../../config.json");
            if (File.Exists(path)) return Path.GetFullPath(path);

            return "config.json";
        }

        private static string GetStatePath()
        {
            // Place state.data next to the config file
            string configPath = GetConfigPath();
            string? dir = Path.GetDirectoryName(configPath);
            if (string.IsNullOrEmpty(dir)) dir = ".";
            return Path.Combine(dir, "state.data");
        }

        private string FormatUnixTimestamp(long? seconds)
        {
            if (!seconds.HasValue || seconds.Value <= 0) return "N/A";
            try
            {
                var offset = DateTimeOffset.FromUnixTimeSeconds(seconds.Value);
                bool useUtc = _config.GetUseUtc();
                var displayDate = useUtc ? offset.UtcDateTime : offset.LocalDateTime;
                string tz = useUtc ? "UTC" : GetTimezoneAbbreviation();
                return displayDate.ToString("yyyy-MM-dd HH:mm:ss") + " " + tz;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to format Unix timestamp");
                return seconds.Value.ToString();
            }
        }
    }
}
