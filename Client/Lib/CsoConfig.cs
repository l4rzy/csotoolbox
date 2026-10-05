using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CSOToolbox.Client.Lib
{
    public class CsoConfig
    {
        private readonly string _configFile;
        private Dictionary<string, Dictionary<string, string>> _configData = new();
        private readonly object _lock = new();
        private readonly ILogger<CsoConfig> _logger;
        private bool _dirty;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = true,
            TypeInfoResolver = CsoConfigJsonContext.Default,
        };

        private static readonly Dictionary<string, Dictionary<string, string>> DefaultConfig = new(StringComparer.OrdinalIgnoreCase)
        {
            ["general"] = new(StringComparer.OrdinalIgnoreCase)
            {
                ["backend"] = "https://localhost:5059",
                ["backend_timeout"] = "7",
                ["history_limit"] = "100",
                ["clipboard_max_length"] = "16384",
            },
            ["behavior"] = new(StringComparer.OrdinalIgnoreCase)
            {
                ["analyze_on_focus"] = "true",
                ["iconify_on_escape"] = "false",
                ["use_utc"] = "false",
                ["auto_update"] = "true",
                ["keep_in_tray"] = "true",
            },
            ["advanced"] = new(StringComparer.OrdinalIgnoreCase)
            {
                ["show_data_tab"] = "false",
                ["show_log_tab"] = "true",
                ["console_log_level"] = "off",
                ["disable_ssl_pinning"] = "false",
            },
            ["analyzers"] = new(StringComparer.OrdinalIgnoreCase)
            {
                ["default_ip"] = "abuseipdb",
                ["default_internalip"] = "rdns",
                ["default_hash"] = "virustotal",
                ["default_url"] = "virustotal",
                ["default_domain"] = "whois",
                ["default_mac"] = "mac",
                ["default_cve"] = "circl",
                ["default_base64"] = "base64",
                ["default_user"] = "netuser",
                ["default_pcomputer"] = "dns",
                ["default_email"] = "dns",
                ["default_hostport"] = "threatfox",
            },
        };

        public CsoConfig(string configFile = "config.json", ILogger<CsoConfig>? logger = null)
        {
            _configFile = configFile;
            _logger = logger ?? NullLogger<CsoConfig>.Instance;
            LoadDefaults();
            if (File.Exists(_configFile))
            {
                LoadFromFile();
                Migrate(NeedsBackendHttpsMigration());
            }
            else
            {
                _dirty = true;
                Persist();
            }
        }

        private void Migrate(bool resetBackendToDefault)
        {
            if (!resetBackendToDefault) return;

            _logger.LogInformation("Config migration: backend does not use HTTPS, resetting to default");
            Set("general", "backend", "https://localhost:5059");
            _dirty = true;
            Persist();
        }

        private void LoadDefaults()
        {
            _configData = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var (section, kvps) in DefaultConfig)
            {
                var sec = new Dictionary<string, string>(kvps, StringComparer.OrdinalIgnoreCase);
                _configData[section] = sec;
            }
        }

        private void LoadFromFile()
        {
            try
            {
                var content = File.ReadAllText(_configFile);
                var data = JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string>>>(content, JsonOptions);
                if (data == null) return;
                lock (_lock)
                {
                    foreach (var (section, kvps) in data)
                    {
                        if (!_configData.ContainsKey(section))
                            _configData[section] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        foreach (var (key, value) in kvps)
                            _configData[section][key] = value;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error reading config file");
            }
        }

        private bool NeedsBackendHttpsMigration()
        {
            var backend = Get("general", "backend");
            return !string.IsNullOrEmpty(backend)
                && !string.Equals(backend, "false", StringComparison.OrdinalIgnoreCase)
                && !backend.StartsWith("https", StringComparison.OrdinalIgnoreCase);
        }

        public string? Get(string section, string key)
        {
            lock (_lock)
            {
                if (_configData.TryGetValue(section, out var sec) && sec.TryGetValue(key, out var val))
                    return val;
                return null;
            }
        }

        public T? Get<T>(string section, string key) where T : struct
        {
            var raw = Get(section, key);
            if (raw == null) return null;
            if (typeof(T) == typeof(int) && int.TryParse(raw, out int i)) return (T)(object)i;
            if (typeof(T) == typeof(bool) && bool.TryParse(raw, out bool b)) return (T)(object)b;
            return null;
        }

        public void Set(string section, string key, string value)
        {
            lock (_lock)
            {
                if (!_configData.ContainsKey(section))
                    _configData[section] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                _configData[section][key] = value;
                _dirty = true;
            }
        }

        public void Set<T>(string section, string key, T value) where T : struct
        {
            Set(section, key, value switch
            {
                bool b => b ? "true" : "false",
                _ => value.ToString() ?? "",
            });
        }

        public void RemoveKey(string section, string key)
        {
            lock (_lock)
            {
                if (_configData.TryGetValue(section, out var sec) && sec.Remove(key))
                    _dirty = true;
            }
        }

        public string? GetTunnelString()
        {
            var val = Get("general", "backend");
            return string.Equals(val, "false", StringComparison.OrdinalIgnoreCase) ? null : val;
        }

        public int GetBackendTimeout()
        {
            var val = Get<int>("general", "backend_timeout");
            if (val.HasValue && val.Value >= 5) return val.Value;
            return 7;
        }

        public void SetBackendTimeout(int seconds) =>
            Set("general", "backend_timeout", seconds);

        public int GetClipboardMaxLength()
        {
            var val = Get<int>("general", "clipboard_max_length");
            if (val.HasValue && val.Value >= 1024) return val.Value;
            return 16384;
        }

        public void SetClipboardMaxLength(int limit) => Set("general", "clipboard_max_length", limit);

        public int GetHistoryLimit()
        {
            var val = Get<int>("general", "history_limit");
            if (val.HasValue && (val.Value == 0 || val.Value >= 10)) return val.Value;
            return 100;
        }

        public void SetHistoryLimit(int limit) => Set("general", "history_limit", limit);

        public bool GetIconifyOnEscape() => Get<bool>("behavior", "iconify_on_escape") ?? false;
        public bool GetAnalyzeOnFocus() => Get<bool>("behavior", "analyze_on_focus") ?? false;
        public bool GetShowDataTab() => Get<bool>("advanced", "show_data_tab") ?? false;
        public bool GetShowLogTab() => Get<bool>("advanced", "show_log_tab") ?? false;
        public bool GetUseUtc() => Get<bool>("behavior", "use_utc") ?? false;
        public bool GetAutoUpdate() => Get<bool>("behavior", "auto_update") ?? false;
        public bool GetKeepInTray() => Get<bool>("behavior", "keep_in_tray") ?? true;
        public bool GetPassiveClipboard() => Get<bool>("behavior", "passive_clipboard") ?? false;
        public bool GetDisableSslPinning() => Get<bool>("advanced", "disable_ssl_pinning") ?? false;

        public void SetUseUtc(bool value) => Set("behavior", "use_utc", value);
        public void SetAutoUpdate(bool value) => Set("behavior", "auto_update", value);
        public void SetAnalyzeOnFocus(bool value) => Set("behavior", "analyze_on_focus", value);
        public void SetMinimizeEscape(bool value) => Set("behavior", "iconify_on_escape", value);
        public void SetKeepInTray(bool value) => Set("behavior", "keep_in_tray", value);
        public void SetPassiveClipboard(bool value) => Set("behavior", "passive_clipboard", value);
        public void SetShowDataTab(bool value) => Set("advanced", "show_data_tab", value);
        public void SetShowLogTab(bool value) => Set("advanced", "show_log_tab", value);
        public void SetDisableSslPinning(bool value) => Set("advanced", "disable_ssl_pinning", value);
        public static string CleanBackendUrl(string url)
        {
            url = url.Trim();
            if (url.EndsWith("/tunnel", StringComparison.OrdinalIgnoreCase))
            {
                url = url.Substring(0, url.Length - 7).TrimEnd('/');
            }
            else if (url.EndsWith("/tunnel/", StringComparison.OrdinalIgnoreCase))
            {
                url = url.Substring(0, url.Length - 8).TrimEnd('/');
            }
            return url;
        }

        public void SetBackendUrl(string? url) => Set("general", "backend", string.IsNullOrEmpty(url) ? "false" : CleanBackendUrl(url));
        public string GetConsoleLogLevel() => Get("advanced", "console_log_level") ?? "off";
        public void SetConsoleLogLevel(string level) => Set("advanced", "console_log_level", level);

        public AnalyzerType GetDefaultAnalyzer(IndicatorType type)
        {
            var key = $"default_{type.ToString().ToLower()}";
            var val = Get("analyzers", key);
            if (!string.IsNullOrEmpty(val)) return AnalyzerTypeParser.Parse(val);
            if (AnalyzerMap.DefaultAnalyzers.TryGetValue(type, out var defaultAnalyzer)) return defaultAnalyzer;
            return AnalyzerType.Unknown;
        }

        public void SetDefaultAnalyzer(IndicatorType type, AnalyzerType analyzer)
            => Set("analyzers", $"default_{type.ToString().ToLower()}", AnalyzerMap.ToStringValue(analyzer));

        public void Persist()
        {
            if (!_dirty) return;
            try
            {
                lock (_lock)
                {
                    _dirty = false;
                    var json = JsonSerializer.Serialize(_configData, JsonOptions);
                    File.WriteAllText(_configFile, json);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Can not write config");
            }
        }
    }
}
