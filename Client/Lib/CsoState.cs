using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CSOToolbox.Client.Lib
{
    public class CsoState : IDisposable
    {
        private readonly string _stateFile;
        private readonly Dictionary<string, string> _data = new(StringComparer.OrdinalIgnoreCase);
        private readonly ILogger<CsoState> _logger;
        private readonly Timer _debounceTimer;
        private bool _isDirty = false;
        private bool _disposed = false;
        private readonly object _lock = new();

        public CsoState(string stateFile, ILogger<CsoState>? logger = null)
        {
            _stateFile = stateFile;
            _logger = logger ?? NullLogger<CsoState>.Instance;
            _debounceTimer = new Timer(SaveCallback, null, Timeout.Infinite, Timeout.Infinite);
            Load();
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            lock (_lock)
            {
                _debounceTimer.Dispose();
                if (_isDirty)
                {
                    _isDirty = false;
                    Save();
                }
            }
        }

        public int Width
        {
            get => GetInt("width", 640);
            set { _data["width"] = value.ToString(); ScheduleSave(); }
        }

        public int Height
        {
            get => GetInt("height", 800);
            set { _data["height"] = value.ToString(); ScheduleSave(); }
        }

        public int X
        {
            get => GetInt("x", 800);
            set { _data["x"] = value.ToString(); ScheduleSave(); }
        }

        public int Y
        {
            get => GetInt("y", 378);
            set { _data["y"] = value.ToString(); ScheduleSave(); }
        }

        public void SetGeometry(int x, int y, int width, int height)
        {
            lock (_lock)
            {
                _data["x"] = x.ToString();
                _data["y"] = y.ToString();
                _data["width"] = width.ToString();
                _data["height"] = height.ToString();
            }
            ScheduleSave();
        }

        private void ScheduleSave()
        {
            lock (_lock)
            {
                _isDirty = true;
            }
            _debounceTimer.Change(500, Timeout.Infinite);
        }

        private void SaveCallback(object? state)
        {
            lock (_lock)
            {
                if (!_isDirty) return;
                _isDirty = false;
                Save();
            }
        }

        private void Load()
        {
            if (!File.Exists(_stateFile))
            {
                _logger.LogDebug("State file not found at {Path}, using defaults", _stateFile);
                _data["width"] = "640";
                _data["height"] = "800";
                _data["x"] = "800";
                _data["y"] = "378";
                return;
            }

            try
            {
                foreach (var line in File.ReadAllLines(_stateFile))
                {
                    var trimmed = line.Trim();
                    if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith('#')) continue;
                    var eqIdx = trimmed.IndexOf('=');
                    if (eqIdx > 0)
                    {
                        var key = trimmed.Substring(0, eqIdx).Trim();
                        var val = trimmed.Substring(eqIdx + 1).Trim();
                        _data[key] = val;
                    }
                }
                _logger.LogInformation("Loaded window state from {Path}", _stateFile);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error reading state file");
            }
        }

        private void Save()
        {
            try
            {
                using var writer = new StreamWriter(_stateFile, false);
                writer.WriteLine("# Window state — auto-generated, do not edit");
                foreach (var kvp in _data)
                    writer.WriteLine($"{kvp.Key} = {kvp.Value}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error writing state file");
            }
        }

        private int GetInt(string key, int fallback)
            => _data.TryGetValue(key, out var val) && int.TryParse(val, out var result) ? result : fallback;
    }
}
