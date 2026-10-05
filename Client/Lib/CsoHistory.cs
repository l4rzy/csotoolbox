using System;
using System.Collections.Generic;

namespace CSOToolbox.Client.Lib
{
    public class CsoHistory
    {
        private readonly CsoConfig _config;
        private readonly List<(string source, string text, object? data, DateTime timestamp)> _list = new();
        private readonly Dictionary<string, (string source, string text, object? data, DateTime timestamp)> _allEntries = new(StringComparer.OrdinalIgnoreCase);
        private int _index = -1;

        public CsoHistory(CsoConfig config)
        {
            _config = config;
        }

        public void EnforceLimit()
        {
            int limit = _config.GetHistoryLimit();
            if (limit > 0 && _list.Count > limit)
            {
                int removeCount = _list.Count - limit;
                for (int i = 0; i < removeCount; i++)
                {
                    var oldEntry = _list[i];
                    if (_allEntries.TryGetValue(oldEntry.text.Trim(), out var currentEntry) && currentEntry.timestamp == oldEntry.timestamp)
                    {
                        _allEntries.Remove(oldEntry.text.Trim());
                    }
                }
                _list.RemoveRange(0, removeCount);
                _index = _list.Count - 1;
            }
        }

        public void Append(string source, string text, object? data, DateTime timestamp)
        {
            if (_index < _list.Count - 1)
            {
                _list.RemoveRange(_index + 1, _list.Count - (_index + 1));
            }
            var entry = (source, text, data, timestamp);
            _list.Add(entry);
            _index = _list.Count - 1;

            if (source.ToLower() != "indicators" && source.ToLower() != "ocr" && source.ToLower() != "switch")
            {
                _allEntries[text.Trim()] = entry;
            }

            EnforceLimit();
        }

        public (string source, string text, object? data, DateTime timestamp)? FindEntry(string text)
        {
            var target = text.Trim();
            if (_allEntries.TryGetValue(target, out var entry))
            {
                return entry;
            }
            foreach (var item in _list)
            {
                if (item.text.Trim().Equals(target, StringComparison.OrdinalIgnoreCase))
                {
                    return item;
                }
            }
            return null;
        }

        public List<(string source, string text, object? data, DateTime timestamp)> GetAllEntries()
        {
            return new List<(string source, string text, object? data, DateTime timestamp)>(_list);
        }
    }
}
