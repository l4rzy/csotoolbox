using System;
using System.Collections.Generic;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using CSOToolbox.Client.Lib;
using Microsoft.Extensions.Logging;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private const int _NAVIGATION_HISTORY_LIMIT = 200;

        public struct NavHistoryEntry
        {
            public string Source { get; set; }
            public string Text { get; set; }
            public object? Data { get; set; }
        }

        private readonly List<NavHistoryEntry> _navHistoryList = new();
        private int _navHistoryIndex = -1;
        private bool _isNavigating = false;
        private readonly Dictionary<string, int> _navJobTargetTabs = new();

        private void UpdateNavButtons()
        {
            var canGoBack = _navHistoryIndex > 0;
            var canGoForward = _navHistoryList.Count > 0 && _navHistoryIndex < _navHistoryList.Count - 1;
            if (_btnNavLeft != null) _btnNavLeft.IsEnabled = canGoBack;
            if (_btnNavRight != null) _btnNavRight.IsEnabled = canGoForward;
        }

        private async void OnNavLeftClick(object? sender, RoutedEventArgs e)
        {
            if (_navHistoryIndex > 0)
            {
                _navHistoryIndex--;
                await NavigateHistoryEntry(_navHistoryList[_navHistoryIndex], "backward");
            }
            else
            {
                _logger.LogDebug("Nothing to go backward to");
            }
        }

        private async void OnNavRightClick(object? sender, RoutedEventArgs e)
        {
            if (_navHistoryIndex >= 0 && _navHistoryIndex < _navHistoryList.Count - 1)
            {
                _navHistoryIndex++;
                await NavigateHistoryEntry(_navHistoryList[_navHistoryIndex], "forward");
            }
            else
            {
                _logger.LogDebug("Nothing to go forward to");
            }
        }

        private async System.Threading.Tasks.Task NavigateHistoryEntry(NavHistoryEntry entry, string direction)
        {
            _logger.LogDebug("Navigated {Direction} to: {Source} | {Text}", direction, entry.Source, entry.Text);
            UpdateNavButtons();

            var targetTab = 0;
            var tabControl = _mainTabControl;
            if (tabControl != null)
            {
                var cur = tabControl.SelectedIndex;
                if (cur == 0 || cur == 1)
                {
                    targetTab = cur;
                }
            }

            var jobId = "nav_" + Guid.NewGuid().ToString("N");
            lock (_pendingJobsLock)
            {
                _navJobTargetTabs[jobId] = targetTab;
            }

            await Dispatcher.UIThread.InvokeAsync(async () =>
            {
                _isNavigating = true;
                try
                {
                    UpdateSearchBar(entry.Text);
                    await RestoreHistoryEntry(entry.Source, entry.Text, entry.Data, jobId);
                }
                finally
                {
                    _isNavigating = false;
                }
            });
        }

        private void RecordNavigation(string source, string text, object? data)
        {
            if (_isNavigating) return;

            if (string.Equals(source, "switch", StringComparison.OrdinalIgnoreCase)) return;

            if (_navHistoryIndex >= 0 && _navHistoryIndex < _navHistoryList.Count)
            {
                var current = _navHistoryList[_navHistoryIndex];
                if (string.Equals(current.Source, source, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(current.Text, text, StringComparison.OrdinalIgnoreCase))
                {
                    var updated = _navHistoryList[_navHistoryIndex];
                    updated.Data = data;
                    _navHistoryList[_navHistoryIndex] = updated;
                    return;
                }
            }

            _navHistoryList.Add(new NavHistoryEntry { Source = source, Text = text, Data = data });
            _navHistoryIndex = _navHistoryList.Count - 1;

            var limit = _NAVIGATION_HISTORY_LIMIT;
            if (limit > 0 && _navHistoryList.Count > limit)
            {
                var removeCount = _navHistoryList.Count - limit;
                _navHistoryList.RemoveRange(0, removeCount);
                _navHistoryIndex = Math.Max(0, _navHistoryIndex - removeCount);
            }

            UpdateNavButtons();
        }
    }
}
