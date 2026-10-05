using System;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private void OnLogFilterTextChanged(object? sender, TextChangedEventArgs e)
        {
            _logFilterTimer?.Stop();
            _logFilterTimer ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
            _logFilterTimer.Tick -= OnLogFilterTimerTick; // Avoid subscribing multiple times
            _logFilterTimer.Tick += OnLogFilterTimerTick;
            _logFilterTimer.Start();
        }

        private void OnLogFilterTimerTick(object? sender, EventArgs e)
        {
            _logFilterTimer?.Stop();
            _logFilterTimer!.Tick -= OnLogFilterTimerTick;
            ApplyLogFilter(_txtLogFilter?.Text ?? "");
        }

        private void OnClearLogFilterClick(object? sender, RoutedEventArgs e)
        {
            _logFilterTimer?.Stop();
            if (_txtLogFilter != null)
                _txtLogFilter.Text = "";
            ApplyLogFilter("");
        }

        private void ApplyLogFilter(string filterText)
        {
            _logViewModels.Clear();
            foreach (var log in _allLogs)
            {
                if (string.IsNullOrEmpty(filterText) ||
                    log.Compartment.Contains(filterText, StringComparison.OrdinalIgnoreCase) ||
                    log.Message.Contains(filterText, StringComparison.OrdinalIgnoreCase))
                {
                    _logViewModels.Add(log);
                }
            }
        }
    }
}
