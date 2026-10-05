using System;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using CSOToolbox.Client.Lib;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private Action? _notificationDismissAction;

        private void DismissNotification()
        {
            if (_notificationTimer != null)
            {
                _notificationTimer.Stop();
                _notificationTimer = null;
            }
            if (_inAppToastNotification != null)
            {
                _inAppToastNotification.IsVisible = false;
            }
            if (_btnNotificationAction != null)
            {
                _btnNotificationAction.IsVisible = false;
            }
            _notificationDismissAction?.Invoke();
            _notificationDismissAction = null;
            _notificationHovered = false;
        }

        private void ScheduleDismiss(double seconds)
        {
            if (_notificationTimer != null)
            {
                _notificationTimer.Stop();
                _notificationTimer = null;
            }

            _notificationTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(seconds)
            };
            _notificationTimer.Tick += (s, e) =>
            {
                _notificationTimer?.Stop();
                _notificationTimer = null;

                if (_notificationHovered) return;
                _notificationDismissAction?.Invoke();
                _notificationDismissAction = null;
            };
            _notificationTimer.Start();
        }

        private void OnNotificationPointerEntered(object? sender, Avalonia.Input.PointerEventArgs e)
        {
            _notificationHovered = true;
            if (_notificationTimer != null)
            {
                _notificationTimer.Stop();
                _notificationTimer = null;
            }
        }

        private void OnNotificationPointerExited(object? sender, Avalonia.Input.PointerEventArgs e)
        {
            _notificationHovered = false;
            // Restart dismiss timer so user has time to click after unhovering
            var border = _inAppToastNotification;
            if (border != null && border.IsVisible)
                ScheduleDismiss(5.0);
        }

        private void Notify(string message, Action? dismissAction = null)
        {
            var border = _inAppToastNotification;
            var txt = _txtNotification;
            var btn = _btnNotificationAction;
            if (border != null && txt != null)
            {
                txt.Text = message;
                if (btn != null) btn.IsVisible = false;
                border.IsVisible = true;
                _notificationDismissAction = () =>
                {
                    border.IsVisible = false;
                    dismissAction?.Invoke();
                };
                ScheduleDismiss(5.0);
            }
        }

        private void TryOfferAnalysis(string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            var trimmed = text.Trim();
            if (trimmed == _currentText && IsReportActive()) return;

            var (extracted, _) = CsoStatelessIndicatorExtractor.TryExtractIndicator(trimmed);
            if (extracted == null) return;

            var display = extracted.Length > 40 ? extracted.Substring(0, 40) + "..." : extracted;
            NotifyWithAnalyzeAction($"'{display}' copied. Analyze it?", extracted);
        }

        private void NotifyWithAnalyzeAction(string message, string text)
        {
            _pendingAnalyzeText = text;
            _pendingHistorySource = null;
            _pendingHistoryText = null;

            var border = _inAppToastNotification;
            var txt = _txtNotification;
            var btn = _btnNotificationAction;
            if (border != null && txt != null && btn != null)
            {
                txt.Text = message;
                btn.Content = "Analyze";
                btn.IsVisible = true;
                border.IsVisible = true;
                var captured = text;
                _notificationDismissAction = () =>
                {
                    if (_pendingAnalyzeText == captured)
                    {
                        border.IsVisible = false;
                        btn.IsVisible = false;
                        _pendingAnalyzeText = null;
                    }
                };
                ScheduleDismiss(5.0);
            }
        }

        private void NotifyWithAction(string message, string source, string text, object? data)
        {
            _pendingHistorySource = source;
            _pendingHistoryText = text;
            _pendingHistoryData = data;
            _pendingAnalyzeText = null;

            var border = _inAppToastNotification;
            var txt = _txtNotification;
            var btn = _btnNotificationAction;
            if (border != null && txt != null && btn != null)
            {
                txt.Text = message;
                btn.IsVisible = true;
                border.IsVisible = true;
                var captured = text;
                _notificationDismissAction = () =>
                {
                    if (_pendingHistoryText == captured)
                    {
                        border.IsVisible = false;
                        btn.IsVisible = false;
                    }
                };
                ScheduleDismiss(5.0);
            }
        }

        private void NotifyWithButton(string message, string buttonText, Action callback, bool autoDismiss = true)
        {
            var border = _inAppToastNotification;
            var txt = _txtNotification;
            var btn = _btnNotificationAction;
            if (border == null || txt == null || btn == null) return;

            txt.Text = message;
            btn.Content = buttonText;
            btn.IsVisible = true;
            border.IsVisible = true;

            var clicked = false;
            void Handler(object? s, RoutedEventArgs args)
            {
                clicked = true;
                btn.Click -= Handler;
                border.IsVisible = false;
                btn.IsVisible = false;
                callback();
            }
            btn.Click += Handler;

            _notificationDismissAction = () =>
            {
                if (!clicked)
                {
                    btn.Click -= Handler;
                    border.IsVisible = false;
                    btn.IsVisible = false;
                }
            };
            if (autoDismiss)
                ScheduleDismiss(5.0);
        }

        private async void OnNotificationActionClick(object? sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(_pendingHistoryText) && !string.IsNullOrEmpty(_pendingHistorySource))
            {
                var searchBar = _txtSearchBar;
                if (searchBar != null) searchBar.Text = _pendingHistoryText;

                await RestoreHistoryEntry(_pendingHistorySource.ToLower(), _pendingHistoryText, _pendingHistoryData);

                _pendingHistorySource = null;
                _pendingHistoryText = null;
                _pendingHistoryData = null;

                if (_inAppToastNotification != null) _inAppToastNotification.IsVisible = false;
                if (_btnNotificationAction != null) _btnNotificationAction.IsVisible = false;
            }
            else if (!string.IsNullOrEmpty(_pendingAnalyzeText))
            {
                var text = _pendingAnalyzeText;
                _pendingAnalyzeText = null;
                await ProcessInput(CsoInputSource.User, text);

                if (_inAppToastNotification != null) _inAppToastNotification.IsVisible = false;
                if (_btnNotificationAction != null) _btnNotificationAction.IsVisible = false;
            }
        }
    }
}
