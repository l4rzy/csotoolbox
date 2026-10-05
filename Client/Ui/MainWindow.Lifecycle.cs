using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Threading;
using CSOToolbox.Client.Helpers;
using CSOToolbox.Client.Lib;
using Microsoft.Extensions.Logging;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private bool _isUpdating = false;
        private bool _showButtonPercentage = false;
        private int _currentDownloadPercentage = 0;

        private void OnWindowPositionChanged(object? sender, PixelPointEventArgs e)
        {
            if (!_isInitialized) return;
            _state.SetGeometry(e.Point.X, e.Point.Y, (int)this.Width, (int)this.Height);
        }

        private void OnWindowPropertyChanged(object? sender, AvaloniaPropertyChangedEventArgs e)
        {
            if (!_isInitialized) return;
            if (e.Property == WidthProperty || e.Property == HeightProperty)
            {
                _state.SetGeometry(this.Position.X, this.Position.Y, (int)this.Width, (int)this.Height);
            }
        }

        private async void OnWindowActivated(object? sender, EventArgs e)
        {
            _logger.LogInformation("Window activated");

            if (!_config.GetAnalyzeOnFocus())
                return;

            var now = DateTime.UtcNow;
            if ((now - _lastClipboardCheckTime).TotalSeconds < 1)
            {
                _logger.LogDebug("Window activated but clipboard check skipped (cooldown)");
                return;
            }
            _lastClipboardCheckTime = now;

            try
            {
                var tabControl = _mainTabControl;
                var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
                if (clipboard == null) return;

                // Check for image on the clipboard first
                var imageBytes = await GetClipboardImageBytesAsync(clipboard);
                if (imageBytes != null && imageBytes.Length > 0)
                {
                    string imageHash;
                    using (var sha256 = System.Security.Cryptography.SHA256.Create())
                    {
                        var hashBytes = sha256.ComputeHash(imageBytes);
                        imageHash = Convert.ToHexString(hashBytes);
                    }

                    if (imageHash == _lastClipboardImageHash)
                    {
                        _logger.LogDebug("Clipboard image already processed");
                        return;
                    }

                    _lastClipboardImageHash = imageHash;
                    if (tabControl != null) tabControl.SelectedIndex = 0;

                    _logger.LogDebug("Extracting text from clipboard image via OCR");
                    var base64Image = Convert.ToBase64String(imageBytes);
                    DispatchOcr(base64Image);
                    return;
                }

                var clipboardText = await clipboard.TryGetTextAsync();
                if (string.IsNullOrEmpty(clipboardText)) return;

                clipboardText = clipboardText.Trim();
                if (clipboardText == _lastCheckedClipboardText)
                {
                    return;
                }
                _lastCheckedClipboardText = clipboardText;

                var searchBar = _txtSearchBar;
                if (searchBar == null) return;

                if (clipboardText == searchBar.Text)
                {
                    _logger.LogDebug("Nothing or nothing new to analyze");
                    return;
                }

                var historyEntry = _history.FindEntry(clipboardText);
                if (historyEntry != null)
                {
                    var entry = historyEntry.Value;
                    var display = clipboardText;
                    if (display.Length > 20) display = display.Substring(0, 20) + "...";
                    NotifyWithAction($"Clipboard item '{display}' is in history.", entry.source, entry.text, entry.data);
                    return;
                }

                await ProcessInput(CsoInputSource.Clipboard, clipboardText);
            }
            catch (Exception ex)
            {
                HideLoading();
                _logger.LogError(ex, "Error reading clipboard");
            }
        }

        private async Task<byte[]?> GetClipboardImageBytesAsync(IClipboard clipboard)
        {
            try
            {
                var bitmap = await clipboard.TryGetBitmapAsync();
                if (bitmap == null) return null;

                using var ms = new MemoryStream();
                bitmap.Save(ms);
                return ms.ToArray();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to read clipboard image");
            }
            return null;
        }

        private async Task SetClipboardTextAsync(string? text)
        {
            if (text == null) return;
            var cb = TopLevel.GetTopLevel(this)?.Clipboard;
            if (cb != null)
            {
                _lastCheckedClipboardText = text.Trim();
                await cb.SetTextAsync(text);
            }
        }

        private void OnWindowKeyDown(object? sender, KeyEventArgs e)
        {
            if (e.Key == Key.Escape && _config.GetIconifyOnEscape())
            {
                this.WindowState = WindowState.Minimized;
            }
            else if (e.Key == Key.L && e.KeyModifiers == KeyModifiers.Control)
            {
                _txtSearchBar?.Focus();
                _txtSearchBar?.SelectAll();
            }
            else if (e.Key == Key.R && e.KeyModifiers == KeyModifiers.Control)
            {
                OnIndicatorRefreshClick(null, null!);
            }
            else if (e.Key == Key.F && e.KeyModifiers == KeyModifiers.Control)
            {
                var target = _mainTabControl?.SelectedIndex switch
                {
                    1 => _txtDataFilter,      // Data tab
                    2 => _txtHistoryFilter,   // History tab
                    3 => _txtLogFilter,       // Log tab
                    _ => null
                };
                if (target != null)
                {
                    target.Focus();
                    target.SelectAll();
                }
            }
        }

        private void StartAutoUpdateTimer()
        {
            if (_updateTimer == null)
            {
                _updateTimer = new DispatcherTimer { Interval = TimeSpan.FromHours(1) };
                _updateTimer.Tick += async (s, e) => await CheckForUpdatesAsync(silent: true);
            }
            _updateTimer.Start();
            _ = CheckForUpdatesAsync(silent: true);
        }

        private void StopAutoUpdateTimer() => _updateTimer?.Stop();

        private void UpdateCheckButtonText()
        {
            if (_btnCheckUpdates == null) return;
            if (_isUpdating)
            {
                _btnCheckUpdates.IsEnabled = false;
                if (_showButtonPercentage)
                {
                    _btnCheckUpdates.Content = $"Downloading {_currentDownloadPercentage}%";
                }
                else
                {
                    _btnCheckUpdates.Content = "Check for Updates";
                }
            }
            else
            {
                _btnCheckUpdates.IsEnabled = true;
                _btnCheckUpdates.Content = "Check for Updates";
            }
        }

        private async Task CheckForUpdatesAsync(bool silent = false)
        {
            _logger.LogDebug("Checking for updates (silent={Silent})", silent);

            if (_isUpdating)
            {
                if (!silent)
                {
                    Notify("An update is already in progress.");
                }
                return;
            }

            try
            {
                var backendUrl = _config.GetTunnelString();
                if (string.IsNullOrEmpty(backendUrl))
                {
                    if (!silent)
                    {
                        Dispatcher.UIThread.Post(() => Notify("Could not check for updates. Backend server URL is not configured."));
                    }
                    return;
                }

                var platform = UpdateChecker.GetCurrentPlatform();
                var currentVer = UpdateChecker.GetCurrentVersionString();
                var result = await UpdateChecker.CheckForUpdateAsync(backendUrl, platform, currentVer);

                Dispatcher.UIThread.Post(() =>
                {
                    if (result == null)
                    {
                        if (!silent)
                        {
                            Notify("Could not check for updates. Server not reachable");
                        }
                    }
                    else if (result.UpdateAvailable == true)
                    {
                        _logger.LogDebug("Update available: v{Version}", result.Version);
                        var capturedResult = result;
                        NotifyWithButton($"Update v{result.Version} available!", "Update",
                            async () => await DownloadAndApplyUpdate(backendUrl, platform, capturedResult), autoDismiss: false);
                    }
                    else if (!silent)
                    {
                        _logger.LogDebug("No updates available");
                        Notify("Your application is up-to-date.");
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to run update check");
                if (!silent)
                {
                    Dispatcher.UIThread.Post(() => Notify($"Could not check for updates. Error: {ex.Message}"));
                }
            }
        }

        private async Task DownloadAndApplyUpdate(string url, string platform, UpdateCheckResult info)
        {
            _isUpdating = true;
            _showButtonPercentage = false;
            _currentDownloadPercentage = 0;

            StopAutoUpdateTimer();
            UpdateCheckButtonText();

            double fileSizeMb = (double)info.Size / (1024 * 1024);
            _logger.LogDebug("Downloading update v{Version} ({Size:F1}MB)", info.Version, fileSizeMb);
            Notify($"Downloading {info.Version} - {fileSizeMb:F1}MB", dismissAction: () =>
            {
                _showButtonPercentage = true;
                UpdateCheckButtonText();
            });

            var progress = new Progress<int>(pct =>
            {
                Dispatcher.UIThread.Post(() =>
                {
                    _currentDownloadPercentage = pct;
                    UpdateCheckButtonText();
                });
            });

            var path = await UpdateChecker.DownloadUpdateAsync(url, platform,
                info.Filename ?? "csotoolbox-update", info.Size, progress);

            if (path == null)
            {
                _isUpdating = false;
                _showButtonPercentage = false;
                UpdateCheckButtonText();
                if (_config != null && _config.GetAutoUpdate())
                {
                    StartAutoUpdateTimer();
                }
                Notify("Update download failed");
                return;
            }

            if (!string.IsNullOrEmpty(info.Sha256) && !UpdateChecker.VerifyHash(path, info.Sha256))
            {
                _logger.LogWarning("Update hash mismatch for {File}, expected {ExpectedHash}", path, info.Sha256);
                _isUpdating = false;
                _showButtonPercentage = false;
                UpdateCheckButtonText();
                if (_config != null && _config.GetAutoUpdate())
                {
                    StartAutoUpdateTimer();
                }
                Notify("Update hash verification failed");
                return;
            }

            _logger.LogDebug("Applying update from {Path}", path);
            UpdateChecker.ApplyUpdateAndRestart(path);
        }

        private async void OnCheckUpdatesClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            _logger.LogDebug("Manual update check triggered");
            await CheckForUpdatesAsync(silent: false);
        }

        private void CreateTrayIcon()
        {
            if (_trayIcon != null) return;
            try
            {
                var bitmap = new Avalonia.Media.Imaging.Bitmap(Avalonia.Platform.AssetLoader.Open(new Uri("avares://Client/Resources/icon.png")));
                var icon = new WindowIcon(bitmap);

                var menu = new NativeMenu();
                var showItem = new NativeMenuItem("Show");
                showItem.Click += (s, e) =>
                {
                    this.Show();
                    this.WindowState = WindowState.Normal;
                    this.Activate();
                };
                menu.Items.Add(showItem);
                menu.Items.Add(new NativeMenuItemSeparator());
                var exitItem = new NativeMenuItem("Exit");
                exitItem.Click += (s, e) => Environment.Exit(0);
                menu.Items.Add(exitItem);

                _trayIcon = new TrayIcon
                {
                    Icon = icon,
                    ToolTipText = "CSO Toolbox",
                    Menu = menu
                };
                _trayIcon.Clicked += (s, e) =>
                {
                    this.Show();
                    this.WindowState = WindowState.Normal;
                    this.Activate();
                };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to create tray icon");
            }
        }

        private void StartBackgroundClipboardMonitor()
        {
            if (!_config.GetPassiveClipboard()) return;
            if (_clipboardMonitor != null) return;

            _logger.LogDebug("Starting background clipboard monitor");
            _clipboardMonitor = new ClipboardMonitor(async () =>
            {
                return await Dispatcher.UIThread.InvokeAsync(async () =>
                {
                    try
                    {
                        var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
                        return clipboard != null ? await clipboard.TryGetTextAsync() : null;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to read clipboard on UI thread");
                        return null;
                    }
                });
            });

            _clipboardMonitor.ClipboardTextChanged += OnBackgroundClipboardTextChanged;
            _clipboardMonitor.Start();
        }

        private void StopBackgroundClipboardMonitor()
        {
            if (_clipboardMonitor == null) return;

            _logger.LogDebug("Stopping background clipboard monitor");
            _clipboardMonitor.Stop();
            _clipboardMonitor.ClipboardTextChanged -= OnBackgroundClipboardTextChanged;
            _clipboardMonitor = null;

            // Cancel any pending debounced requests
            _debounceCts?.Cancel();
            _debounceCts?.Dispose();
            _debounceCts = null;
        }

        private void OnBackgroundClipboardTextChanged(object? sender, string text)
        {
            // Handle clipboard change processing on UI thread
            Dispatcher.UIThread.Post(async () =>
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(text)) return;
                    text = text.Trim();

                    // 1. Skip if already matches the last checked text
                    if (text == _lastCheckedClipboardText) return;

                    // 2. Skip if already in history
                    var entry = _history.FindEntry(text);
                    if (entry != null) return;

                    // 3. Cooldown check: enforce minimum rate limit (e.g. 5 seconds)
                    var now = DateTime.UtcNow;
                    var timeSinceLastApi = (now - _lastApiExecutionTime).TotalSeconds;
                    if (timeSinceLastApi < 5)
                    {
                        _logger.LogWarning("Clipboard change '{Text}' ignored due to cooldown rate limit (elapsed: {Elapsed:F1}s)", text, timeSinceLastApi);
                        return;
                    }

                    // 4. Debounce check: wait 500ms quiet period before triggering
                    _debounceCts?.Cancel();
                    _debounceCts?.Dispose();
                    _debounceCts = new CancellationTokenSource();
                    var token = _debounceCts.Token;

                    _logger.LogDebug("Debouncing analysis for clipboard input: '{Text}'", text);

                    try
                    {
                        await Task.Delay(500, token);
                    }
                    catch (OperationCanceledException)
                    {
                        _logger.LogDebug("Debounce canceled for clipboard input: '{Text}'", text);
                        return;
                    }

                    // Set last checked clipboard text
                    _lastCheckedClipboardText = text;
                    _lastApiExecutionTime = DateTime.UtcNow;

                    _logger.LogDebug("Triggering background analysis for clipboard input: '{Text}'", text);
                    await ProcessInput(CsoInputSource.Clipboard, text);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error processing background clipboard text change");
                }
            });
        }
    }
}
