using System;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using CSOToolbox.Client.Lib;
using Microsoft.Extensions.Logging;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private void LoadPreferencesUI()
        {
            // Temporarily suppress change handlers so programmatic
            // IsChecked assignments don't overwrite config values.
            _isInitialized = false;

            _switchAnalyzeFocus!.IsChecked = _config.GetAnalyzeOnFocus();
            _switchMinimizeEscape!.IsChecked = _config.GetIconifyOnEscape();
            _switchUseUtc!.IsChecked = _config.GetUseUtc();
            _switchAutoUpdate!.IsChecked = _config.GetAutoUpdate();
            _switchKeepInTray!.IsChecked = _config.GetKeepInTray();
            _switchPassiveClipboard!.IsChecked = _config.GetPassiveClipboard();

            var txtBackendServer = _txtBackendServer!;
            var backendStr = _config.Get("general", "backend");
            txtBackendServer.Text = (backendStr == "false" || backendStr == null)
                ? ""
                : CsoConfig.CleanBackendUrl(backendStr);

            var txtHistoryLimit = _txtHistoryLimit!;
            txtHistoryLimit.Text = _config.GetHistoryLimit().ToString();

            var txtClipboardLimit = _txtClipboardLimit!;
            txtClipboardLimit.Text = _config.GetClipboardMaxLength().ToString();

            _txtBackendTimeout.Text = _config.GetBackendTimeout().ToString();

            var switchDataTab = _switchShowDataTab!;
            switchDataTab.IsChecked = _config.GetShowDataTab();
            ApplyDataTabVisibility(_config.GetShowDataTab());

            var switchLogTab = _switchShowLogTab!;
            switchLogTab.IsChecked = _config.GetShowLogTab();
            ApplyLogTabVisibility(_config.GetShowLogTab());

            var switchDisableSslPinning = _switchDisableSslPinning!;
            switchDisableSslPinning.IsChecked = _config.GetDisableSslPinning();
            AppConstants.SslPinningDisabled = _config.GetDisableSslPinning();

            PopulatePrefComboBox("ComboPrefDefaultIp", IndicatorType.Ip);
            PopulatePrefComboBox("ComboPrefDefaultInternalIp", IndicatorType.InternalIp);
            PopulatePrefComboBox("ComboPrefDefaultHash", IndicatorType.Hash);
            PopulatePrefComboBox("ComboPrefDefaultDomain", IndicatorType.Domain);
            PopulatePrefComboBox("ComboPrefDefaultUrl", IndicatorType.Url);
            PopulatePrefComboBox("ComboPrefDefaultMac", IndicatorType.Mac);
            PopulatePrefComboBox("ComboPrefDefaultCve", IndicatorType.Cve);
            PopulatePrefComboBox("ComboPrefDefaultBase64", IndicatorType.Base64);
            PopulatePrefComboBox("ComboPrefDefaultUser", IndicatorType.User);
            PopulatePrefComboBox("ComboPrefDefaultPComputer", IndicatorType.PComputer);
            PopulatePrefComboBox("ComboPrefDefaultEmail", IndicatorType.Email);
            PopulateConsoleLogLevelCombo();

            // Populate Footer Row with version and build date
            var version = Helpers.UpdateChecker.GetDisplayVersionString();
            var buildDate = "Unknown";
            try
            {
                if (DateTime.TryParse(BuildInfo.BuildDate, null, System.Globalization.DateTimeStyles.RoundtripKind, out var dt))
                {
                    bool useUtc = _config.GetUseUtc();
                    var displayDate = useUtc ? dt.ToUniversalTime() : dt.ToLocalTime();
                    string tz = useUtc ? "UTC" : GetTimezoneAbbreviation();
                    buildDate = displayDate.ToString("yyyy-MM-dd HH:mm:ss") + " " + tz;
                }
            }
            catch (System.Exception ex) { _logger.LogDebug(ex, "Failed to parse burnt build date"); }

            var txtVersion = _txtVersionInfo;
            if (txtVersion != null)
            {
                txtVersion.Text = $"Version: {version}";
            }

            var txtDotnet = _txtDotnetInfo;
            if (txtDotnet != null) txtDotnet.Text = $"Runtime: .NET {System.Environment.Version}";

            var txtBuild = _txtBuildDateInfo;
            if (txtBuild != null) txtBuild.Text = $"Build Date: {buildDate}";

            _isInitialized = true;
        }

        private void PopulatePrefComboBox(string comboName, IndicatorType type)
        {
            var combo = this.FindControl<ComboBox>(comboName);
            if (combo == null) return;
            combo.SelectionChanged -= OnPrefDefaultAnalyzerChanged;

            var available = AnalyzerMap.AvailableAnalyzers[type];
            var items = available.Select(a =>
            {
                var name = AnalyzerMap.ToStringValue(a);
                return new AnalyzerOption
                {
                    Type = a,
                    Name = name.ToUpper(),
                    Icon = LoadServiceIcon(a),
                };
            }).ToList();
            combo.ItemsSource = items;

            var currentDefault = _config.GetDefaultAnalyzer(type);
            int idx = available.IndexOf(currentDefault);
            combo.SelectedIndex = idx >= 0 ? idx : 0;

            combo.SelectionChanged += OnPrefDefaultAnalyzerChanged;
        }

        private void PopulateConsoleLogLevelCombo()
        {
            var combo = _comboConsoleLogLevel;
            if (combo == null) return;
            var levels = new[] { "OFF", "WARNING", "INFORMATION", "DEBUG" };
            combo.ItemsSource = levels;
            var current = _config?.GetConsoleLogLevel()?.ToUpper() ?? "OFF";
            combo.SelectedIndex = Math.Max(0, Array.IndexOf(levels, current));
            Lib.LogTabLogger._consoleLogLevel = current;
        }

        private void OnConsoleLogLevelChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (!_isInitialized || _config == null) return;
            if (_comboConsoleLogLevel?.SelectedItem is string level)
            {
                _config.SetConsoleLogLevel(level);
                Lib.LogTabLogger._consoleLogLevel = level;
                _config.Persist();
            }
        }

        private void OnPrefDefaultAnalyzerChanged(object? sender, SelectionChangedEventArgs e)
        {
            var combo = sender as ComboBox;
            if (combo == null || combo.SelectedItem == null) return;
            var option = combo.SelectedItem as AnalyzerOption;
            var analyzer = option?.Type ?? AnalyzerType.Unknown;
            if (analyzer == AnalyzerType.Unknown) return;

            var type = combo.Name switch
            {
                "ComboPrefDefaultIp" => IndicatorType.Ip,
                "ComboPrefDefaultInternalIp" => IndicatorType.InternalIp,
                "ComboPrefDefaultHash" => IndicatorType.Hash,
                "ComboPrefDefaultDomain" => IndicatorType.Domain,
                "ComboPrefDefaultUrl" => IndicatorType.Url,
                "ComboPrefDefaultMac" => IndicatorType.Mac,
                "ComboPrefDefaultCve" => IndicatorType.Cve,
                "ComboPrefDefaultBase64" => IndicatorType.Base64,
                "ComboPrefDefaultUser" => IndicatorType.User,
                "ComboPrefDefaultPComputer" => IndicatorType.PComputer,
                "ComboPrefDefaultEmail" => IndicatorType.Email,
                _ => IndicatorType.Unknown
            };

            if (type != IndicatorType.Unknown)
            {
                _config.SetDefaultAnalyzer(type, analyzer);
                _config.Persist();
            }
        }

        private void OnPrefBehaviorToggleChanged(object? sender, RoutedEventArgs e)
        {
            if (!_isInitialized || _config == null) return;

            if (sender is Avalonia.Controls.ToggleSwitch toggleSwitch && toggleSwitch.Name != null)
                _logger.LogDebug("Preference changed: {SettingName} = {Value}", toggleSwitch.Name, toggleSwitch.IsChecked);

            if (sender is Avalonia.Controls.ToggleSwitch ts && ts.Name != null)
            {
                switch (ts.Name)
                {
                    case "SwitchAnalyzeFocus":
                        _config.SetAnalyzeOnFocus(ts.IsChecked == true);
                        break;
                    case "SwitchMinimizeEscape":
                        _config.SetMinimizeEscape(ts.IsChecked == true);
                        break;
                    case "SwitchUseUtc":
                        _config.SetUseUtc(ts.IsChecked == true);
                        if (ts.IsChecked == false)
                            Notify($"Timezone set to {GetTimezoneAbbreviation()}");
                        RefreshHistoryUI();
                        RefreshReportUI();
                        break;
                    case "SwitchAutoUpdate":
                        _config.SetAutoUpdate(ts.IsChecked == true);
                        if (ts.IsChecked == true) StartAutoUpdateTimer();
                        else StopAutoUpdateTimer();
                        break;
                    case "SwitchKeepInTray":
                        _config.SetKeepInTray(ts.IsChecked == true);
                        if (ts.IsChecked == true && _trayIcon == null)
                            CreateTrayIcon();
                        else if (ts.IsChecked == false && _trayIcon != null)
                        {
                            _trayIcon.Dispose();
                            _trayIcon = null;
                        }
                        break;
                    case "SwitchPassiveClipboard":
                        _config.SetPassiveClipboard(ts.IsChecked == true);
                        if (ts.IsChecked == true)
                        {
                            if (!_isWindowFocused) StartBackgroundClipboardMonitor();
                        }
                        else
                        {
                            StopBackgroundClipboardMonitor();
                        }
                        break;
                }

                _config.Persist();
            }
        }

        private void OnPrefGeneralSaveClick(object? sender, RoutedEventArgs e)
        {
            if (_config == null) return;

            if (sender is Button btn)
            {
                switch (btn.Name)
                {
                    case "BtnSaveBackendUrl":
                        var url = _txtBackendServer!.Text?.Trim();
                        _config.SetBackendUrl(url);
                        _config.Persist();
                        Notify("Backend server URL updated successfully!");
                        break;

                    case "BtnSaveTimeout":
                        var timeoutInput = _txtBackendTimeout!.Text?.Trim();
                        if (int.TryParse(timeoutInput, out int seconds) && seconds >= 5)
                        {
                            _config.SetBackendTimeout(seconds);
                            _config.Persist();
                            _worker.SetTimeout(seconds);
                            Notify("Backend timeout updated successfully!");
                        }
                        else
                        {
                            Notify("Invalid value! Timeout must be >= 5 seconds.");
                            _txtBackendTimeout.Text = _config.GetBackendTimeout().ToString();
                        }
                        break;

                    case "BtnSaveHistoryLimit":
                        var historyInput = _txtHistoryLimit!.Text?.Trim();
                        if (int.TryParse(historyInput, out int limit) && (limit == 0 || limit >= 10))
                        {
                            _config.SetHistoryLimit(limit);
                            _config.Persist();
                            _history.EnforceLimit();
                            RefreshHistoryUI();
                            Notify("History limit updated successfully!");
                        }
                        else
                        {
                            Notify("Invalid value! History limit must be 0 (unlimited) or >= 10.");
                            _txtHistoryLimit.Text = _config.GetHistoryLimit().ToString();
                        }
                        break;

                    case "BtnSaveClipboardLimit":
                        var clipInput = _txtClipboardLimit!.Text?.Trim();
                        if (int.TryParse(clipInput, out int clipLimit) && clipLimit >= 1024)
                        {
                            _config.SetClipboardMaxLength(clipLimit);
                            _config.Persist();
                            Notify("Clipboard limit updated successfully!");
                        }
                        else
                        {
                            Notify("Invalid value! Clipboard limit must be >= 1024.");
                            _txtClipboardLimit.Text = _config.GetClipboardMaxLength().ToString();
                        }
                        break;
                }
            }
        }

        private void OnPrefAdvancedToggled(object? sender, RoutedEventArgs e)
        {
            if (!_isInitialized || _config == null) return;

            if (sender is Avalonia.Controls.ToggleSwitch ts && ts.Name != null)
            {
                switch (ts.Name)
                {
                    case "SwitchShowDataTab":
                        bool show = ts.IsChecked == true;
                        _config.SetShowDataTab(show);
                        ApplyDataTabVisibility(show);
                        break;
                    case "SwitchShowLogTab":
                        bool showLog = ts.IsChecked == true;
                        _config.SetShowLogTab(showLog);
                        ApplyLogTabVisibility(showLog);
                        break;
                    case "SwitchDisableSslPinning":
                        bool disabled = ts.IsChecked == true;
                        _config.SetDisableSslPinning(disabled);
                        AppConstants.SslPinningDisabled = disabled;
                        if (disabled)
                            _logger.LogInformation("SSL certificate pinning disabled");
                        else
                            _logger.LogInformation("SSL certificate pinning enabled (hash: {Hash})", AppConstants.SslCertificateHash);
                        break;
                }
                _config.Persist();
            }
        }

        private void ApplyDataTabVisibility(bool show)
        {
            var tabData = _tabHeaderData;
            if (tabData != null) tabData.IsVisible = show;

            if (show && _lastRawResponse != null)
                DisplayJsonDataTab(_lastRawResponse);
        }

        private void ApplyLogTabVisibility(bool show)
        {
            _isLogTabEnabled = show;
            var tabLog = _tabHeaderLog;
            if (tabLog != null) tabLog.IsVisible = show;

            var listLog = _listLog;

            if (show)
            {
                if (_logViewModels.Count == 0)
                {
                    AddLogRow("system", "Log enabled and started", LogLevel.Warning);
                }
            }
            else
            {
                _allLogs.Clear();
                _logViewModels.Clear();
            }
        }

        private void OnToggleExpandClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var tree = _treeJsonData;
            if (tree?.Items == null) return;

            _treeIsExpanded = !_treeIsExpanded;
            foreach (var item in tree.Items)
                if (item is TreeViewItem tvi)
                    Helpers.JsonTreeBuilder.SetTreeViewExpanded(tvi, _treeIsExpanded);

            SetExpandButtonState(_treeIsExpanded);
        }

        private void SetExpandButtonState(bool allExpanded)
        {
            _txtToggleExpand!.Text = allExpanded ? "Collapse All" : "Expand All";
            _iconToggleExpand!.Data = allExpanded
                ? Geometry.Parse("M17 11l-5-5-5 5 M17 17l-5-5-5 5")
                : Geometry.Parse("M7 13l5 5 5-5 M7 7l5 5 5-5");
        }
    }
}
