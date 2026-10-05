using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Threading;
using CSOToolbox.Client.Lib;
using CSOToolbox.Client.Helpers;
using CSOToolbox.Client.ViewModels;
using Microsoft.Extensions.Logging;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private async Task ProcessInput(CsoInputSource source, string text, IndicatorType? explicitIndicatorType = null)
        {
            _logger.LogInformation("ProcessInput: source={Source}, text='{Text}'", source, text);
            _indicatorExtractor.Process(source, text, explicitIndicatorType);
            if (_indicatorExtractor.WasProcessingSkipped)
            {
                Notify(_indicatorExtractor.StatusMessage);
                return;
            }

            var tabReport = _tabHeaderReport;
            bool isReportTabActive = tabReport != null && tabReport.IsSelected;
            var indicatorType = _indicatorExtractor.GetPrimaryIndicatorType();
            bool hasIndicators = indicatorType != IndicatorType.Unknown || _indicatorExtractor.TotalMatchCount > 0;

            if (source != CsoInputSource.SelectedIndicator && !string.IsNullOrEmpty(_indicatorExtractor.PrimaryIndicatorText) && _indicatorExtractor.PrimaryIndicatorText == _currentText)
            {
                var defaultAnalyzer = indicatorType != IndicatorType.Unknown
                    ? _config.GetDefaultAnalyzer(indicatorType) : AnalyzerType.Unknown;

                bool isDefault = true;
                if (defaultAnalyzer != AnalyzerType.Unknown && _comboAnalyzers?.SelectedItem is AnalyzerOption opt)
                {
                    isDefault = opt.Type == defaultAnalyzer || opt.Type == AnalyzerType.Unknown;
                }

                if (isDefault)
                {
                    if (isReportTabActive)
                    {
                        var display = _indicatorExtractor.PrimaryIndicatorText;
                        if (display.Length > 20)
                        {
                            display = display.Substring(0, 20) + "...";
                        }
                        _logger.LogDebug("Input already displayed, skipping: {Text}", _currentText);
                        Notify($"'{display}' is already being displayed.");
                        return;
                    }
                    else
                    {
                        var tabControl = _mainTabControl;
                        if (tabControl != null) tabControl.SelectedIndex = 0;
                        return;
                    }
                }
                // Non-default analyzer: proceed to BeginAnalysis for re-analysis
            }

            if (source == CsoInputSource.Clipboard)
            {
                if (!hasIndicators)
                {
                    _logger.LogDebug("Clipboard input contains no indicators: '{Text}'", text);
                    return;
                }
            }

            if (source == CsoInputSource.User)
            {
                if (!hasIndicators)
                {
                    Notify("There is nothing to analyze in the inputted text");
                    return;
                }
                else if (_mainTabControl != null && _mainTabControl.SelectedIndex != 0)
                {
                    _mainTabControl.SelectedIndex = 0;
                }
            }

            UpdateSearchBar(_indicatorExtractor.PrimaryIndicatorText);

            if (!_indicatorExtractor.HasComplexData())
            {
                await BeginAnalysis(indicatorType);
            }
            else
            {
                _logger.LogDebug("Complex input detected, showing selection UI ({Count} matches)", _indicatorExtractor.TotalMatchCount);
                var indicatorsJobId = NewJobId();
                var indicatorList = new List<string>();
                foreach (var list in _indicatorExtractor.MatchesByCategory.Values)
                {
                    foreach (var item in list)
                    {
                        if (!indicatorList.Contains(item))
                            indicatorList.Add(item);
                    }
                }
                await Render("INDICATORS", indicatorsJobId, _indicatorExtractor.RawInputText, indicatorList);
            }
        }

        private async Task BeginAnalysis(IndicatorType indicatorType)
        {
            ShowLoading();
            var jobId = NewJobId();

            if (indicatorType == IndicatorType.Unknown)
            {
                Notify("No indicators was found in the input");
                HideLoading();
                return;
            }

            var available = AnalyzerMap.AvailableAnalyzers[indicatorType];
            if (available.Count == 0)
            {
                Notify("No analyzer available");
                HideLoading();
                return;
            }

            _logger.LogDebug("Analysis started for '{Text}' ({IndicatorType})",
                _indicatorExtractor.PrimaryIndicatorText, indicatorType);

            // Populate the Dropdown
            var combo = _comboAnalyzers;
            if (combo != null)
            {
                combo.SelectionChanged -= OnAnalyzerSelectionChanged; // Prevent triggering
                try
                {
                    var sortedAvailable = available.OrderBy(a => AnalyzerMap.ToStringValue(a)).ToList();
                    var items = sortedAvailable.Select(a =>
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

                    // Pick default
                    var defaultAnalyzer = _config.GetDefaultAnalyzer(indicatorType);
                    if (defaultAnalyzer == AnalyzerType.Unknown || !available.Contains(defaultAnalyzer))
                        defaultAnalyzer = available[0];

                    int defaultIndex = sortedAvailable.IndexOf(defaultAnalyzer);
                    combo.SelectedIndex = defaultIndex;

                    UpdateOpenWebButtonState(defaultAnalyzer);

                    EmitWorkerJob(jobId, defaultAnalyzer, _indicatorExtractor.PrimaryIndicatorText, indicatorType: indicatorType);
                }
                finally
                {
                    combo.SelectionChanged += OnAnalyzerSelectionChanged; // Reattach
                }
            }
            await Task.CompletedTask;
        }

        private void EmitWorkerJob(string jobId, AnalyzerType analyzer, string text, bool force = false, IndicatorType indicatorType = IndicatorType.Unknown)
        {
            _workerStartTime = DateTime.UtcNow;
            _worker.Run(jobId, new[] { analyzer }, text, force: force, ct: _currentCts?.Token ?? CancellationToken.None, indicatorType: indicatorType);
        }

        private void DispatchOcr(string base64Image)
        {
            var ocrJobId = NewJobId();
            ShowLoading();
            EmitWorkerJob(ocrJobId, AnalyzerType.Ocr, base64Image, force: true);
        }

        private void OnWorkerJobCompleted(string jobId, string source, string originalText, object? data)
        {
            Dispatcher.UIThread.Post(async () =>
            {
                try
                {
                    await Render(source, jobId, originalText, data);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Render failed for job {JobId}", jobId);
                }
            });
        }

        private async Task Render(string source, string jobId, string originalText, object? data, bool recordHistory = true)
        {
            _logger.LogDebug("Data received from {Source}", source);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            HideLoading();

            var activeData = UnwrapV1Response(data);
            var navTargetTab = ConsumeNavTarget(jobId);
            if (IsJobExpired(jobId, source, recordHistory)) return;

            ShowBackgroundNotificationIfNeeded(activeData, originalText);
            UpdateStateAndHistory(source, originalText, activeData, data, jobId, recordHistory);
            _lastRawResponse = data;
            DisplayJsonDataTab(data);
            HideAllReportPanels();
            UpdateIndicatorHeader(source);

            if (TryHandleTunnelError(activeData, source, navTargetTab))
            {
                ScrollReportToTop();
                return;
            }

            var hasError = await ValidateAndRender(source, activeData, originalText);

            sw.Stop();

            var workerMs = (int)(DateTime.UtcNow - _workerStartTime).TotalMilliseconds;

            if (workerMs >= 0)
                _logger.LogDebug("Analysis completed for '{Text}' from {Source} in {Worker}ms (worker) + {Render}ms (render)", originalText, source, workerMs, sw.ElapsedMilliseconds);
            else
                _logger.LogDebug("Analysis completed for '{Text}' from {Source} in {Render}ms (render)", originalText, source, sw.ElapsedMilliseconds);

            SelectTargetTabOrNotify(navTargetTab, hasError, source, originalText);
            ScrollReportToTop();
        }

        private static object? UnwrapV1Response(object? data)
        {
            if (data is TunnelResponseV1 tr)
                return (object?)tr.Error ?? tr.Payload;
            return data;
        }

        private int? ConsumeNavTarget(string? jobId)
        {
            if (string.IsNullOrEmpty(jobId)) return null;
            lock (_pendingJobsLock)
            {
                if (_navJobTargetTabs.TryGetValue(jobId, out var tabIndex))
                {
                    _navJobTargetTabs.Remove(jobId);
                    return tabIndex;
                }
            }
            return null;
        }

        private bool IsJobExpired(string jobId, string source, bool recordHistory)
        {
            bool isActive;
            lock (_pendingJobsLock)
                isActive = _pendingJobIds.Contains(jobId);

            if (!isActive && source != "switch" && recordHistory)
            {
                _logger.LogDebug("Data dropped due to expiration");
                return true;
            }

            lock (_pendingJobsLock)
                _pendingJobIds.Remove(jobId);

            return false;
        }

        private void ShowBackgroundNotificationIfNeeded(object? activeData, string originalText)
        {
            if (_isWindowFocused) return;
            try
            {
                if (activeData is AbuseObject ao && ao.Data != null)
                {
                    NativeNotification.Show("AbuseIPDB Analysis", $"IP: {ao.Data.IpAddress}\nAbuse Confidence Score: {ao.Data.AbuseConfidenceScore}%");
                }
                else if (activeData is VirusTotalObject vto && vto.Data is { Count: > 0 } && vto.Data[0].Attributes?.LastAnalysisStats is { } stats)
                {
                    int total = stats.Malicious + stats.Harmless + stats.Suspicious + stats.Undetected;
                    NativeNotification.Show("VirusTotal Analysis", $"Target: {originalText}\nDetection Rate: {stats.Malicious} / {total}");
                }
                else if (activeData is CommonCVEObject cco)
                {
                    var cveId = cco.Id ?? originalText;
                    var cvss = cco.Cvss.HasValue ? cco.Cvss.Value.ToString("F1") : "N/A";
                    NativeNotification.Show("CVE Analysis", $"CVE: {cveId}\nCVSS Score: {cvss}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to show background native notification");
            }
        }

        private void UpdateStateAndHistory(string source, string originalText, object? activeData, object? data, string jobId, bool recordHistory)
        {
            if (recordHistory)
            {
                bool isRestore = false;
                lock (_pendingJobsLock)
                    isRestore = _historyRestoreJobIds.Remove(jobId);

                if (!isRestore)
                {
                    var now = DateTime.UtcNow;
                    _history.Append(source, originalText, data, now);
                    if (source == "INDICATORS" && activeData is List<string> indList)
                        _cachedIndicatorList = indList;
                    AddHistoryRow(source.ToUpper(), originalText, now);
                    UpdateNavButtons();
                }
            }

            _currentSource = source;
            _currentText = originalText;
            _currentData = activeData;

            RecordNavigation(source, originalText, data);
        }

        private object? _lastRawResponse;

        private void DisplayJsonDataTab(object? data)
        {
            if (!_config.GetShowDataTab()) return;
            var txtRawData = _txtRawData;
            var treeJsonData = _treeJsonData;
            if (txtRawData == null || treeJsonData == null) return;

            treeJsonData.Items.Clear();
            txtRawData.Text = "";
            txtRawData.IsVisible = false;
            treeJsonData.IsVisible = false;
            _dataFilterTimer?.Stop();
            if (_txtDataFilter != null) _txtDataFilter.Text = "";

            if (data == null)
            {
                txtRawData.Text = "No data payload returned.";
                txtRawData.IsVisible = true;
                return;
            }

            try
            {
                var jsonText = JsonSerializer.Serialize(data, data.GetType(), SourceGenerationContext.Default);

                if (data is not TunnelResponseV1 && !string.IsNullOrEmpty(jsonText))
                    jsonText = $"{{\"payload\":{jsonText},\"error\":null}}";

                _jsonDocument?.Dispose();
                _jsonDocument = JsonDocument.Parse(jsonText);
                var rootItems = JsonTreeBuilder.BuildJsonTree(_jsonDocument.RootElement, "root");
                treeJsonData.Items.Clear();
                foreach (var item in rootItems) treeJsonData.Items.Add(item);
                treeJsonData.IsVisible = true;
                _treeIsExpanded = false;
                SetExpandButtonState(false);
            }
            catch
            {
                txtRawData.Text = data.ToString();
                txtRawData.IsVisible = true;
            }
        }

        private void UpdateIndicatorHeader(string source)
        {
            var panelHeader = _indicatorHeader;
            var txtTarget = _txtIndicatorTarget;
            if (panelHeader == null || txtTarget == null) return;

            var sl = source.ToLower();
            string? text = null;
            bool showButtons = false;

            switch (sl)
            {
                case "ocr":
                    text = "Clipboard Image OCR";
                    break;
                case "base64":
                    text = "Base64 Decoded";
                    break;
                default:
                    if (sl != "switch" && sl != "indicators" && !string.IsNullOrEmpty(_currentText))
                    {
                        text = _currentText;
                        showButtons = true;
                    }
                    break;
            }

            if (text != null)
            {
                txtTarget.Text = text;
                panelHeader.IsVisible = true;
                if (_panelIndicatorButtons != null)
                    _panelIndicatorButtons.IsVisible = showButtons;
            }
        }

        private bool TryHandleTunnelError(object? activeData, string source, int? navTargetTab)
        {
            if (activeData is not TunnelError tunnelErr) return false;

            string errorMessage;
            if (tunnelErr.ServerHttpStatusCode == 0)
                errorMessage = "Server is not reachable";
            else if (tunnelErr.ServerHttpStatusCode == 200)
                errorMessage = tunnelErr.Message ?? $"server is working but {source} didn't respond";
            else
                errorMessage = string.IsNullOrEmpty(tunnelErr.Message) ? "Server encountered an issue" : tunnelErr.Message;

            if (tunnelErr.Type == "NotFoundError")
                ShowNotFoundError(errorMessage, keepHeader: true);
            else
                ShowError(errorMessage, keepHeader: true);

            if (_mainTabControl != null) _mainTabControl.SelectedIndex = navTargetTab ?? 0;
            return true;
        }

        private async Task<bool> ValidateAndRender(string source, object? activeData, string originalText)
        {
            var analyzer = AnalyzerTypeParser.Parse(source);
            if (analyzer == AnalyzerType.Unknown)
            {
                RenderSelectionReport(activeData!);
                return false;
            }

            switch (analyzer)
            {
                case AnalyzerType.AbuseIpDb:
                    if (activeData is AbuseObject a && a.Data != null)
                        { RenderAbuseIpReport(a); return false; }
                    break;
                case AnalyzerType.Scamalytics:
                    if (activeData is ScamalyticsObject s && s.Data != null)
                        { RenderScamalyticsReport(s); return false; }
                    break;
                case AnalyzerType.Bazaar:
                    if (activeData is BazaarObject b && !string.IsNullOrEmpty(b.Sha256))
                        { RenderBazaarReport(b); return false; }
                    break;
                case AnalyzerType.VirusTotal:
                    if (activeData is VirusTotalObject vt)
                        { await RenderVirusTotalReport(vt); return false; }
                    break;
                case AnalyzerType.Circl:
                case AnalyzerType.Shodan:
                    if (activeData is CommonCVEObject c && !string.IsNullOrEmpty(c.Id))
                        { RenderCveReport(c); return false; }
                    break;
                case AnalyzerType.Whois:
                    if (activeData is WhoisObject w && !string.IsNullOrEmpty(w.DomainName))
                        { RenderWhoisReport(w); return false; }
                    break;
                case AnalyzerType.Rdap:
                    if (activeData is RdapResult)
                        { RenderRdapReport((RdapResult)activeData); return false; }
                    break;
                case AnalyzerType.Dns:
                case AnalyzerType.Rdns:
                    if (activeData is DnsObject dns)
                        { RenderDnsReport(dns); return false; }
                    break;
                case AnalyzerType.Ocr:
                case AnalyzerType.Base64:
                case AnalyzerType.Mac:
                case AnalyzerType.NetUser:
                    if (activeData != null)
                        { RenderTextReport(source, originalText, activeData); return false; }
                    break;
                case AnalyzerType.ThreatFox:
                    if (activeData is ThreatFoxObject tf)
                        { RenderThreatFoxReport(tf); return false; }
                    break;
                default:
                    _logger.LogWarning("Unhandled analyzer: {Source}", source);
                    return true;
            }

            ShowError($"Failed to retrieve details for '{originalText}' from {AnalyzerMap.GetDisplayName(analyzer)}.", keepHeader: true);
            return true;
        }

        private void SelectTargetTabOrNotify(int? navTargetTab, bool isError, string source, string originalText)
        {
            var mainTabControl = _mainTabControl;
            if (mainTabControl == null) return;

            if (navTargetTab.HasValue)
            {
                mainTabControl.SelectedIndex = navTargetTab.Value;
            }
            else if (!isError && _isWindowFocused && mainTabControl.SelectedIndex > 1)
            {
                var sl = source.ToLower();
                if (sl != "switch")
                {
                    var display = originalText.Length > 40 ? originalText.Substring(0, 40) + "..." : originalText;
                    NotifyWithButton($"Analysis result for '{display}' is ready.", "View", () =>
                    {
                        if (_mainTabControl != null)
                            _mainTabControl.SelectedIndex = 0;
                    });
                }
                else
                {
                    mainTabControl.SelectedIndex = 0;
                }
            }
            else
            {
                mainTabControl.SelectedIndex = 0;
            }
        }

    }
}
