using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using CSOToolbox.Client.Lib;
using CSOToolbox.Client.ViewModels;
using Microsoft.Extensions.Logging;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private HistoryRowViewModel CreateHistoryRowViewModel(string source, string text, DateTime timestamp)
        {
            bool useUtc = _config.GetUseUtc();
            DateTime displayTime = useUtc ? timestamp : timestamp.ToLocalTime();
            string timeStr = displayTime.ToString("yyyy-MM-dd HH:mm:ss") + " " + (useUtc ? "UTC" : GetTimezoneAbbreviation());

            string displayData = text;
            if (displayData.Length > 100)
                displayData = displayData.Substring(0, 100).Replace("\n", " ") + "...";

            return new HistoryRowViewModel
            {
                TimeDisplay = timeStr,
                Source = source.ToUpper(),
                DataDisplay = displayData,
                OriginalData = text,
                SourceColor = GetSourceColor(source.ToUpper())
            };
        }

        private void AddHistoryRow(string source, string text, DateTime timestamp)
        {
            var newRow = CreateHistoryRowViewModel(source, text, timestamp);
            _historyViewModels.Insert(0, newRow);

            var historyLimit = _config.GetHistoryLimit();
            if (historyLimit > 0)
            {
                while (_historyViewModels.Count > historyLimit)
                {
                    _historyViewModels.RemoveAt(_historyViewModels.Count - 1);
                }
            }
        }

        private string GetSourceColor(string source)
        {
            if (string.IsNullOrEmpty(source)) return "#E0E0E0";
            return AnalyzerMap.SourceColors.TryGetValue(source.ToLower(), out var color) ? color : "#dcd1ff";
        }

        private async System.Threading.Tasks.Task RestoreHistoryEntry(string source, string text, object? data, string? jobId = null)
        {
            _logger.LogDebug("Restoring history entry: {Source} | {Text}", source, text);
            var useJobId = jobId;
            if (useJobId == null)
            {
                useJobId = NewJobId();
            }
            else
            {
                _currentCts?.Cancel();
                _currentCts?.Dispose();
                _currentCts = new CancellationTokenSource();
                lock (_pendingJobsLock)
                {
                    _pendingJobIds.Clear();
                    _pendingJobIds.Add(useJobId);
                }
            }

            var sl = source.ToLower();

            // ── Local results — render from cached data directly ──

            if (sl == "indicators")
            {
                var cachedList = (data as List<string>) ?? _cachedIndicatorList;
                if (cachedList != null)
                {
                    _indicatorExtractor.Process(CsoInputSource.User, text);
                    await Render("INDICATORS", useJobId, text, cachedList, false);
                }
                return;
            }

            if (sl == "base64" && data is string)
            {
                _indicatorExtractor.Process(CsoInputSource.User, text);
                await Render("base64", useJobId, text, data, false);
                return;
            }

            if (sl == "ocr" && data != null)
            {
                await Render("ocr", useJobId, text, data, false);
                return;
            }

            // ── Server-backed results — re-dispatch via worker ──

            var analyzerType = AnalyzerTypeParser.Parse(source);
            if (analyzerType == AnalyzerType.Unknown) return;

            _indicatorExtractor.Process(CsoInputSource.User, text);
            var reclassifiedType = _indicatorExtractor.GetPrimaryIndicatorType();
            var indicatorType = reclassifiedType;
            if (indicatorType == IndicatorType.Unknown ||
                !AnalyzerMap.AvailableAnalyzers.TryGetValue(indicatorType, out var available) ||
                !available.Contains(analyzerType))
            {
                indicatorType = GetIndicatorTypeForAnalyzer(analyzerType);
            }

            if (indicatorType != IndicatorType.Unknown && AnalyzerMap.AvailableAnalyzers.TryGetValue(indicatorType, out var dropdownAnalyzers))
            {
                var combo = _comboAnalyzers;
                if (combo != null)
                {
                    combo.SelectionChanged -= OnAnalyzerSelectionChanged;
                    var sortedAnalyzers = dropdownAnalyzers.OrderBy(a => AnalyzerMap.ToStringValue(a)).ToList();
                    combo.ItemsSource = sortedAnalyzers.Select(a =>
                    {
                        var name = AnalyzerMap.ToStringValue(a);
                        return new AnalyzerOption
                        {
                            Type = a,
                            Name = name.ToUpper(),
                            Icon = LoadServiceIcon(a),
                        };
                    }).ToList();
                    int activeIndex = sortedAnalyzers.IndexOf(analyzerType);
                    combo.SelectedIndex = activeIndex >= 0 ? activeIndex : 0;
                    combo.SelectionChanged += OnAnalyzerSelectionChanged;
                }
            }

            UpdateOpenWebButtonState(analyzerType);
            UpdateSearchBar(_indicatorExtractor.PrimaryIndicatorText);
            ShowLoading();
            _historyRestoreJobIds.Add(useJobId);
            EmitWorkerJob(useJobId, analyzerType, _indicatorExtractor.PrimaryIndicatorText, indicatorType: indicatorType);
        }

        private static IndicatorType GetIndicatorTypeForAnalyzer(AnalyzerType analyzerType)
        {
            if (AnalyzerMap.PrimaryIndicatorType.TryGetValue(analyzerType, out var type))
                return type;
            return IndicatorType.Unknown;
        }

        private async void OnHistoryListDoubleTapped(object? sender, RoutedEventArgs e)
        {
            var listbox = sender as ListBox;
            if (listbox?.SelectedItem is HistoryRowViewModel item)
            {
                var tabControl = _mainTabControl;
                if (tabControl != null) tabControl.SelectedIndex = 0; // Force switch to Report Tab

                // Use the structured data to render instantly instead of reprocessing
                var found = _history.FindEntry(item.OriginalData);
                await RestoreHistoryEntry(item.Source.ToLower(), item.OriginalData, found?.data);
            }
        }

        private void RefreshHistoryUI()
        {
            _historyViewModels.Clear();
            if (_txtHistoryFilter != null)
                _txtHistoryFilter.Text = "";
            var entries = _history.GetAllEntries();
            foreach (var entry in entries)
            {
                AddHistoryRow(entry.source.ToUpper(), entry.text, entry.timestamp);
            }
        }

        private void OnHistoryFilterTextChanged(object? sender, TextChangedEventArgs e)
        {
            _historyFilterTimer?.Stop();
            _historyFilterTimer ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
            _historyFilterTimer.Tick -= OnHistoryFilterTimerTick;
            _historyFilterTimer.Tick += OnHistoryFilterTimerTick;
            _historyFilterTimer.Start();
        }

        private void OnHistoryFilterTimerTick(object? sender, EventArgs e)
        {
            _historyFilterTimer?.Stop();
            ApplyHistoryFilter(_txtHistoryFilter?.Text ?? "");
        }

        private void OnClearHistoryFilterClick(object? sender, RoutedEventArgs e)
        {
            _historyFilterTimer?.Stop();
            if (_txtHistoryFilter != null)
                _txtHistoryFilter.Text = "";
            ApplyHistoryFilter("");
        }

        private void ApplyHistoryFilter(string filterText)
        {
            _historyViewModels.Clear();
            var entries = _history.GetAllEntries();
            foreach (var entry in entries)
            {
                if (string.IsNullOrEmpty(filterText) ||
                    entry.source.ToLower().Contains(filterText.ToLower()) ||
                    entry.text.ToLower().Contains(filterText.ToLower()))
                {
                    var newRow = CreateHistoryRowViewModel(entry.source, entry.text, entry.timestamp);
                    _historyViewModels.Insert(0, newRow);
                }
            }
        }

        private void RefreshReportUI()
        {
            if (_currentSource == "whois" && _currentData is WhoisObject whois)
            {
                RenderWhoisReport(whois);
            }
            else if (_currentSource == "abuseipdb" && _currentData is AbuseObject abuse)
            {
                RenderAbuseIpReport(abuse);
            }
            else if (_currentSource == "scamalytics" && _currentData is ScamalyticsObject scam)
            {
                RenderScamalyticsReport(scam);
            }
            else if (_currentSource == "bazaar" && _currentData is BazaarObject bazaar)
            {
                RenderBazaarReport(bazaar);
            }
            else if ((_currentSource == "cve" || _currentSource == "shodan") && _currentData is CommonCVEObject cve)
            {
                RenderCveReport(cve);
            }
            else if (_currentSource == "rdap" && _currentData is RdapResult rdap)
            {
                RenderRdapReport(rdap);
            }
            else if ((_currentSource == "dns" || _currentSource == "rdns") && _currentData is DnsObject dns)
            {
                RenderDnsReport(dns);
            }
            else if (_currentSource == "ocr" && _currentData is OcrResult ocr && _currentText != null)
            {
                RenderTextReport("ocr", _currentText, ocr);
            }
            else if (_currentSource == "mac" && _currentData is MacVendorResult mac && _currentText != null)
            {
                RenderTextReport("mac", _currentText, mac);
            }
            else if (_currentSource == "threatfox" && _currentData is ThreatFoxObject threatfox)
            {
                RenderThreatFoxReport(threatfox);
            }
        }
    }
}
