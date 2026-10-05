using System;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using CSOToolbox.Client.Lib;
using Microsoft.Extensions.Logging;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private const string ImagePlaceholderText = "<Image From Clipboard>";

        private async Task ProcessClipboardImageOcrAsync()
        {
            _searchImagePasted = false;
            if (_txtSearchBar != null) _txtSearchBar.Text = "";

            var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
            if (clipboard == null) return;

            var imageBytes = await GetClipboardImageBytesAsync(clipboard);
            if (imageBytes == null || imageBytes.Length == 0) return;

            var base64Image = Convert.ToBase64String(imageBytes);
            DispatchOcr(base64Image);
        }

        private async void OnSearchClick(object? sender, RoutedEventArgs e)
        {
            if (_searchImagePasted)
            {
                await ProcessClipboardImageOcrAsync();
                return;
            }

            var searchBar = _txtSearchBar;
            if (searchBar != null)
            {
                await ProcessInput(CsoInputSource.User, searchBar.Text ?? "");
            }
        }

        private async void OnSearchBarKeyDown(object? sender, KeyEventArgs e)
        {
            // Block text input while image placeholder is active
            if (_searchImagePasted && e.Key != Key.Enter && e.Key != Key.Back)
            {
                e.Handled = true;
                return;
            }

            // Backspace clears the image placeholder entirely
            if (e.Key == Key.Back && _searchImagePasted)
            {
                _searchImagePasted = false;
                _txtSearchBar.Text = "";

                var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
                if (clipboard != null)
                {
                    var bytes = await GetClipboardImageBytesAsync(clipboard);
                    if (bytes != null && bytes.Length > 0)
                    {
                        using var sha256 = System.Security.Cryptography.SHA256.Create();
                        _lastClipboardImageHash = Convert.ToHexString(sha256.ComputeHash(bytes));
                    }
                }

                e.Handled = true;
                return;
            }

            if (e.Key == Key.Enter)
            {
                var searchBar = _txtSearchBar;
                if (searchBar == null) return;

                if (_searchImagePasted)
                {
                    e.Handled = true;
                    await ProcessClipboardImageOcrAsync();
                    return;
                }

                await ProcessInput(CsoInputSource.User, searchBar.Text ?? "");
            }
            else if (e.Key == Key.Up)
            {
                OnNavLeftClick(null, null!);
            }
            else if (e.Key == Key.Down)
            {
                OnNavRightClick(null, null!);
            }
        }

        private async void OnSearchBarPastingFromClipboard(object? sender, RoutedEventArgs e)
        {
            var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
            if (clipboard == null) return;

            var imageBytes = await GetClipboardImageBytesAsync(clipboard);
            if (imageBytes != null && imageBytes.Length > 0)
            {
                e.Handled = true;
                _searchImagePasted = true;
                _txtSearchBar.Text = ImagePlaceholderText;
                Avalonia.Threading.Dispatcher.UIThread.Post(() => _txtSearchBar.SelectAll());
            }
        }

        private void OnSearchBarTextChanged(object? sender, TextChangedEventArgs e)
        {
            if (!_searchImagePasted) return;

            if (string.IsNullOrEmpty(_txtSearchBar.Text))
            {
                _searchImagePasted = false;
                return;
            }

            if (_txtSearchBar.Text != ImagePlaceholderText)
            {
                _txtSearchBar.Text = ImagePlaceholderText;
                Avalonia.Threading.Dispatcher.UIThread.Post(() => _txtSearchBar.SelectAll());
            }
        }

        private void UpdateOpenWebButtonState(AnalyzerType analyzerType)
        {
            var btnWeb = _btnIndicatorWeb;
            if (btnWeb == null) return;

            bool isSupported = analyzerType == AnalyzerType.AbuseIpDb ||
                               analyzerType == AnalyzerType.VirusTotal ||
                               analyzerType == AnalyzerType.Circl ||
                               analyzerType == AnalyzerType.Shodan ||
                               analyzerType == AnalyzerType.Whois ||
                               analyzerType == AnalyzerType.Scamalytics ||
                               analyzerType == AnalyzerType.Rdap ||
                               analyzerType == AnalyzerType.Bazaar ||
                               analyzerType == AnalyzerType.ThreatFox;

            btnWeb.IsEnabled = isSupported;
        }

        private void OnAnalyzerSelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (!_isInitialized) return;

            var combo = sender as ComboBox;
            if (combo == null || combo.SelectedItem == null) return;
            var option = combo.SelectedItem as AnalyzerOption;
            if (option == null) return;

            var selectedAnalyzer = option.Type;
            if (selectedAnalyzer == AnalyzerType.Unknown) return;

            UpdateOpenWebButtonState(selectedAnalyzer);

            ShowLoading(keepHeader: true);
            EmitWorkerJob(NewJobId(), selectedAnalyzer, _currentText ?? _indicatorExtractor.PrimaryIndicatorText, indicatorType: _indicatorExtractor.GetPrimaryIndicatorType());
        }

        private async void OnIndicatorCopyClick(object? sender, RoutedEventArgs e)
            => await CopyAndNotify(_currentText ?? _indicatorExtractor.PrimaryIndicatorText);

        private void OnIndicatorWebClick(object? sender, RoutedEventArgs e)
        {
            var target = _currentText ?? _indicatorExtractor.PrimaryIndicatorText;
            var combo = _comboAnalyzers;
            if (combo == null || combo.SelectedItem == null) return;
            var option = combo.SelectedItem as AnalyzerOption;
            if (option == null) return;

            var analyzerType = option.Type;

            if (analyzerType == AnalyzerType.AbuseIpDb)
                OpenBrowser($"https://www.abuseipdb.com/check/{target}");
            else if (analyzerType == AnalyzerType.VirusTotal)
            {
                string type = _currentSource == "virustotal" && _currentData is VirusTotalObject vt && vt.Data.Count > 0 ? vt.Data[0].Type ?? "file" : "file";
                if (type == "ip_address") type = "ip-address";
                OpenBrowser($"https://www.virustotal.com/gui/{type}/{target}");
            }
            else if (analyzerType == AnalyzerType.Circl)
                OpenBrowser($"https://cve.circl.lu/cve/{target}");
            else if (analyzerType == AnalyzerType.Shodan)
                OpenBrowser($"https://cvedb.shodan.io/cve/{target}");
            else if (analyzerType == AnalyzerType.Whois)
                OpenBrowser($"https://whois.domaintools.com/{target}");
            else if (analyzerType == AnalyzerType.Scamalytics)
            {
                if (_currentData is ScamalyticsObject scam && scam.Data != null && !string.IsNullOrEmpty(scam.Data.Url))
                    OpenBrowser(scam.Data.Url);
            }
            else if (analyzerType == AnalyzerType.Rdap)
            {
                if (_currentData is RdapResult rdap && !string.IsNullOrEmpty(rdap.LdhName))
                    OpenBrowser($"https://client.rdap.org/?type=domain&object={rdap.LdhName}&follow-referral=1");
                else
                    OpenBrowser($"https://client.rdap.org/?type=ip&object={target}&follow-referral=1");
            }
            else if (analyzerType == AnalyzerType.Bazaar)
            {
                var sha256 = _currentData is BazaarObject bazaar ? bazaar.Sha256 : null;
                OpenBrowser($"https://bazaar.abuse.ch/sample/{sha256 ?? target}");
            }
            else if (analyzerType == AnalyzerType.ThreatFox)
            {
                var id = _currentData is ThreatFoxObject tf && tf.Results.Count > 0 ? tf.Results[0].Id : null;
                if (id != null)
                    OpenBrowser($"https://threatfox.abuse.ch/ioc/{id}");
            }
        }

        private void OnIndicatorRefreshClick(object? sender, RoutedEventArgs e)
        {
            var combo = _comboAnalyzers;
            if (combo == null || combo.SelectedItem == null) return;
            var option = combo.SelectedItem as AnalyzerOption;
            if (option == null) return;

            var selectedAnalyzer = option.Type;
            if (selectedAnalyzer == AnalyzerType.Unknown) return;

            ShowLoading(keepHeader: true);
            EmitWorkerJob(NewJobId(), selectedAnalyzer, _currentText ?? _indicatorExtractor.PrimaryIndicatorText, force: true, indicatorType: _indicatorExtractor.GetPrimaryIndicatorType());
        }

        private async Task CopyAndNotify(string text, string? label = null, bool offerAnalysis = true)
        {
            if (string.IsNullOrEmpty(text)) return;
            await SetClipboardTextAsync(text);
            Notify(label != null ? $"{label} copied" : "Copied to clipboard");
            if (offerAnalysis) TryOfferAnalysis(text);
        }

        private async void OnRawAnalyzeClick(object? sender, RoutedEventArgs e)
        {
            if (_txtTextContent != null && !string.IsNullOrEmpty(_txtTextContent.Text))
                await ProcessInput(CsoInputSource.User, _txtTextContent.Text);
        }

        private async void OnRawCopyClick(object? sender, RoutedEventArgs e)
            => await CopyAndNotify(_txtTextContent?.Text ?? "", "Content");

        private async void OnCveIdCopyClick(object? sender, RoutedEventArgs e)
            => await CopyAndNotify(_txtCveId?.Text ?? "", "CVE ID");

        private async void OnAbuseIspCopyClick(object? sender, RoutedEventArgs e)
            => await CopyAndNotify(_txtAbuseIsp?.Text ?? "", "ISP");

        private async void OnAbuseUsageCopyClick(object? sender, RoutedEventArgs e)
            => await CopyAndNotify(_txtAbuseUsage?.Text ?? "", "Usage type");

        private async void OnAbuseDomainCopyClick(object? sender, RoutedEventArgs e)
            => await CopyAndNotify(_txtAbuseDomain?.Text ?? "", "Domain");

        private async void OnAbuseCountryCopyClick(object? sender, RoutedEventArgs e)
            => await CopyAndNotify(_txtAbuseCountry?.Text ?? "", "Country");

        private async void OnDnsHostCopyClick(object? sender, RoutedEventArgs e)
            => await CopyAndNotify(_txtDnsHost?.Text ?? "", "Host");

        private async void OnMacAddressCopyClick(object? sender, RoutedEventArgs e)
            => await CopyAndNotify(_txtMacAddress?.Text ?? "", "MAC address");

        private async void OnMacVendorCopyClick(object? sender, RoutedEventArgs e)
            => await CopyAndNotify(_txtMacVendor?.Text ?? "", "Vendor");

        private void OnScamalyticsOpenMapsClick(object? sender, RoutedEventArgs e)
        {
            var loc = _txtScamalyticsLocation?.Text ?? "";
            if (loc == "..." || loc == "N/A") return;
            var parts = loc.Split(',');
            if (parts.Length == 2 && double.TryParse(parts[0].Trim(), out var lat) && double.TryParse(parts[1].Trim(), out var lng))
                OpenBrowser($"https://www.google.com/maps/@{lat},{lng},12z");
        }

        private void OnAboutClick(object? sender, RoutedEventArgs e)
        {
            _logger.LogDebug("About dialog opened");
            var btnClose = new Button
            {
                Content = "Close",
                Width = 90,
                Height = 36,
                CornerRadius = new Avalonia.CornerRadius(4),
                Background = Avalonia.Media.Brush.Parse("#2b2b2b"),
                BorderBrush = Avalonia.Media.Brush.Parse("#3d3d3d"),
                HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center,
                VerticalContentAlignment = Avalonia.Layout.VerticalAlignment.Center,
                HorizontalContentAlignment = Avalonia.Layout.HorizontalAlignment.Center,
                Padding = new Avalonia.Thickness(6, 2)
            };

            var aboutDialog = new Window
            {
                Title = "About",
                Icon = this.Icon,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Width = 360,
                Height = 300,
                Background = Avalonia.Media.Brush.Parse("#121212"),
                Foreground = Avalonia.Media.Brushes.White,
                CanResize = false
            };

            var cts = new System.Threading.CancellationTokenSource();

            btnClose.Click += (s, args) =>
            {
                cts.Cancel();
                aboutDialog.Close();
            };

            Image? iconImage = null;
            try
            {
                iconImage = new Image
                {
                    Source = new Avalonia.Media.Imaging.Bitmap(Avalonia.Platform.AssetLoader.Open(new Uri("avares://Client/Resources/icon.png"))),
                    Width = 64,
                    Height = 64,
                    HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center
                };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load app icon");
            }

            string? backendUrl = _config.GetTunnelString();

            var serverStatusText = new TextBlock
            {
                Text = "Server Status: checking...",
                FontSize = 11,
                Foreground = Avalonia.Media.Brush.Parse("#888888"),
                HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center
            };

            var dialogContent = new StackPanel
            {
                Spacing = 12,
                Margin = new Avalonia.Thickness(20),
            };
            if (iconImage != null)
                dialogContent.Children.Add(iconImage);
            var ver = Helpers.UpdateChecker.GetDisplayVersionString();
            var versionText = $"CSO Toolbox v{ver}";
            dialogContent.Children.Add(new TextBlock { Text = versionText, FontSize = 18, FontWeight = Avalonia.Media.FontWeight.Bold, HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center });
            dialogContent.Children.Add(new TextBlock { Text = "A modern, cross-platform SOC workflow automation tool.", FontSize = 12, TextWrapping = Avalonia.Media.TextWrapping.Wrap, HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center });
            dialogContent.Children.Add(new TextBlock { Text = "License: GPL-3.0-or-later", FontSize = 12, HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center });
            dialogContent.Children.Add(new TextBlock { Text = $"Running on .NET Runtime {Environment.Version}", FontSize = 11, Foreground = Avalonia.Media.Brush.Parse("#888888"), HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Center });
            dialogContent.Children.Add(serverStatusText);
            dialogContent.Children.Add(btnClose);
            aboutDialog.Content = dialogContent;

            if (!string.IsNullOrEmpty(backendUrl))
            {
                aboutDialog.Closed += (_, _) =>
                {
                    cts.Cancel();
                    _lastClipboardCheckTime = DateTime.UtcNow;
                    this.IsEnabled = true;
                };

                _ = UpdateServerStatusAsync();

                async Task UpdateServerStatusAsync()
                {
                    try
                    {
                        var healthObj = await _worker.CheckServerHealth(cts.Token);
                        if (cts.IsCancellationRequested) return;

                        if (healthObj.IsOperational)
                        {
                            serverStatusText.Text = $"Server Status: {healthObj.Health}, version {healthObj.Version}";
                            serverStatusText.Foreground = Avalonia.Media.Brush.Parse("#50fa7b");
                        }
                        else
                        {
                            serverStatusText.Text = "Server Status: offline";
                            serverStatusText.Foreground = Avalonia.Media.Brush.Parse("#ffb86c");
                        }
                    }
                    catch (OperationCanceledException) { }
                    catch
                    {
                        if (!cts.IsCancellationRequested)
                        {
                            serverStatusText.Text = "Server Status: offline";
                            serverStatusText.Foreground = Avalonia.Media.Brush.Parse("#ff5555");
                        }
                    }
                }
            }
            else
            {
                serverStatusText.Text = "Server Status: not configured";
            }

            aboutDialog.Show(this);
            this.IsEnabled = false;
        }
    }
}
