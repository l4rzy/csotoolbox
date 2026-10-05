using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private void ScrollReportToTop()
        {
            _panelAbuseIPDB!.Offset = Vector.Zero;
            _panelVirusTotal!.Offset = Vector.Zero;
            _panelCVE!.Offset = Vector.Zero;
            _panelBazaar!.Offset = Vector.Zero;
            _panelWhois!.Offset = Vector.Zero;
            _panelScamalytics!.Offset = Vector.Zero;
            _panelRdap!.Offset = Vector.Zero;
            _panelText!.Offset = Vector.Zero;
            _panelSelection!.Offset = Vector.Zero;
        }

        private bool IsReportActive()
        {
            return (_panelAbuseIPDB?.IsVisible == true) ||
                   (_panelVirusTotal?.IsVisible == true) ||
                   (_panelCVE?.IsVisible == true) ||
                   (_panelBazaar?.IsVisible == true) ||
                   (_panelWhois?.IsVisible == true) ||
                   (_panelScamalytics?.IsVisible == true) ||
                   (_panelRdap?.IsVisible == true) ||
                   (_panelText?.IsVisible == true) ||
                   (_panelSelection?.IsVisible == true);
        }

        private void HideAllReportPanels(bool keepHeader = false)
        {
            _progressLoading!.IsIndeterminate = false;
            _progressLoading!.Value = 100;
            _panelLoading!.IsVisible = false;
            _panelWelcome!.IsVisible = false;
            _panelError!.IsVisible = false;
            if (!keepHeader)
            {
                _indicatorHeader!.IsVisible = false;
            }
            _panelAbuseIPDB!.IsVisible = false;
            _panelScamalytics!.IsVisible = false;
            _panelVirusTotal!.IsVisible = false;
            _panelCVE!.IsVisible = false;
            _panelBazaar!.IsVisible = false;
            _panelThreatFox!.IsVisible = false;
            _panelWhois!.IsVisible = false;
            _panelRdap!.IsVisible = false;
            _cardRdapContacts!.IsVisible = false;
            _gridRdapDomainDetails!.IsVisible = false;
            _panelText!.IsVisible = false;
            _panelSelection!.IsVisible = false;
        }

        private void ShowStatusBanner(string title, string details, string iconColor, string borderColor, string backgroundColor, bool keepHeader = true)
        {
            HideAllReportPanels(keepHeader);
            _errorBorder!.Background = Avalonia.Media.Brush.Parse(backgroundColor);
            _errorBorder!.BorderBrush = Avalonia.Media.Brush.Parse(borderColor);
            _errorIcon!.Foreground = Avalonia.Media.Brush.Parse(iconColor);
            _errorTitle!.Text = title;
            _errorTitle!.Foreground = Avalonia.Media.Brush.Parse(iconColor);
            _txtErrorDetails!.Text = details;
            _panelError!.IsVisible = true;
        }

        private void ShowError(string message, bool keepHeader = true)
        {
            ShowStatusBanner("Analysis Failed", message, "#ff5555", "#8b2525", "#2b1a1a", keepHeader);
        }

        private void ShowNotFoundError(string message, bool keepHeader = true)
        {
            ShowStatusBanner("Analysis Failed", message, "#4a9eff", "#4a9eff", "#0d2137", keepHeader);
        }

        private void ShowLoading(bool keepHeader = false)
        {
            HideAllReportPanels(keepHeader);
            _panelLoading!.VerticalAlignment = VerticalAlignment.Center;
            _progressLoading!.IsIndeterminate = true;
            _progressLoading!.Value = 0;

            _panelLoading!.IsVisible = true;
        }

        private void HideLoading()
        {
            _panelLoading!.IsVisible = false;
        }

        private void UpdateSearchBar(string text)
        {
            var searchBar = _txtSearchBar;
            if (searchBar != null)
            {
                searchBar.Text = text;
            }
        }
    }
}
