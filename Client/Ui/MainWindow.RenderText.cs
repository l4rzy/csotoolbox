using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using CSOToolbox.Client.Helpers;
using CSOToolbox.Client.Lib;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private void RenderTextReport(string source, string originalText, object data)
        {
            var panel = _panelText!;

            var layoutDns = _layoutDnsReport!;
            var layoutMac = _layoutMacReport!;
            var layoutTextReport = _layoutTextReport!;

            layoutDns.IsVisible = false;
            layoutMac.IsVisible = false;
            layoutTextReport.IsVisible = false;

            if (source == "mac")
            {
                panel.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
                layoutMac.IsVisible = true;

                var txtMac = _txtMacAddress!;
                var txtVendor = _txtMacVendor!;

                txtMac.Text = originalText;

                var vendor = data is MacVendorResult mac ? mac.Vendor : null;
                txtVendor.Text = !string.IsNullOrEmpty(vendor) ? vendor : "Unknown";
            }
            else if (data is OcrResult ocr)
            {
                panel.VerticalScrollBarVisibility = ScrollBarVisibility.Disabled;
                layoutTextReport.IsVisible = true;
                var txtContent = _txtTextContent!;
                txtContent.IsReadOnly = false;
                txtContent.Text = ocr.Text;
            }
            else if (data is ThreatFoxObject threatfox)
            {
                panel.VerticalScrollBarVisibility = ScrollBarVisibility.Disabled;
                layoutTextReport.IsVisible = true;
                var txtContent = _txtTextContent!;
                txtContent.IsReadOnly = true;
                txtContent.Text = string.Join("\n\n", threatfox.Results.Select(r =>
                    $"ID: {r.Id}\nIOC: {r.Ioc}\nType: {r.IocType ?? "-"}\nThreat: {r.ThreatType ?? "-"}\nMalware: {r.MalwarePrintable ?? r.Malware ?? "-"}\nConfidence: {r.ConfidenceLevel}\nFirst Seen: {r.FirstSeen ?? "-"}\nLast Seen: {r.LastSeen ?? "-"}\nTags: {(r.Tags != null ? string.Join(", ", r.Tags) : "-")}"
                ));
            }
            else if (data is string text)
            {
                panel.VerticalScrollBarVisibility = ScrollBarVisibility.Disabled;
                layoutTextReport.IsVisible = true;
                var txtContent = _txtTextContent!;
                txtContent.IsReadOnly = true;
                txtContent.Text = text;
            }
            else
            {
                ShowError($"Failed to perform '{source}' analysis on '{originalText}'.");
                return;
            }

            panel.IsVisible = true;
        }

    }
}
