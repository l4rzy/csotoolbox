using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using CSOToolbox.Client.Helpers;
using CSOToolbox.Client.Lib;
using Microsoft.Extensions.Logging;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private async Task RenderVirusTotalReport(VirusTotalObject vt)
        {
            var panel = _panelVirusTotal!;
            panel.IsVisible = true;

            var txtDetections = _txtVtDetections!;
            var progressDetections = _progressVtDetections!;
            var txtSummary = _txtVtSummary!;
            var panelDetails = _panelVtDetails!;
            var cardHighlight = _cardVtHighlight!;
            var panelHighlight = _panelVtHighlight!;

            panelDetails.Children.Clear();
            panelHighlight.Children.Clear();
            cardHighlight.IsVisible = false;

            var item = vt.Data[0];
            var attr = item.Attributes;

            if (attr.LastAnalysisStats != null)
            {
                var stats = attr.LastAnalysisStats;
                int total = stats.Malicious + stats.Harmless + stats.Suspicious + stats.Undetected;
                txtDetections.Text = $"{stats.Malicious} / {total}";

                int scorePct = total == 0 ? 0 : (stats.Malicious * 100) / total;
                progressDetections.Value = scorePct;

                var scoreBrush = FormatHelpers.GetInterpolatedScoreBrush(scorePct);
                progressDetections.Foreground = scoreBrush;
                txtDetections.Foreground = scoreBrush;

                txtSummary.Text = $"Marked as malicious by {stats.Malicious} out of {total} security vendors.";
            }

            void AddVtDetailRow(string label, string value, bool showCopy = true)
            {
                AddRowToPanel(panelDetails, label, value, showCopy);
            }

            void AddVtHighlightRow(string label, string value, bool showCopy = true)
            {
                AddRowToPanel(panelHighlight, label, value, showCopy);
            }

            void AddRowToPanel(StackPanel panel, string label, string value, bool showCopy)
            {
                AddDetailRow(
                    panel: panel,
                    label: label,
                    value: value,
                    labelWidth: "160",
                    fontSize: 14,
                    showCopy: showCopy,
                    margin: new Thickness(0, 1),
                    foregroundColorHex: DraculaColors.ForegroundLight,
                    maxLines: 2,
                    skipIfEmpty: false
                );
            }

            string type = (item.Type ?? "").ToLowerInvariant();

            if (type == "ip_address")
            {
                AddVtDetailRow("Network", attr.Network ?? "N/A");
                AddVtDetailRow("ASN", attr.Asn?.ToString() ?? "N/A");
                AddVtDetailRow("AS Owner", attr.AsOwner ?? "N/A");

                cardHighlight.IsVisible = true;
                if (_cardVtHighlight.Child is StackPanel vtSp && vtSp.Children.Count > 0 && vtSp.Children[0] is TextBlock vtTitle)
                    vtTitle.Text = "Reputation";
                AddVtHighlightRow("Reputation Score", (attr.Reputation ?? 0).ToString(), showCopy: false);
            }
            else if (type == "domain")
            {
                AddVtDetailRow("Registrar", attr.Registrar ?? "N/A");

                AddVtDetailRow("Created Date", FormatUnixTimestamp(attr.CreationDate), showCopy: false);
                AddVtDetailRow("Expiration Date", FormatUnixTimestamp(attr.ExpirationDate), showCopy: false);

                cardHighlight.IsVisible = true;
                AddVtHighlightRow("Reputation Score", (attr.Reputation ?? 0).ToString(), showCopy: false);

                if (attr.Categories != null && attr.Categories.Count > 0)
                {
                    var cats = string.Join(", ", attr.Categories.Select(c => $"{c.Key}: {c.Value}").Take(3));
                    AddVtHighlightRow("Categories", cats, showCopy: false);
                }
                else
                {
                    AddVtHighlightRow("Categories", "None", showCopy: false);
                }
            }
            else if (type == "url")
            {
                AddVtDetailRow("URL", attr.Url ?? "N/A");
                AddVtDetailRow("Status Code", attr.LastHttpResponseCode?.ToString() ?? "N/A", showCopy: false);

                if (attr.LastHttpResponseContentLength.HasValue)
                {
                    AddVtDetailRow("Body Length", FormatHelpers.FormatBytes(attr.LastHttpResponseContentLength.Value), showCopy: false);
                }
                else
                {
                    AddVtDetailRow("Body Length", "N/A", showCopy: false);
                }

                AddVtDetailRow("Title", attr.Title ?? "N/A");

                string servingIp = "N/A";
                if (!string.IsNullOrEmpty(attr.Url))
                {
                    try
                    {
                        var uri = new Uri(attr.Url);
                        var host = uri.Host;
                        var addresses = await Dns.GetHostAddressesAsync(host);
                        if (addresses.Length > 0)
                        {
                            servingIp = addresses[0].ToString();
                        }
                    }
                    catch (Exception ex) { _logger.LogDebug(ex, "DNS lookup failed for URL host"); }
                }
                AddVtDetailRow("Serving IP Address", servingIp);
                AddVtDetailRow("Reputation Score", (attr.Reputation ?? 0).ToString(), showCopy: false);
            }
            else
            {
                AddVtDetailRow("Names", attr.Names != null && attr.Names.Count > 0 ? string.Join(", ", attr.Names.Take(3)) : "None");

                if (attr.Size.HasValue)
                {
                    AddVtDetailRow("File Size", FormatHelpers.FormatBytes(attr.Size.Value), showCopy: false);
                }
                else
                {
                    AddVtDetailRow("File Size", "N/A", showCopy: false);
                }

                AddVtDetailRow("Magic Type", attr.Magic ?? "N/A");

                if (attr.SignatureInfo != null)
                {
                    AddVtDetailRow("Signed Binary", $"Signed by {attr.SignatureInfo.Signers ?? "Unknown"} ({attr.SignatureInfo.Verified ?? "Unverified"})");
                }
                else
                {
                    AddVtDetailRow("Signed Binary", "No signature info");
                }

                AddVtDetailRow("Reputation Score", (attr.Reputation ?? 0).ToString());
            }
        }
    }
}
