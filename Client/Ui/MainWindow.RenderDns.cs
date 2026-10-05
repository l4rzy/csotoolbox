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
        private void RenderDnsReport(DnsObject dns)
        {
            var panel = _panelText!;

            panel.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;

            var layoutDns = _layoutDnsReport!;
            layoutDns.IsVisible = true;
            _layoutTextReport!.IsVisible = false;
            _layoutMacReport!.IsVisible = false;

            var txtHost = _txtDnsHost!;
            var txtType = _txtDnsType!;

            txtHost.Text = dns.Host;
            txtType.Text = dns.Nameservers is { Count: > 0 } ? string.Join(", ", dns.Nameservers) : "N/A";

            if (_txtDnsReportTitle != null)
                _txtDnsReportTitle.Text = dns.Reverse ? "RDNS Query Details" : "DNS Query Details";

            var cardPrimary = _cardDnsPrimary!;
            var cardCname = _cardDnsCname!;
            var cardMail = _cardDnsMail!;
            var cardNs = _cardDnsNs!;
            var cardSoa = _cardDnsSoa!;

            var panelPrimary = _panelDnsIpsList!;
            var panelCname = _panelDnsCnameList!;
            var panelMail = _panelDnsMailList!;
            var panelNs = _panelDnsNsList!;
            var panelSoa = _panelDnsSoaList!;

            panelPrimary.Children.Clear();
            panelCname.Children.Clear();
            panelMail.Children.Clear();
            panelNs.Children.Clear();
            panelSoa.Children.Clear();

            cardPrimary.IsVisible = false;
            cardCname.IsVisible = false;
            cardMail.IsVisible = false;
            cardNs.IsVisible = false;
            cardSoa.IsVisible = false;

            var txtIpsTitle = _txtDnsIpsTitle!;
            txtIpsTitle.Text = dns.Reverse ? "Resolved Hostname (PTR)" : "IP Addresses (A / AAAA)";

            var cardIpdb = _cardIpdb!;
            cardIpdb.IsVisible = false;

            bool hasPtr = false;

            if (dns.IsResolvable && dns.Records != null && dns.Records.Count > 0)
            {
                foreach (var record in dns.Records)
                {
                    var type = record.Type.ToUpper();
                    var value = record.Value;

                    if (type == "PTR")
                    {
                        hasPtr = true;
                        cardPrimary.IsVisible = true;
                        AddDnsRow(panelPrimary, "PTR", value);
                    }
                    else if (type == "A" || type == "AAAA")
                    {
                        cardPrimary.IsVisible = true;
                        AddDnsRow(panelPrimary, type, value);
                    }
                    else if (type == "CNAME")
                    {
                        cardCname.IsVisible = true;
                        AddDnsRow(panelCname, "CNAME", value);
                    }
                    else if (type == "MX")
                    {
                        cardMail.IsVisible = true;
                        AddDnsRow(panelMail, "MX", value, wrapText: true);
                    }
                    else if (type == "NS")
                    {
                        cardNs.IsVisible = true;
                        AddDnsRow(panelNs, "NS", value);
                    }
                    else if (type == "SOA")
                    {
                        cardSoa.IsVisible = true;
                        AddDnsRow(panelSoa, "SOA", value, wrapText: true);
                    }
                    else if (type == "TXT")
                    {
                        var cleanVal = value;
                        if (cleanVal.StartsWith('"') && cleanVal.EndsWith('"') && cleanVal.Length >= 2)
                        {
                            cleanVal = cleanVal.Substring(1, cleanVal.Length - 2);
                        }

                        if (cleanVal.StartsWith("v=spf1", System.StringComparison.OrdinalIgnoreCase))
                        {
                            cardMail.IsVisible = true;
                            AddDnsRow(panelMail, "SPF", cleanVal, wrapText: true);
                        }
                        else if (cleanVal.StartsWith("v=DMARC1", System.StringComparison.OrdinalIgnoreCase))
                        {
                            cardMail.IsVisible = true;
                            AddDnsRow(panelMail, "DMARC", cleanVal, wrapText: true);
                        }
                    }
                }
            }

            if (dns.Reverse && !hasPtr)
            {
                cardPrimary.IsVisible = true;
                AddDnsRow(panelPrimary, "PTR", "N/A");
            }

            if (dns.Ipdb is { Found: true })
            {
                cardIpdb.IsVisible = true;

                var txtCidr = _txtIpdbCidr!;
                var txtUsage = _txtIpdbUsage!;
                var txtLocation = _txtIpdbLocation!;
                var txtComment = _txtIpdbComment!;

                txtCidr.Text = string.IsNullOrEmpty(dns.Ipdb.Cidr) ? "N/A" : dns.Ipdb.Cidr;
                txtUsage.Text = string.IsNullOrEmpty(dns.Ipdb.Usage) ? "N/A" : dns.Ipdb.Usage;
                txtLocation.Text = string.IsNullOrEmpty(dns.Ipdb.Location) ? "N/A" : dns.Ipdb.Location;
                txtComment.Text = string.IsNullOrEmpty(dns.Ipdb.Comment) ? "N/A" : dns.Ipdb.Comment;
            }

            panel.IsVisible = true;
        }

        private void AddDnsRow(StackPanel container, string label, string value, bool wrapText = true)
        {
            var grid = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("80,*,Auto"),
                Margin = new Thickness(0, 2)
            };

            var badgeColor = label switch
            {
                "AAAA" => DraculaColors.Orange,
                "CNAME" => DraculaColors.Yellow,
                "NS" => DraculaColors.Purple,
                "TXT" => DraculaColors.Pink,
                "MX" => DraculaColors.Pink,
                "SPF" => DraculaColors.Cyan,
                "DMARC" => DraculaColors.Purple,
                "PTR" or "A" => DraculaColors.Cyan,
                _ => DraculaColors.Green
            };

            var badge = CreateBadgeBorder(label, badgeColor);
            badge.VerticalAlignment = VerticalAlignment.Center;
            grid.Children.Add(badge);

            var textBlock = new TextBlock
            {
                Text = value,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(12, 0),
                FontFamily = Avalonia.Media.FontFamily.Parse("avares://Client/Resources/Inconsolata-Regular.ttf#Inconsolata"),
                FontSize = 14,
                Foreground = Avalonia.Media.Brush.Parse(DraculaColors.ForegroundLight),
                TextWrapping = wrapText ? Avalonia.Media.TextWrapping.Wrap : Avalonia.Media.TextWrapping.NoWrap
            };
            Grid.SetColumn(textBlock, 1);
            grid.Children.Add(textBlock);

            CreateCopyButton(value, grid);

            container.Children.Add(grid);
        }
    }
}
