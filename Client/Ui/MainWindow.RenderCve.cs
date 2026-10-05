using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using CSOToolbox.Client.Helpers;
using CSOToolbox.Client.Lib;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private void RenderCveReport(CommonCVEObject cve)
        {

            // ── CVE Details Card ──
            _cardCveDetails!.IsVisible = true;
            _txtCveId!.Text = cve.Id;
            _txtCveAssigner!.Text = string.IsNullOrEmpty(cve.Assigner) ? "N/A" : cve.Assigner;
            _txtCvePublished!.Text = FormatDateTime(cve.Published);
            _txtCveModified!.Text = !string.IsNullOrEmpty(cve.Modified) ? FormatDateTime(cve.Modified) : "N/A";

            // ── CVSS Score Card ──
            double cvss = cve.Cvss ?? 0.0;
            _txtCveScore!.Text = cvss.ToString("F1");
            _progressCveScore!.Value = cvss * 10;
            var scoreBrush = FormatHelpers.GetInterpolatedScoreBrush(cvss, 10.0);
            _progressCveScore.Foreground = scoreBrush;
            _txtCveScore.Foreground = scoreBrush;

            // ── EPSS & KEV Card (Shodan extras) ──
            _cardCveEpssKev!.IsVisible = false;
            _panelCveEpssKev!.Children.Clear();
            if (cve.Epss.HasValue || cve.Kev == true)
            {
                _cardCveEpssKev.IsVisible = true;
                if (cve.Epss.HasValue)
                {
                    double epssPct = cve.Epss.Value * 100.0;
                    var epssGrid = new Grid
                    {
                        ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto"),
                        ColumnSpacing = 12,
                        Margin = new Thickness(0, 2)
                    };
                    epssGrid.Children.Add(new TextBlock
                    {
                        Text = "EPSS",
                        FontWeight = Avalonia.Media.FontWeight.SemiBold,
                        Foreground = Avalonia.Media.Brush.Parse(DraculaColors.Orange),
                        VerticalAlignment = VerticalAlignment.Center
                    });
                    var epssBar = new ProgressBar
                    {
                        Value = epssPct,
                        Maximum = 100,
                        Height = 6,
                        Foreground = FormatHelpers.GetInterpolatedScoreBrush(epssPct),
                        Background = Avalonia.Media.Brush.Parse("#444444"),
                        VerticalAlignment = VerticalAlignment.Center
                    };
                    Grid.SetColumn(epssBar, 1);
                    epssGrid.Children.Add(epssBar);
                    var epssTxt = new TextBlock
                    {
                        Text = $"{cve.Epss.Value:P2}",
                        FontSize = 13,
                        Foreground = Avalonia.Media.Brush.Parse(DraculaColors.ForegroundLight),
                        VerticalAlignment = VerticalAlignment.Center
                    };
                    Grid.SetColumn(epssTxt, 2);
                    epssGrid.Children.Add(epssTxt);
                    _panelCveEpssKev.Children.Add(epssGrid);
                }
                if (cve.Kev == true)
                {
                    var kevBadge = new Border
                    {
                        Background = Avalonia.Media.Brush.Parse("#3d0000"),
                        BorderBrush = Avalonia.Media.Brush.Parse(DraculaColors.Red),
                        BorderThickness = new Thickness(1),
                        CornerRadius = new CornerRadius(6),
                        Padding = new Thickness(12, 6),
                        Child = new TextBlock
                        {
                            Text = "KNOWN EXPLOITED VULNERABILITY (CISA KEV)",
                            FontWeight = Avalonia.Media.FontWeight.Bold,
                            Foreground = Avalonia.Media.Brush.Parse(DraculaColors.Red),
                            FontSize = 13
                        }
                    };
                    _panelCveEpssKev.Children.Add(kevBadge);
                }
            }

            // ── Access Vector Card (CIRCL) ──
            _cardCveAccess!.IsVisible = false;
            _panelCveAccess!.Children.Clear();
            if (cve.Access != null)
            {
                _cardCveAccess.IsVisible = true;
                AddCveMetricRow(_panelCveAccess, "Authentication", cve.Access.Authentication ?? "UNKNOWN", DraculaColors.Cyan);
                AddCveMetricRow(_panelCveAccess, "Complexity", cve.Access.Complexity ?? "UNKNOWN", DraculaColors.Cyan);
                AddCveMetricRow(_panelCveAccess, "Vector", cve.Access.Vector ?? "UNKNOWN", DraculaColors.Cyan);
            }

            // ── Impact Ratings Card (CIRCL) ──
            _cardCveImpact!.IsVisible = false;
            _panelCveImpact!.Children.Clear();
            if (cve.Impact != null)
            {
                _cardCveImpact.IsVisible = true;
                AddCveMetricRow(_panelCveImpact, "Confidentiality", cve.Impact.Confidentiality ?? "UNKNOWN", DraculaColors.Red);
                AddCveMetricRow(_panelCveImpact, "Integrity", cve.Impact.Integrity ?? "UNKNOWN", DraculaColors.Red);
                AddCveMetricRow(_panelCveImpact, "Availability", cve.Impact.Availability ?? "UNKNOWN", DraculaColors.Red);
            }

            // ── Summary Description ──
            _txtCveSummary!.Text = cve.Summary ?? "No description available.";

            _panelCVE!.IsVisible = true;
        }

        private void AddCveMetricRow(StackPanel container, string label, string value, string badgeColor)
        {
            var grid = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("Auto,*"),
                ColumnSpacing = 8,
                Margin = new Thickness(0, 1)
            };

            var badge = CreateBadgeBorder(label, badgeColor);
            grid.Children.Add(badge);

            var valueText = new TextBlock
            {
                Text = value,
                VerticalAlignment = VerticalAlignment.Center,
                FontSize = 14,
                Foreground = Avalonia.Media.Brush.Parse(DraculaColors.ForegroundLight),
                TextWrapping = Avalonia.Media.TextWrapping.Wrap
            };
            Grid.SetColumn(valueText, 1);
            grid.Children.Add(valueText);

            container.Children.Add(grid);
        }
    }
}
