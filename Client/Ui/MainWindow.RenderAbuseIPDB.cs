using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using CSOToolbox.Client.Helpers;
using CSOToolbox.Client.Lib;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private static readonly string[] AbuseCategories = {
            "None",
            "DNS Compromise",
            "DNS Poisoning",
            "Fraud Orders",
            "DDoS Attack",
            "FTP Brute-Force",
            "Ping of Death",
            "Phishing",
            "Fraud VoIP",
            "Open Proxy",
            "Web Spam",
            "Email Spam",
            "Blog Spam",
            "VPN IP",
            "Port Scan",
            "Hacking",
            "SQL Injection",
            "Spoofing",
            "Brute-Force",
            "Bad Web Bot",
            "Exploited Host",
            "Web App Attack",
            "SSH",
            "IoT Targeted"
        };

        private void RenderAbuseIpReport(AbuseObject abuse)
        {
            var panel = _panelAbuseIPDB!;

            var txtScore = _txtAbuseScore!;
            var progressScore = _progressAbuseScore!;
            var txtDetails = _txtAbuseDetails!;
            var txtIsp = _txtAbuseIsp!;
            var txtUsage = _txtAbuseUsage!;
            var txtDomain = _txtAbuseDomain!;
            var txtCountry = _txtAbuseCountry!;

            var d = abuse.Data!;
            txtScore.Text = $"{d.AbuseConfidenceScore}%";
            progressScore.Value = d.AbuseConfidenceScore;

            // Color-code score bar and text dynamically
            var scoreBrush = FormatHelpers.GetInterpolatedScoreBrush(d.AbuseConfidenceScore);
            progressScore.Foreground = scoreBrush;
            txtScore.Foreground = scoreBrush;

            if (!d.IsPublic)
            {
                ShowError("This IP address is private (RFC 1918).");
                return;
            }

            txtIsp.IsVisible = true;
            txtUsage.IsVisible = true;
            txtDomain.IsVisible = true;
            txtCountry.IsVisible = true;

            string formattedLastReported = !string.IsNullOrEmpty(d.LastReportedAt) ? FormatDateTime(d.LastReportedAt) : "Never";
            txtDetails.Text = $"Reported {d.TotalReports} times by {d.NumDistinctUsers} distinct users. Last reported at {formattedLastReported}.";
            txtIsp.Text = d.Isp ?? "Unknown";
            txtUsage.Text = d.UsageType ?? "Unknown";
            txtDomain.Text = d.Domain ?? "Unknown";

            // Hide copy buttons for non-copyable fields and N/A values
            _btnAbuseUsageCopy.IsVisible = false;
            _btnAbuseCountryCopy.IsVisible = false;
            FormatHelpers.SetCountryTextWithFlag(txtCountry, d.CountryCode, null);

            var categoriesPanel = _panelAbuseCategories!;
            categoriesPanel.Children.Clear();

            if (d.Reports != null && d.Reports.Count > 0)
            {
                categoriesPanel.IsVisible = true;
                var categoriesDict = new Dictionary<int, int>();
                foreach (var report in d.Reports)
                {
                    foreach (var category in report.Categories)
                    {
                        categoriesDict[category] = categoriesDict.GetValueOrDefault(category, 0) + 1;
                    }
                }

                // --- Donut Chart Implementation ---
                int totalReports = categoriesDict.Values.Sum();
                if (totalReports > 0)
                {
                    var sortedCategories = categoriesDict.OrderByDescending(x => x.Value).ToList();
                    var chartData = new List<(string Name, int Count, string Color)>();
                    string[] colors = { DraculaColors.Red, DraculaColors.Orange, DraculaColors.Pink, DraculaColors.Purple, DraculaColors.Green }; // Premium colors: Red, Orange, Pink, Purple, Green

                    for (int i = 0; i < Math.Min(4, sortedCategories.Count); i++)
                    {
                        var item = sortedCategories[i];
                        string name = item.Key >= 0 && item.Key < AbuseCategories.Length ? AbuseCategories[item.Key] : $"Category {item.Key}";
                        chartData.Add((name, item.Value, colors[i]));
                    }

                    if (sortedCategories.Count > 4)
                    {
                        int otherCount = 0;
                        for (int i = 4; i < sortedCategories.Count; i++)
                        {
                            otherCount += sortedCategories[i].Value;
                        }
                        chartData.Add(("Others", otherCount, colors[4]));
                    }

                    var chartGrid = new Avalonia.Controls.Grid();
                    chartGrid.ColumnDefinitions.Add(new Avalonia.Controls.ColumnDefinition(new Avalonia.Controls.GridLength(160)));
                    chartGrid.ColumnDefinitions.Add(new Avalonia.Controls.ColumnDefinition(Avalonia.Controls.GridLength.Star));
                    chartGrid.ColumnSpacing = 24;

                    var canvas = new Avalonia.Controls.Canvas
                    {
                        Width = 160,
                        Height = 160,
                        HorizontalAlignment = HorizontalAlignment.Center,
                        VerticalAlignment = VerticalAlignment.Center
                    };
                    chartGrid.Children.Add(canvas);
                    Avalonia.Controls.Grid.SetColumn(canvas, 0);

                    double currentAngle = -90.0;
                    foreach (var slice in chartData)
                    {
                        if (slice.Count == 0) continue;
                        double percent = (double)slice.Count / totalReports;
                        double sweepAngle = percent * 360.0;

                        if (sweepAngle >= 359.9)
                        {
                            var path = new Avalonia.Controls.Shapes.Path
                            {
                                Fill = Avalonia.Media.Brush.Parse(slice.Color),
                                Data = new Avalonia.Media.EllipseGeometry { Center = new Avalonia.Point(80, 80), RadiusX = 70, RadiusY = 70 }
                            };
                            Avalonia.Controls.ToolTip.SetTip(path, $"{slice.Name}: {slice.Count} ({percent:P1})");
                            canvas.Children.Add(path);
                        }
                        else
                        {
                            var path = new Avalonia.Controls.Shapes.Path
                            {
                                Fill = Avalonia.Media.Brush.Parse(slice.Color),
                                Data = FormatHelpers.CreatePieSlice(80, 80, 70, currentAngle, currentAngle + sweepAngle)
                            };
                            Avalonia.Controls.ToolTip.SetTip(path, $"{slice.Name}: {slice.Count} ({percent:P1})");
                            canvas.Children.Add(path);
                            currentAngle += sweepAngle;
                        }
                    }

                    var hole = new Avalonia.Controls.Shapes.Path
                    {
                        Fill = Avalonia.Media.Brush.Parse(DraculaColors.BackgroundCard), // matches detail cards
                        Data = new Avalonia.Media.EllipseGeometry { Center = new Avalonia.Point(80, 80), RadiusX = 38, RadiusY = 38 }
                    };
                    canvas.Children.Add(hole);

                    var legendStack = new StackPanel
                    {
                        Spacing = 8,
                        VerticalAlignment = VerticalAlignment.Center
                    };
                    chartGrid.Children.Add(legendStack);
                    Avalonia.Controls.Grid.SetColumn(legendStack, 1);

                    foreach (var slice in chartData)
                    {
                        double percent = (double)slice.Count / totalReports;
                        var dot = new Avalonia.Controls.Border
                        {
                            Background = Avalonia.Media.Brush.Parse(slice.Color),
                            Width = 10,
                            Height = 10,
                            CornerRadius = new Avalonia.CornerRadius(5),
                            VerticalAlignment = VerticalAlignment.Center
                        };

                        var nameTxt = new TextBlock
                        {
                            Text = slice.Name,
                            FontSize = 13,
                            FontWeight = Avalonia.Media.FontWeight.SemiBold,
                            Foreground = Avalonia.Media.Brush.Parse(DraculaColors.ForegroundLight),
                            VerticalAlignment = VerticalAlignment.Center
                        };

                        var countTxt = new TextBlock
                        {
                            Text = $"{slice.Count} ({percent:P0})",
                            FontSize = 12,
                            Foreground = Avalonia.Media.Brush.Parse("#888888"),
                            VerticalAlignment = VerticalAlignment.Center,
                            HorizontalAlignment = HorizontalAlignment.Right
                        };

                        var rowGrid = new Avalonia.Controls.Grid();
                        rowGrid.ColumnDefinitions.Add(new Avalonia.Controls.ColumnDefinition(Avalonia.Controls.GridLength.Auto));
                        rowGrid.ColumnDefinitions.Add(new Avalonia.Controls.ColumnDefinition(Avalonia.Controls.GridLength.Star));
                        rowGrid.ColumnDefinitions.Add(new Avalonia.Controls.ColumnDefinition(Avalonia.Controls.GridLength.Auto));
                        rowGrid.ColumnSpacing = 12;

                        rowGrid.Children.Add(dot);
                        rowGrid.Children.Add(nameTxt);
                        rowGrid.Children.Add(countTxt);

                        Avalonia.Controls.Grid.SetColumn(dot, 0);
                        Avalonia.Controls.Grid.SetColumn(nameTxt, 1);
                        Avalonia.Controls.Grid.SetColumn(countTxt, 2);

                        legendStack.Children.Add(rowGrid);
                    }

                    var cardContent = new StackPanel { Spacing = 14 };

                    var titleTxt = new TextBlock
                    {
                        Text = "Reported Categories",
                        FontSize = 15,
                        FontWeight = Avalonia.Media.FontWeight.Bold,
                        Foreground = Avalonia.Media.Brush.Parse(DraculaColors.Purple)
                    };
                    cardContent.Children.Add(titleTxt);

                    var separator = new Avalonia.Controls.Border
                    {
                        BorderBrush = Avalonia.Media.Brush.Parse(DraculaColors.BorderColor),
                        BorderThickness = new Avalonia.Thickness(0, 1, 0, 0),
                        Margin = new Avalonia.Thickness(0, 2)
                    };
                    cardContent.Children.Add(separator);

                    cardContent.Children.Add(chartGrid);

                    var chartCard = new Avalonia.Controls.Border
                    {
                        Background = Avalonia.Media.Brush.Parse(DraculaColors.BackgroundCard),
                        BorderBrush = Avalonia.Media.Brush.Parse(DraculaColors.BorderColor),
                        BorderThickness = new Avalonia.Thickness(1),
                        CornerRadius = new Avalonia.CornerRadius(8),
                        Padding = new Avalonia.Thickness(16),
                        Margin = new Avalonia.Thickness(0, 0, 0, 0),
                        Child = cardContent
                    };

                    categoriesPanel.Children.Add(chartCard);
                }
            }
            else
            {
                categoriesPanel.IsVisible = false;
            }

            panel.IsVisible = true;
        }

    }
}
