using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Layout;
using Avalonia.Media;
using CSOToolbox.Client.Helpers;
using CSOToolbox.Client.Lib;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private void RenderBazaarReport(BazaarObject bazaar)
        {
            var panel = _panelBazaar!;

            var infoPanel = _panelBazaarInfo!;
            var classPanel = _panelBazaarClassification!;
            var vendorPanel = _panelBazaarVendors!;

            infoPanel.Children.Clear();
            classPanel.Children.Clear();
            vendorPanel.Children.Clear();

            // ── Card 1: File Information ──
            AddDetailRow(infoPanel, "File Name", bazaar.FileName, showCopy: true);
            AddDetailRow(infoPanel, "File Size", bazaar.FileSize > 0 ? $"{bazaar.FileSize:N0} bytes" : null, showCopy: false);

            // MIME Type badge
            var mimeGrid = new Grid { ColumnDefinitions = new ColumnDefinitions("160,*"), Margin = new Thickness(0, 1) };
            mimeGrid.Children.Add(new TextBlock
            {
                Text = "MIME Type:", FontWeight = FontWeight.Bold, Foreground = Brush.Parse("#E0E0E0"),
                VerticalAlignment = VerticalAlignment.Center, FontSize = 14
            });
            var mimeBadge = CreateBadgeBorder(bazaar.FileTypeMime ?? "N/A", DraculaColors.Cyan);
            mimeBadge.HorizontalAlignment = HorizontalAlignment.Left;
            Grid.SetColumn(mimeBadge, 1);
            mimeGrid.Children.Add(mimeBadge);
            infoPanel.Children.Add(mimeGrid);

            AddDetailRow(infoPanel, "File Type", bazaar.FileType, showCopy: false);
            AddDetailRow(infoPanel, "Delivery Method", bazaar.DeliveryMethod, showCopy: false);
            AddDetailRow(infoPanel, "First Seen", FormatDateTime(bazaar.FirstSeen), showCopy: false);
            AddDetailRow(infoPanel, "Last Seen", FormatDateTime(bazaar.LastSeen), showCopy: false);
            AddDetailRow(infoPanel, "Comment", Defang(bazaar.Comment ?? ""), showCopy: true, maxLines: 5, skipIfEmpty: true);
            if (infoPanel.Children.Count == 0)
            {
                infoPanel.Children.Add(new TextBlock
                {
                    Text = "No file information available.",
                    Foreground = new SolidColorBrush(Color.Parse("#888888")),
                    FontSize = 13
                });
            }

            // ── Card 2: Classification ──
            if (!string.IsNullOrEmpty(bazaar.Signature))
                AddDetailRow(classPanel, "Malware Family", bazaar.Signature);
            if (bazaar.Tags is { Count: > 0 })
            {
                var tagGrid = new Grid { ColumnDefinitions = new ColumnDefinitions("160,*"), Margin = new Thickness(0, 1) };
                tagGrid.Children.Add(new TextBlock
                {
                    Text = "Tags:", FontWeight = FontWeight.Bold, Foreground = Brush.Parse("#E0E0E0"),
                    VerticalAlignment = VerticalAlignment.Top, FontSize = 14
                });
                var wrapPanel = new WrapPanel { Margin = new Thickness(0, 2) };
                var tagColors = new[] { DraculaColors.Cyan, DraculaColors.Orange, DraculaColors.Purple, DraculaColors.Pink, DraculaColors.Green, DraculaColors.Yellow, DraculaColors.Red };
                int ci = 0;
                foreach (var tag in bazaar.Tags)
                {
                    var badge = CreateBadgeBorder(tag, tagColors[ci % tagColors.Length]);
                    badge.Margin = new Thickness(0, 2, 4, 2);
                    wrapPanel.Children.Add(badge);
                    ci++;
                }
                Grid.SetColumn(wrapPanel, 1);
                tagGrid.Children.Add(wrapPanel);
                classPanel.Children.Add(tagGrid);
            }
            if (classPanel.Children.Count == 0)
            {
                classPanel.Children.Add(new TextBlock
                {
                    Text = "No classification data available.",
                    Foreground = new SolidColorBrush(Color.Parse("#888888")),
                    FontSize = 13
                });
            }

            // ── Card 3: Vendor Intelligence ──
            if (bazaar.VendorIntel != null && bazaar.VendorIntel.Count > 0)
            {
                // First pass: classify vendors
                int malCount = 0, suspCount = 0, cleanCount = 0, otherCount = 0;
                foreach (var kvp in bazaar.VendorIntel)
                {
                    switch (ClassifyVendor(kvp.Value))
                    {
                        case "Malicious": malCount++; break;
                        case "Suspicious": suspCount++; break;
                        case "Clean": cleanCount++; break;
                        default: otherCount++; break;
                    }
                }

                int total = malCount + suspCount + cleanCount + otherCount;
                if (total > 0)
                    vendorPanel.Children.Add(BuildVendorPieChart(malCount, suspCount, cleanCount, otherCount, total));

                // Second pass: individual rows
                foreach (var kvp in bazaar.VendorIntel)
                {
                    var summary = ExtractVendorSummary(kvp.Value);
                    var url = ExtractVendorUrl(kvp.Value);
                    AddVendorRow(vendorPanel, kvp.Key, summary, url);
                }
            }
            if (vendorPanel.Children.Count == 0)
            {
                vendorPanel.Children.Add(new TextBlock
                {
                    Text = "No vendor intelligence available.",
                    Foreground = new SolidColorBrush(Color.Parse("#888888")),
                    FontSize = 13
                });
            }

            panel.IsVisible = true;
        }

        private static string? ExtractVendorUrl(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Object)
                foreach (var key in new[] { "link", "report_link", "analysis_url", "url" })
                    if (element.TryGetProperty(key, out var val) && val.ValueKind == JsonValueKind.String)
                        return val.GetString();
            return null;
        }

        private void AddVendorRow(StackPanel panel, string label, string summary, string? url)
        {
            var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("160,*,Auto"), Margin = new Thickness(0, 1) };
            grid.Children.Add(new TextBlock
            {
                Text = label + ":", FontWeight = FontWeight.Bold,
                Foreground = Brush.Parse("#E0E0E0"), VerticalAlignment = VerticalAlignment.Top, FontSize = 14
            });
            var tb = new TextBlock
            {
                Text = summary, TextWrapping = TextWrapping.Wrap, FontSize = 14,
                Foreground = Brush.Parse("#E0E0E0"), VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(8, 0, 0, 0), MaxLines = 3,
                TextTrimming = TextTrimming.CharacterEllipsis
            };
            Grid.SetColumn(tb, 1);
            grid.Children.Add(tb);

            if (!string.IsNullOrEmpty(url))
            {
                var btn = new Button
                {
                    Content = "Analysis", Height = 24, Padding = new Thickness(6, 1, 6, 3),
                    FontSize = 11, Background = Brush.Parse(DraculaColors.BackgroundButton),
                    BorderBrush = Brush.Parse(DraculaColors.BorderButton),
                    VerticalContentAlignment = VerticalAlignment.Center,
                    HorizontalContentAlignment = HorizontalAlignment.Center,
                    Margin = new Thickness(4, 0)
                };
                var captured = url;
                btn.Click += (s, e) => OpenBrowser(captured);
                Grid.SetColumn(btn, 2);
                grid.Children.Add(btn);
            }
            panel.Children.Add(grid);
        }

        private static string ExtractVendorSummary(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    var parts = new System.Collections.Generic.List<string>();
                    foreach (var prop in new[] { "detection", "verdict", "score", "malware_family", "status", "maliciousness" })
                    {
                        if (element.TryGetProperty(prop, out var val) && val.ValueKind != JsonValueKind.Null)
                        {
                            var str = val.ToString();
                            if (!string.IsNullOrEmpty(str))
                                parts.Add(str);
                        }
                    }
                    return parts.Count > 0 ? string.Join(" · ", parts) : "N/A";
                case JsonValueKind.Array:
                    var arrParts = new System.Collections.Generic.List<string>();
                    foreach (var item in element.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.Object)
                        {
                            if (item.TryGetProperty("verdict", out var v))
                            {
                                var str = v.ToString();
                                if (!string.IsNullOrEmpty(str))
                                    arrParts.Add(str);
                            }
                            else if (item.TryGetProperty("detection", out var d))
                            {
                                arrParts.Add(d.ToString());
                            }
                        }
                    }
                    return arrParts.Count > 0 ? string.Join(" · ", arrParts) : $"({element.GetArrayLength()} entries)";
                default:
                    return element.ToString();
            }
        }

        private static string Defang(string text)
        {
            if (string.IsNullOrEmpty(text)) return text;
            text = Regex.Replace(text, @"\bhttps?://", m => "hxxp" + m.Value.Substring(4));
            text = Regex.Replace(text, @"(?<=\w)\.(?=\w)", "[.]");
            text = text.Replace("@", "[at]");
            return text;
        }

        private static string ClassifyVendor(JsonElement element)
        {
            var text = ExtractVendorSummary(element).ToLowerInvariant();
            if (text.Contains("malware") || text.Contains("malicious"))
                return "Malicious";
            if (text.Contains("suspicious"))
                return "Suspicious";
            if (text == "n/a" || text.Contains("clean") || text.Contains("harmless") ||
                text.Contains("known") || text.Contains("notcategorized") || text.Contains("unknown"))
                return "Clean";
            return "Other";
        }

        private Border BuildVendorPieChart(int malCount, int suspCount, int cleanCount, int otherCount, int total)
        {
            double canvasSize = 160;
            double radius = 70;
            double holeRadius = 38;

            var chartData = new List<(string name, int count, string color)>();
            if (malCount > 0) chartData.Add(("Malicious", malCount, DraculaColors.Red));
            if (suspCount > 0) chartData.Add(("Suspicious", suspCount, DraculaColors.Orange));
            if (cleanCount > 0) chartData.Add(("Clean", cleanCount, DraculaColors.Green));
            if (otherCount > 0) chartData.Add(("Other", otherCount, "#888888"));

            var rootGrid = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("Auto,*"),
                ColumnSpacing = 24
            };

            var canvas = new Canvas
            {
                Width = canvasSize, Height = canvasSize,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            double cx = canvasSize / 2, cy = canvasSize / 2;
            double currentAngle = -90.0;

            foreach (var (name, count, color) in chartData)
            {
                double sweep = count * 360.0 / total;

                if (sweep >= 359.9)
                {
                    var path = new Path
                    {
                        Fill = Brush.Parse(color),
                        Data = new EllipseGeometry { Center = new Point(cx, cy), RadiusX = radius, RadiusY = radius }
                    };
                    ToolTip.SetTip(path, $"{name}: {count} ({(double)count / total:P1})");
                    canvas.Children.Add(path);
                }
                else
                {
                    var path = new Path
                    {
                        Fill = Brush.Parse(color),
                        Data = FormatHelpers.CreatePieSlice(cx, cy, radius, currentAngle, currentAngle + sweep)
                    };
                    ToolTip.SetTip(path, $"{name}: {count} ({(double)count / total:P1})");
                    canvas.Children.Add(path);
                    currentAngle += sweep;
                }
            }

            canvas.Children.Add(new Path
            {
                Fill = Brush.Parse(DraculaColors.BackgroundCard),
                Data = new EllipseGeometry { Center = new Point(cx, cy), RadiusX = holeRadius, RadiusY = holeRadius }
            });

            rootGrid.Children.Add(canvas);

            var legendPanel = new StackPanel { Spacing = 8, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(12, 0, 0, 0) };
            foreach (var (name, count, color) in chartData)
            {
                var rowGrid = new Grid();
                rowGrid.ColumnDefinitions.Add(new ColumnDefinition(GridLength.Auto));
                rowGrid.ColumnDefinitions.Add(new ColumnDefinition(GridLength.Star));
                rowGrid.ColumnDefinitions.Add(new ColumnDefinition(GridLength.Auto));
                rowGrid.ColumnSpacing = 12;

                var dot = new Border
                {
                    Width = 10, Height = 10, CornerRadius = new CornerRadius(5),
                    Background = Brush.Parse(color), BorderThickness = new Thickness(0),
                    VerticalAlignment = VerticalAlignment.Center
                };
                var nameTxt = new TextBlock
                {
                    Text = name, FontSize = 13, FontWeight = FontWeight.SemiBold,
                    Foreground = Brush.Parse(DraculaColors.ForegroundLight),
                    VerticalAlignment = VerticalAlignment.Center
                };
                var pct = count * 100.0 / total;
                var countTxt = new TextBlock
                {
                    Text = $"{count} ({pct:F0}%)", FontSize = 12,
                    Foreground = Brush.Parse("#888888"),
                    VerticalAlignment = VerticalAlignment.Center,
                    HorizontalAlignment = HorizontalAlignment.Right
                };

                rowGrid.Children.Add(dot);
                Grid.SetColumn(dot, 0);
                rowGrid.Children.Add(nameTxt);
                Grid.SetColumn(nameTxt, 1);
                rowGrid.Children.Add(countTxt);
                Grid.SetColumn(countTxt, 2);

                legendPanel.Children.Add(rowGrid);
            }
            Grid.SetColumn(legendPanel, 1);
            rootGrid.Children.Add(legendPanel);

            return new Border
            {
                Background = Brush.Parse(DraculaColors.BackgroundCard),
                CornerRadius = new CornerRadius(8), Padding = new Thickness(16),
                BorderBrush = Brush.Parse(DraculaColors.BorderColor), BorderThickness = new Thickness(1),
                Child = rootGrid, Margin = new Thickness(0, 0, 0, 12)
            };
        }
    }
}
