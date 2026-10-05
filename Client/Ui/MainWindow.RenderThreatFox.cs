using System;
using System.Collections.Generic;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media;
using CSOToolbox.Client.Helpers;
using CSOToolbox.Client.Lib;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private void RenderThreatFoxReport(ThreatFoxObject threatfox)
        {
            var panel = _panelThreatFox!;

            var result = threatfox.Results.FirstOrDefault();
            if (result == null) { panel.IsVisible = false; return; }

            // ── Card 1: Confidence Score ──
            var scorePanel = _panelThreatfoxConfidenceScore!;
            scorePanel.Children.Clear();

            scorePanel.Children.Add(new TextBlock
            {
                Text = "Confidence Score",
                FontSize = 12,
                Foreground = Brush.Parse("#888888"),
                HorizontalAlignment = HorizontalAlignment.Center
            });

            var scoreColor = FormatHelpers.GetInterpolatedScoreBrush(result.ConfidenceLevel);
            scorePanel.Children.Add(new TextBlock
            {
                Text = $"{result.ConfidenceLevel}%",
                FontSize = 36,
                FontWeight = FontWeight.Black,
                Foreground = scoreColor,
                HorizontalAlignment = HorizontalAlignment.Center
            });

            scorePanel.Children.Add(new ProgressBar
            {
                Value = result.ConfidenceLevel,
                Maximum = 100,
                Height = 8,
                Width = 300,
                Foreground = scoreColor,
                Background = Brush.Parse("#444444")
            });

            var detailPanel = _panelThreatfoxConfidenceDetail!;
            detailPanel.Children.Clear();

            detailPanel.Children.Add(new TextBlock
            {
                Text = result.Ioc,
                FontSize = 14,
                Foreground = Brush.Parse(DraculaColors.ForegroundLight),
                HorizontalAlignment = HorizontalAlignment.Center,
                TextWrapping = TextWrapping.Wrap,
                TextAlignment = TextAlignment.Center
            });

            var confidenceLabel = result.ConfidenceLevel switch
            {
                >= 90 => "High",
                >= 75 => "Elevated",
                >= 50 => "Moderate",
                _ => "Unverified"
            };
            detailPanel.Children.Add(new TextBlock
            {
                HorizontalAlignment = HorizontalAlignment.Center,
                TextAlignment = TextAlignment.Center,
                Text = $"Confidence Level is {confidenceLabel}",
                FontSize = 14,
                Foreground = Brush.Parse(DraculaColors.ForegroundGray)
            });

            // ── Card 2: Details ──
            var detailsPanel = _panelThreatfoxDetails!;
            detailsPanel.Children.Clear();

            var malwareLabel = result.MalwarePrintable ?? result.Malware;
            if (!string.IsNullOrEmpty(result.MalwareAlias))
                malwareLabel = $"{malwareLabel} ({result.MalwareAlias})";
            AddDetailRow(detailsPanel, "Malware", malwareLabel ?? "N/A", showCopy: true);

            if (!string.IsNullOrEmpty(result.ThreatTypeDesc))
                AddDetailRow(detailsPanel, "Threat Type", result.ThreatTypeDesc, showCopy: false);

            if (!string.IsNullOrEmpty(result.IocTypeDesc))
                AddDetailRow(detailsPanel, "IOC Type", result.IocTypeDesc, showCopy: false);

            // Reference
            if (!string.IsNullOrEmpty(result.Reference))
            {
                var refGrid = new Grid { ColumnDefinitions = new ColumnDefinitions("160,*,Auto"), Margin = new Thickness(0, 1) };
                refGrid.Children.Add(new TextBlock
                {
                    Text = "Reference:",
                    FontWeight = FontWeight.Bold,
                    Foreground = Brush.Parse("#E0E0E0"),
                    VerticalAlignment = VerticalAlignment.Center,
                    FontSize = 14
                });
                var refTb = new TextBlock
                {
                    Text = result.Reference,
                    Foreground = Brush.Parse(DraculaColors.ForegroundLight),
                    VerticalAlignment = VerticalAlignment.Center,
                    FontSize = 14,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(8, 0, 0, 0)
                };
                Grid.SetColumn(refTb, 1);
                refGrid.Children.Add(refTb);
                var openBtn = new Button
                {
                    Content = "Open",
                    Height = 24,
                    Padding = new Thickness(6, 1, 6, 3),
                    FontSize = 11,
                    Background = Brush.Parse(DraculaColors.BackgroundButton),
                    BorderBrush = Brush.Parse(DraculaColors.BorderButton),
                    VerticalContentAlignment = VerticalAlignment.Center,
                    HorizontalContentAlignment = HorizontalAlignment.Center
                };
                var capturedRef = result.Reference;
                openBtn.Click += (_, _) => OpenBrowser(capturedRef);
                Grid.SetColumn(openBtn, 2);
                refGrid.Children.Add(openBtn);
                detailsPanel.Children.Add(refGrid);
            }

            // Separator
            detailsPanel.Children.Add(new Border
            {
                BorderBrush = Brush.Parse(DraculaColors.BorderColor),
                BorderThickness = new Thickness(0, 1, 0, 0),
                Margin = new Thickness(0, 4),
                HorizontalAlignment = HorizontalAlignment.Center,
                Width = 200
            });

            // Tags
            var tagList = new List<string>();
            if (!string.IsNullOrEmpty(result.ThreatType)) tagList.Add($"threat:{result.ThreatType}");
            if (!string.IsNullOrEmpty(result.IocType))    tagList.Add($"ioc:{result.IocType}");
            if (result.Tags is { Count: > 0 })           tagList.AddRange(result.Tags);
            if (tagList.Count > 0)
            {
                var tagColors = new[] { DraculaColors.Cyan, DraculaColors.Orange, DraculaColors.Purple, DraculaColors.Pink, DraculaColors.Green, DraculaColors.Yellow, DraculaColors.Red };
                var wrapPanel = new WrapPanel { Margin = new Thickness(0, 4, 0, 0), HorizontalAlignment = HorizontalAlignment.Center };
                int ci = 0;
                foreach (var tag in tagList)
                {
                    var badge = CreateBadgeBorder(tag, tagColors[ci % tagColors.Length]);
                    badge.Margin = new Thickness(0, 2, 4, 2);
                    wrapPanel.Children.Add(badge);
                    ci++;
                }
                detailsPanel.Children.Add(wrapPanel);
            }

            // ── Card 3: Extra ──
            var extraPanel = _panelThreatfoxExtra!;
            extraPanel.Children.Clear();
            AddDetailRow(extraPanel, "First Seen", FormatDateTime(StripUtcSuffix(result.FirstSeen)), showCopy: false);
            AddDetailRow(extraPanel, "Last Seen", FormatDateTime(StripUtcSuffix(result.LastSeen)), showCopy: false);
            AddDetailRow(extraPanel, "Reporter", result.Reporter ?? "N/A", showCopy: true);

            panel.IsVisible = true;
        }

        private static string? StripUtcSuffix(string? raw)
        {
            if (string.IsNullOrEmpty(raw))
                return raw;

            const string suffix = " UTC";
            if (raw.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                return raw.Substring(0, raw.Length - suffix.Length).Replace(" ", "T") + "Z";

            return raw;
        }
    }
}
