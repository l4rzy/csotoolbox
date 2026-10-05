using System;
using System.Collections.Generic;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using CSOToolbox.Client.Helpers;
using CSOToolbox.Client.Lib;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private static Border CreateBadgeBorder(string text, string colorHex)
        {
            return new Border
            {
                Background = Avalonia.Media.Brush.Parse(DraculaColors.BackgroundDark),
                BorderBrush = Avalonia.Media.Brush.Parse(DraculaColors.BorderColor),
                BorderThickness = new Avalonia.Thickness(1),
                CornerRadius = new Avalonia.CornerRadius(4),
                Padding = new Thickness(8, 4),
                Margin = new Thickness(0, 2),
                Child = new TextBlock
                {
                    Text = text,
                    FontSize = 14,
                    Foreground = Avalonia.Media.Brush.Parse(colorHex),
                    FontFamily = Avalonia.Media.FontFamily.Parse("avares://Client/Resources/Inconsolata-Regular.ttf#Inconsolata"),
                }
            };
        }

        private Button CreateCopyButton(string value, Grid parentGrid)
        {
            var btn = new Button
            {
                Content = "Copy",
                Height = 24,
                Padding = new Thickness(6, 1, 6, 3),
                FontSize = 11,
                Background = Avalonia.Media.Brush.Parse(DraculaColors.BackgroundButton),
                BorderBrush = Avalonia.Media.Brush.Parse(DraculaColors.BorderButton),
                VerticalAlignment = VerticalAlignment.Center,
                HorizontalContentAlignment = HorizontalAlignment.Center,
                VerticalContentAlignment = VerticalAlignment.Center
            };
            var captured = value;
            btn.Click += async (s, e) => await CopyAndNotify(captured);
            Grid.SetColumn(btn, 2);
            parentGrid.Children.Add(btn);
            return btn;
        }

        private void SetBooleanIndicator(TextBlock textBlock, bool isActive, string activeColor = DraculaColors.Red, string inactiveColor = DraculaColors.Green)
        {
            if (textBlock == null) return;
            textBlock.Text = isActive ? "Yes" : "No";
            textBlock.Foreground = Avalonia.Media.Brush.Parse(isActive ? activeColor : inactiveColor);
        }

        private void AddDetailRow(
            StackPanel panel,
            string label,
            string? value,
            string labelWidth = "160",
            double fontSize = 14,
            bool showCopy = true,
            Thickness? margin = null,
            string foregroundColorHex = "#E0E0E0",
            int? maxLines = null,
            bool skipIfEmpty = false)
        {
            if (string.IsNullOrEmpty(value))
            {
                if (skipIfEmpty) return;
                value = "N/A";
            }

            var grid = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions($"{labelWidth},*,Auto"),
                Margin = margin ?? new Thickness(0, 1)
            };
            grid.Children.Add(new TextBlock
            {
                Text = label + ":",
                FontWeight = Avalonia.Media.FontWeight.Bold,
                Foreground = Avalonia.Media.Brush.Parse(foregroundColorHex),
                VerticalAlignment = VerticalAlignment.Center,
                FontSize = fontSize
            });
            var valueTb = new TextBlock
            {
                Text = value,
                Foreground = Avalonia.Media.Brush.Parse(foregroundColorHex),
                VerticalAlignment = VerticalAlignment.Center,
                FontSize = fontSize,
                TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                Margin = new Thickness(8, 0, 0, 0)
            };
            if (maxLines.HasValue)
            {
                valueTb.MaxLines = maxLines.Value;
                valueTb.TextTrimming = Avalonia.Media.TextTrimming.CharacterEllipsis;
            }
            Grid.SetColumn(valueTb, 1);
            grid.Children.Add(valueTb);
            if (showCopy && value != "N/A")
                CreateCopyButton(value, grid);
            panel.Children.Add(grid);
        }

        private static readonly Dictionary<AnalyzerType, string?> ServiceIcons = new()
        {
            { AnalyzerType.AbuseIpDb, "abuseipdb" },
            { AnalyzerType.VirusTotal, "virustotal" },
            { AnalyzerType.Bazaar, "bazaar" },
            { AnalyzerType.ThreatFox, "threatfox" },
            { AnalyzerType.Scamalytics, "scamalytics" },
            { AnalyzerType.Circl, "circl" },
            { AnalyzerType.Shodan, "shodan" },
            { AnalyzerType.Rdap, "rdap" },
            { AnalyzerType.Whois, "whois" },
            { AnalyzerType.Dns, "dns" },
            { AnalyzerType.Rdns, "dns" },
            { AnalyzerType.Mac, "mac" },
            { AnalyzerType.Base64, "base64" },
            { AnalyzerType.NetUser, "netuser" },
        };

        private static Bitmap? LoadServiceIcon(AnalyzerType type)
        {
            if (!ServiceIcons.TryGetValue(type, out var name) || name == null) return null;
            try
            {
                var uri = new Uri($"avares://Client/Resources/Services/{name}.png");
                return new Bitmap(AssetLoader.Open(uri));
            }
            catch
            {
                return null;
            }
        }
    }
}
