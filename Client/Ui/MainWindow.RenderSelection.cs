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
        private void RenderSelectionReport(object data)
        {
            var panel = _panelSelection!;

            var container = _containerSelectionOptions!;
            container.Children.Clear();

            int count = 0;
            if (data is System.Collections.Generic.Dictionary<string, List<string>> choices)
            {
                foreach (var kvp in choices)
                {
                    var type = CsoStatelessIndicatorExtractor.GetIndicatorTypeKey(kvp.Key);
                    foreach (var entry in kvp.Value.Distinct())
                    {
                        AddChoiceRow(container, type, entry);
                        count++;
                    }
                }
            }
            else if (data is List<string> list)
            {
                foreach (var entry in list.Distinct())
                {
                    var type = CsoStatelessIndicatorExtractor.Classify(entry);
                    AddChoiceRow(container, type, entry);
                    count++;
                }
            }

            var txtTitle = _txtSelectionTitle!;
            var txtLabel = _txtSelectionLabel!;
            if (count == 1)
            {
                if (txtTitle != null) txtTitle.Text = "Indicator Detected";
                if (txtLabel != null) txtLabel.Text = "Do you mean to analyze this indicator?";
            }
            else
            {
                if (txtTitle != null) txtTitle.Text = "Multiple Indicators Detected";
                if (txtLabel != null) txtLabel.Text = "Which one should I analyze?";
            }

            panel.IsVisible = true;
        }

        private void AddChoiceRow(StackPanel container, IndicatorType type, string entry)
        {
            var grid = new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto,Auto"),
                Margin = new Thickness(0, 4)
            };

            var (displayType, badgeColor) = GetIndicatorTypeBadge(type, entry);
            var badge = CreateBadgeBorder(displayType, badgeColor);
            badge.VerticalAlignment = VerticalAlignment.Center;
            grid.Children.Add(badge);

            var textBlock = new TextBlock
            {
                Text = entry,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(12, 0),
                FontSize = 13.5,
                Foreground = Avalonia.Media.Brush.Parse(DraculaColors.ForegroundLight),
                TextWrapping = Avalonia.Media.TextWrapping.Wrap
            };
            Grid.SetColumn(textBlock, 1);
            grid.Children.Add(textBlock);

            CreateCopyButton(entry, grid);

            bool wasAnalyzed = false;
            var found = _history.FindEntry(entry);
            if (found.HasValue)
            {
                var s = found.Value.source.ToLower();
                wasAnalyzed = s != "indicators" && s != "switch";
            }
            var btnAnalyze = new Button
            {
                Content = "Analyze",
                Height = 24,
                Padding = new Thickness(6, 1, 6, 3),
                FontSize = 11,
                FontWeight = wasAnalyzed ? Avalonia.Media.FontWeight.Normal : Avalonia.Media.FontWeight.SemiBold,
                Background = wasAnalyzed ? Avalonia.Media.Brush.Parse(DraculaColors.BackgroundButton) : (this.FindResource("SystemAccentColor") is Avalonia.Media.Color accentColor ? new Avalonia.Media.SolidColorBrush(accentColor) : Avalonia.Media.Brush.Parse("#007acc")),
                BorderBrush = wasAnalyzed ? Avalonia.Media.Brush.Parse(DraculaColors.BorderButton) : null,
                Foreground = wasAnalyzed ? Avalonia.Media.Brush.Parse(DraculaColors.ForegroundGray) : Avalonia.Media.Brushes.White,
                VerticalContentAlignment = VerticalAlignment.Center,
                HorizontalContentAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(4, 0)
            };
            btnAnalyze.Click += async (s, e) =>
            {
                await ProcessInput(CsoInputSource.SelectedIndicator, entry, type);
            };
            Grid.SetColumn(btnAnalyze, 3);
            grid.Children.Add(btnAnalyze);

            container.Children.Add(grid);
        }

        private static (string displayType, string color) GetIndicatorTypeBadge(IndicatorType type, string entry)
        {
            return type switch
            {
                IndicatorType.Ip => entry.Contains(':') ? ("IP6", DraculaColors.Orange) : ("IP", DraculaColors.Cyan),
                IndicatorType.InternalIp => ("INT", "#74b9ff"),
                IndicatorType.Hash => entry.Length switch
                {
                    64 => ("SHA256", DraculaColors.Purple),
                    56 => ("SHA224", DraculaColors.Purple),
                    40 => ("SHA1", DraculaColors.Purple),
                    _ => ("MD5", DraculaColors.Purple),
                },
                IndicatorType.Url => ("URL", DraculaColors.Green),
                IndicatorType.Email => ("EMAIL", DraculaColors.Pink),
                IndicatorType.Domain => ("DOMAIN", DraculaColors.Cyan),
                IndicatorType.Mac => ("MAC", "#a29bfe"),
                IndicatorType.Cve => ("CVE", DraculaColors.Orange),
                IndicatorType.PComputer => ("PC", "#dcd1ff"),
                IndicatorType.HostPort => ("HOST", DraculaColors.Cyan),
                _ => ("?", "#888888")
            };
        }
    }
}
