using System;
using System.Linq;
using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {

        private async void OnJsonTreeCopyLineClick(object? sender, RoutedEventArgs e)
        {
            if (_treeJsonData?.SelectedItem is not TreeViewItem item) return;
            if (item.Header is not StackPanel sp) return;
            var text = "";
            foreach (var child in sp.Children)
                if (child is TextBlock tb) text += tb.Text;
            await CopyAndNotify(text);
        }

        private async void OnJsonTreeCopyValueClick(object? sender, RoutedEventArgs e)
        {
            if (_treeJsonData?.SelectedItem is not TreeViewItem item) return;
            if (item.Tag is not JsonElement element) return;
            var text = element.ValueKind == JsonValueKind.String
                ? element.GetString() ?? ""
                : element.GetRawText();
            await CopyAndNotify(text);
        }

        private async void OnJsonTreeCopyTreeClick(object? sender, RoutedEventArgs e)
        {
            if (_treeJsonData?.SelectedItem is not TreeViewItem item) return;
            if (item.Tag is not JsonElement element) return;
            await CopyAndNotify(element.GetRawText(), offerAnalysis: false);
        }
        private void OnDataFilterTextChanged(object? sender, TextChangedEventArgs e)
        {
            _dataFilterTimer?.Stop();
            _dataFilterTimer ??= new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(300) };
            _dataFilterTimer.Tick -= OnDataFilterTimerTick;
            _dataFilterTimer.Tick += OnDataFilterTimerTick;
            _dataFilterTimer.Start();
        }

        private void OnDataFilterTimerTick(object? sender, EventArgs e)
        {
            _dataFilterTimer?.Stop();
            _dataFilterTimer!.Tick -= OnDataFilterTimerTick;
            ApplyDataFilter(_txtDataFilter?.Text ?? "");
        }

        private void OnClearDataFilterClick(object? sender, RoutedEventArgs e)
        {
            _dataFilterTimer?.Stop();
            if (_txtDataFilter != null)
                _txtDataFilter.Text = "";
            ApplyDataFilter("");
        }

        private static string GetItemText(TreeViewItem item)
        {
            if (item.Header is StackPanel sp)
                return string.Join(" ", sp.Children.OfType<TextBlock>().Select(tb => tb.Text));
            return item.Header?.ToString() ?? "";
        }

        private bool ApplyFilterVisibility(TreeViewItem item, string filter, bool hasFilter)
        {
            if (!hasFilter)
            {
                item.IsVisible = true;
                foreach (var child in item.Items)
                    if (child is TreeViewItem childTvi)
                        ApplyFilterVisibility(childTvi, filter, hasFilter);
                return false;
            }

            var text = GetItemText(item);
            bool matches = text.Contains(filter, StringComparison.OrdinalIgnoreCase);

            bool anyMatch = false;
            foreach (var child in item.Items)
                if (child is TreeViewItem childTvi && ApplyFilterVisibility(childTvi, filter, hasFilter))
                    anyMatch = true;

            if (matches || anyMatch)
            {
                if (matches && item.Items.Count > 0)
                {
                    item.IsExpanded = true;
                    foreach (var child in item.Items)
                        if (child is TreeViewItem childTvi)
                            SetAllVisible(childTvi);
                }
                item.IsVisible = true;
            }
            else
            {
                item.IsVisible = false;
            }

            return matches || anyMatch;
        }

        private static void SetAllVisible(TreeViewItem item)
        {
            item.IsVisible = true;
            foreach (var child in item.Items)
                if (child is TreeViewItem childTvi)
                    SetAllVisible(childTvi);
        }

        private void ApplyDataFilter(string filterText)
        {
            var tree = _treeJsonData;
            if (tree == null) return;

            bool hasFilter = !string.IsNullOrEmpty(filterText);
            foreach (var item in tree.Items)
                if (item is TreeViewItem tvi)
                    ApplyFilterVisibility(tvi, filterText, hasFilter);
        }
    }
}
