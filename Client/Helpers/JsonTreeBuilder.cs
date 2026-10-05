using System.Collections.Generic;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace CSOToolbox.Client.Helpers;

public static class JsonTreeBuilder
{
    public static List<TreeViewItem> BuildJsonTree(JsonElement element, string keyName)
    {
        var items = new List<TreeViewItem>();

        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                {
                    var objNode = new TreeViewItem();
                    objNode.Header = BuildJsonHeader(keyName, "{…}", "#bd93f9", "#888888");
                    objNode.IsExpanded = true;
                    objNode.Tag = element;

                    foreach (var prop in element.EnumerateObject())
                    {
                        var childItems = BuildJsonTree(prop.Value, prop.Name);
                        foreach (var child in childItems) objNode.Items.Add(child);
                    }
                    items.Add(objNode);
                    break;
                }
            case JsonValueKind.Array:
                {
                    var arrNode = new TreeViewItem();
                    arrNode.Header = BuildJsonHeader(keyName, $"[{element.GetArrayLength()} items]", "#8be9fd", "#888888");
                    arrNode.IsExpanded = false;
                    arrNode.Tag = element;

                    int idx = 0;
                    foreach (var child in element.EnumerateArray())
                    {
                        var childItems = BuildJsonTree(child, $"[{idx}]");
                        foreach (var ci in childItems) arrNode.Items.Add(ci);
                        idx++;
                    }
                    items.Add(arrNode);
                    break;
                }
            default:
                {
                    var leafNode = new TreeViewItem { IsExpanded = false };
                    string valStr;
                    string valColor;
                    switch (element.ValueKind)
                    {
                        case JsonValueKind.String:
                            valStr = $"\"{element.GetString()}\"";
                            valColor = "#f1fa8c";
                            break;
                        case JsonValueKind.Number:
                            valStr = element.GetRawText();
                            valColor = "#50fa7b";
                            break;
                        case JsonValueKind.True:
                        case JsonValueKind.False:
                            valStr = element.GetRawText();
                            valColor = "#ffb86c";
                            break;
                        case JsonValueKind.Null:
                            valStr = "null";
                            valColor = "#ff5555";
                            break;
                        default:
                            valStr = element.GetRawText();
                            valColor = "#E0E0E0";
                            break;
                    }
                    leafNode.Header = BuildJsonLeafHeader(keyName, valStr, valColor);
                    leafNode.Tag = element;
                    items.Add(leafNode);
                    break;
                }
        }
        return items;
    }

    public static StackPanel BuildJsonHeader(string key, string typeBadge, string keyColor, string badgeColor)
    {
        var sp = new StackPanel { Orientation = Avalonia.Layout.Orientation.Horizontal, Spacing = 6 };
        sp.Children.Add(new TextBlock
        {
            Text = key,
            FontWeight = FontWeight.SemiBold,
            Foreground = Brush.Parse(keyColor),
            FontFamily = FontFamily.Parse("avares://Client/Resources/Inconsolata-Regular.ttf#Inconsolata"),
            FontSize = 14,
            VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center
        });
        sp.Children.Add(new TextBlock
        {
            Text = typeBadge,
            Foreground = Brush.Parse(badgeColor),
            FontFamily = FontFamily.Parse("avares://Client/Resources/Inconsolata-Regular.ttf#Inconsolata"),
            FontSize = 14,
            VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center
        });
        return sp;
    }

    public static StackPanel BuildJsonLeafHeader(string key, string value, string valueColor)
    {
        var sp = new StackPanel { Orientation = Avalonia.Layout.Orientation.Horizontal, Spacing = 6 };
        sp.Children.Add(new TextBlock
        {
            Text = key + ":",
            Foreground = Brush.Parse("#E0E0E0"),
            FontFamily = FontFamily.Parse("avares://Client/Resources/Inconsolata-Regular.ttf#Inconsolata"),
            FontSize = 14,
            VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center
        });
        sp.Children.Add(new TextBlock
        {
            Text = value,
            Foreground = Brush.Parse(valueColor),
            FontFamily = FontFamily.Parse("avares://Client/Resources/Inconsolata-Regular.ttf#Inconsolata"),
            FontSize = 14,
            VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center
        });
        return sp;
    }

    public static bool IsAllExpanded(TreeViewItem item)
    {
        if (item.Items.Count == 0) return true;
        if (!item.IsExpanded) return false;
        foreach (var child in item.Items)
            if (child is TreeViewItem childTvi && !IsAllExpanded(childTvi))
                return false;
        return true;
    }

    public static void SetTreeViewExpanded(TreeViewItem item, bool expanded)
    {
        item.IsExpanded = expanded;
        foreach (var child in item.Items)
        {
            if (child is TreeViewItem childTvi) SetTreeViewExpanded(childTvi, expanded);
        }
    }
}
