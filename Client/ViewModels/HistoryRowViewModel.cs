using System;
namespace CSOToolbox.Client.ViewModels;

public class HistoryRowViewModel
{
    public string TimeDisplay { get; set; } = "";
    public string Source { get; set; } = "";
    public string DataDisplay { get; set; } = "";
    public string OriginalData { get; set; } = "";
    public string SourceColor { get; set; } = "#E0E0E0";
}
