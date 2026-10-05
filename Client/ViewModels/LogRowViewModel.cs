using Microsoft.Extensions.Logging;

namespace CSOToolbox.Client.ViewModels;

public class LogRowViewModel
{
    public string TimeDisplay { get; set; } = "";
    public string Compartment { get; set; } = "";
    public string Message { get; set; } = "";
    public string CompartmentColor { get; set; } = "#E0E0E0";
    public LogLevel Level { get; set; } = LogLevel.Information;
}
