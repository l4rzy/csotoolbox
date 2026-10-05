using System;
using System.IO;
using Microsoft.Extensions.Logging;

namespace CSOToolbox.Client.Lib;

public sealed class LogTabLoggerProvider : ILoggerProvider
{
    private readonly Action<string, string, LogLevel> _onLog;

    public LogTabLoggerProvider(Action<string, string, LogLevel> onLog) => _onLog = onLog;

    public ILogger CreateLogger(string categoryName) => new LogTabLogger(categoryName, _onLog);

    public void Dispose() { }
}

internal sealed class LogTabLogger : ILogger
{
    private readonly string _categoryName;
    private readonly Action<string, string, LogLevel> _onLog;

    internal static string _consoleLogLevel = "OFF";

    private static readonly string? _logDir = CreateLogDir();

    public LogTabLogger(string categoryName, Action<string, string, LogLevel> onLog)
    {
        _categoryName = categoryName;
        _onLog = onLog;
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

    public bool IsEnabled(LogLevel logLevel)
    {
        if (logLevel >= LogLevel.Warning)
            return true;
        return IsConsoleEnabled(logLevel);
    }

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        var message = formatter(state, exception);
        if (exception != null)
            message = $"{message}: {exception.Message}";

        var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
        var levelStr = logLevel.ToString().ToUpper();

        if (logLevel >= LogLevel.Warning)
            _onLog(ExtractCompartment(_categoryName), message, logLevel);

        if (IsConsoleEnabled(logLevel))
        {
            var output = $"[{timestamp}] [{levelStr}] [{_categoryName}] {message}";
            Console.WriteLine(output);
            AppendToLogFile(output);
        }
    }

    internal static string ExtractCompartment(string categoryName)
    {
        var lastDot = categoryName.LastIndexOf('.');
        var className = lastDot >= 0 ? categoryName[(lastDot + 1)..] : categoryName;
        return className switch
        {
            "CsoIndicatorExtractor" => "classifier",
            "CsoWorker" => "worker",
            "CsoConfig" => "config",
            "CsoState" => "state",
            "MainWindow" => "ui",
            _ => className.ToLowerInvariant()
        };
    }

    private static string? CreateLogDir()
    {
        try
        {
            var dir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
            Directory.CreateDirectory(dir);
            return dir;
        }
        catch
        {
            return null;
        }
    }

    private void AppendToLogFile(string line)
    {
        if (_logDir == null) return;
        try
        {
            var path = Path.Combine(_logDir, $"app-{DateTime.Now:yyyy-MM-dd}.log");
            File.AppendAllText(path, line + Environment.NewLine);
        }
        catch { }
    }

    private bool IsConsoleEnabled(LogLevel logLevel)
    {
        return _consoleLogLevel switch
        {
            "WARNING" => logLevel >= LogLevel.Warning,
            "INFORMATION" => logLevel >= LogLevel.Information,
            "DEBUG" => true,
            _ => false
        };
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();
        public void Dispose() { }
    }
}
