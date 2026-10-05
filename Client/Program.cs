using Avalonia;
using System;
using System.Text.Json;

namespace CSOToolbox.Client;

class Program
{
    public static event Action<string[]>? ArgumentsReceived;

    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
    // yet and stuff might break.
    [STAThread]
    public static void Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--run-tests")
        {
            try
            {
                Lib.TestRunner.RunTests();
                Environment.Exit(0);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Tests failed: {ex.Message}");
                Environment.Exit(1);
            }
            return;
        }

        // Single-instance named pipe check
        if (TrySendToExistingInstance(args))
        {
            return;
        }

        StartNamedPipeServer();

        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    private static bool TrySendToExistingInstance(string[] args)
    {
        try
        {
            using var client = new System.IO.Pipes.NamedPipeClientStream(".", "CSOToolboxSingleInstancePipe", System.IO.Pipes.PipeDirection.Out);
            client.Connect(200); // 200ms timeout
            using var writer = new System.IO.StreamWriter(client);
            writer.Write(JsonSerializer.Serialize(args));
            writer.Flush();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void StartNamedPipeServer()
    {
        System.Threading.Tasks.Task.Run(() =>
        {
            while (true)
            {
                try
                {
                    using var server = new System.IO.Pipes.NamedPipeServerStream("CSOToolboxSingleInstancePipe", System.IO.Pipes.PipeDirection.In);
                    server.WaitForConnection();
                    using var reader = new System.IO.StreamReader(server);
                    var argsStr = reader.ReadToEnd();
                    var args = JsonSerializer.Deserialize<string[]>(argsStr) ?? Array.Empty<string>();

                    Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                    {
                        ArgumentsReceived?.Invoke(args);
                    });
                }
                catch
                {
                    System.Threading.Thread.Sleep(100);
                }
            }
        });
    }

    // Avalonia configuration, don't remove; also used by visual designer.
    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
