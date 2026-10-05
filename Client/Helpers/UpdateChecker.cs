using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using CSOToolbox.Client.Lib;

namespace CSOToolbox.Client.Helpers;

public class UpdateCheckResult
{
    [JsonPropertyName("update_available")]
    public bool UpdateAvailable { get; set; }

    [JsonPropertyName("version")]
    public string? Version { get; set; }

    [JsonPropertyName("release_notes")]
    public string? ReleaseNotes { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }

    [JsonPropertyName("filename")]
    public string? Filename { get; set; }

    [JsonPropertyName("sha256")]
    public string? Sha256 { get; set; }

    [JsonPropertyName("size")]
    public long Size { get; set; }
}

public static class UpdateChecker
{
    private static readonly HttpClient _http;

    static UpdateChecker()
    {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = FormatHelpers.ValidateCsoServerCertificate;

        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        _http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", FormatHelpers.ClientUserAgent);
    }

    public static async Task<UpdateCheckResult?> CheckForUpdateAsync(string serverUrl, string platform, string currentVersion)
    {
        try
        {
            var url = $"{serverUrl.TrimEnd('/')}/api/v1/update/check/{platform}/{currentVersion}";
            using var resp = await _http.GetAsync(url);
            if (!resp.IsSuccessStatusCode) return null;
            var json = await resp.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize(json, SourceGenerationContext.Default.UpdateCheckResult);
        }
        catch
        {
            return null;
        }
    }

    public static async Task<string?> DownloadUpdateAsync(
        string serverUrl, string platform, string filename,
        long fileSize, IProgress<int>? progress = null, CancellationToken ct = default)
    {
        try
        {
            var url = $"{serverUrl.TrimEnd('/')}/api/v1/download/{platform}";
            // Stream the download to disk to optimize memory footprint
            using var resp = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!resp.IsSuccessStatusCode) return null;

            var tempPath = Path.Combine(Path.GetTempPath(), filename ?? "csotoolbox-update");
            using var fs = File.Create(tempPath);
            using var stream = await resp.Content.ReadAsStreamAsync(ct);
            var buffer = new byte[8192];
            long totalRead = 0;
            int read;
            while ((read = await stream.ReadAsync(buffer, ct)) > 0)
            {
                await fs.WriteAsync(buffer.AsMemory(0, read), ct);
                totalRead += read;
                if (fileSize > 0)
                    progress?.Report((int)(totalRead * 100 / fileSize));
            }
            return tempPath;
        }
        catch
        {
            return null;
        }
    }

    public static void ApplyUpdateAndRestart(string newBinaryPath)
    {
        var currentExe = Environment.ProcessPath!;
        var exeName = Path.GetFileNameWithoutExtension(currentExe);
        if (exeName.Equals("dotnet", StringComparison.OrdinalIgnoreCase) ||
            currentExe.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}Debug{Path.DirectorySeparatorChar}") ||
            currentExe.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}Release{Path.DirectorySeparatorChar}"))
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[SAFEGUARD] Development/Debug mode detected.");
            Console.WriteLine($"[SAFEGUARD] Skipping update replacement to prevent overwriting development binaries.");
            Console.WriteLine($"[SAFEGUARD] Simulated updating: '{newBinaryPath}' -> '{currentExe}'");
            Console.ResetColor();
            return;
        }
        var currentDir = Path.GetDirectoryName(currentExe)!;
        var targetExe = Path.Combine(currentDir, Path.GetFileName(currentExe)!);
        var backupExe = Path.Combine(currentDir, exeName + ".old.exe");

        // Pre-extract archive natively to a Guid-named temp directory
        var tempUnpackDir = Path.Combine(Path.GetTempPath(), "csotoolbox-unpacked-" + Guid.NewGuid().ToString("N"));
        try
        {
            if (Directory.Exists(tempUnpackDir))
                Directory.Delete(tempUnpackDir, true);
            Directory.CreateDirectory(tempUnpackDir);

            if (newBinaryPath.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                ZipFile.ExtractToDirectory(newBinaryPath, tempUnpackDir, overwriteFiles: true);
            }
            else
            {
                // Fallback copy for raw binary updates (if any)
                var tempFile = Path.Combine(tempUnpackDir, Path.GetFileName(currentExe));
                File.Copy(newBinaryPath, tempFile, true);
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[Error] Unpacking update failed: {ex.Message}");
            Console.ResetColor();
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            var batPath = Path.Combine(Path.GetTempPath(), "csotoolbox-update.bat");
            // Windows batch script to backup, extract, run new binary, wait 5 seconds, and rollback if needed
            var script = $"@echo off\r\n" +
                         $"timeout /t 2 /nobreak >nul\r\n" +
                         $"move /Y \"{targetExe}\" \"{backupExe}\"\r\n" +
                         $"xcopy /Y /E /H /Q \"{tempUnpackDir}\\*\" \"{currentDir}\\\"\r\n" +
                         $"start \"\" \"{targetExe}\"\r\n" +
                         $"timeout /t 5 /nobreak >nul\r\n" +
                         $"tasklist /FI \"IMAGENAME eq {Path.GetFileName(targetExe)}\" 2>NUL | find /I /N \"{Path.GetFileName(targetExe)}\">NUL\r\n" +
                         $"if \"%ERRORLEVEL%\"==\"0\" (\r\n" +
                         $"    rem Success - keep old backup without deleting it\r\n" +
                         $") else (\r\n" +
                         $"    copy /Y \"{backupExe}\" \"{targetExe}\"\r\n" +
                         $"    start \"\" \"{targetExe}\"\r\n" +
                         $")\r\n" +
                         $"rd /S /Q \"{tempUnpackDir}\"\r\n" +
                         $"del \"{newBinaryPath}\"\r\n" +
                         $"del \"%~f0\"\r\n";
            File.WriteAllText(batPath, script);
            Process.Start(new ProcessStartInfo(batPath)
            {
                UseShellExecute = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            });
        }
        else
        {
            var shPath = Path.Combine(Path.GetTempPath(), "csotoolbox-update.sh");
            // Linux/macOS bash script to backup, copy, run new binary, wait 5 seconds, and rollback if needed
            var script = $"#!/bin/bash\n" +
                         $"sleep 2\n" +
                         $"mv -f \"{targetExe}\" \"{backupExe}\"\n" +
                         $"cp -rf \"{tempUnpackDir}\"/* \"{currentDir}\"/\n" +
                         $"chmod +x \"{targetExe}\"\n" +
                         $"nohup \"{targetExe}\" > /dev/null 2>&1 &\n" +
                         $"NEW_PID=$!\n" +
                         $"sleep 5\n" +
                         $"if kill -0 $NEW_PID 2>/dev/null; then\n" +
                         $"    # Success - keep old backup without deleting it\n" +
                         $"    true\n" +
                         $"else\n" +
                         $"    wait $NEW_PID\n" +
                         $"    EXIT_CODE=$?\n" +
                         $"    if [ $EXIT_CODE -ne 0 ]; then\n" +
                         $"        mv -f \"{backupExe}\" \"{targetExe}\"\n" +
                         $"        nohup \"{targetExe}\" > /dev/null 2>&1 &\n" +
                         $"    fi\n" +
                         $"\tfi\n" +
                         $"rm -rf \"{tempUnpackDir}\"\n" +
                         $"rm -f \"{newBinaryPath}\"\n" +
                         $"rm -f \"$0\"\n";
            File.WriteAllText(shPath, script);
            if (OperatingSystem.IsLinux())
                Process.Start("chmod", $"+x \"{shPath}\"")?.WaitForExit();
            Process.Start(new ProcessStartInfo(shPath)
            {
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Hidden
            });
        }

        Environment.Exit(0);
    }

    public static string GetCurrentVersionString()
    {
        var v = Assembly.GetExecutingAssembly().GetName().Version;
        return v != null ? v.ToString(v.Revision == 0 ? 3 : 4) : "0.1.0";
    }

    public static string GetDisplayVersionString()
    {
        var version = GetCurrentVersionString();
#if RELEASE_CHANNEL_PROD
        return $"{version}.PROD";
#else
        return $"{version}.DEV";
#endif
    }

    public static string GetCurrentPlatform()
    {
        if (OperatingSystem.IsWindows()) return "win-x64";
        if (OperatingSystem.IsLinux()) return "linux-x64";
        if (OperatingSystem.IsMacOS()) return "osx-arm64";
        throw new PlatformNotSupportedException();
    }

    public static bool VerifyHash(string path, string expectedSha256)
    {
        try
        {
            using var sha = SHA256.Create();
            using var fs = File.OpenRead(path);
            var hash = Convert.ToHexStringLower(sha.ComputeHash(fs));
            return string.Equals(hash, expectedSha256, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}
