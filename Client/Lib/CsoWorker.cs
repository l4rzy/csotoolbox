using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using CSOToolbox.Client.Helpers;

namespace CSOToolbox.Client.Lib
{
    public class CsoWorker : IAnalysisClient
    {
        private readonly CsoConfig _config;
        private readonly HttpClient _httpClient;
        private readonly ILogger<CsoWorker> _logger;
        private bool _disposed;

        private volatile int _backendTimeoutSeconds = 5;
        private readonly bool _disposeHttpClient;


        private class TunnelAnalyzerDescriptor
        {
            public JsonTypeInfo JsonTypeInfo { get; }
            public Func<string, object?, object?>? Transformer { get; }
            public Func<string, bool, IndicatorType, TunnelOptions>? OptionsFactory { get; }
            public Func<TunnelError, object?>? ErrorFactory { get; }

            public TunnelAnalyzerDescriptor(
                JsonTypeInfo jsonTypeInfo,
                Func<string, object?, object?>? transformer = null,
                Func<string, bool, IndicatorType, TunnelOptions>? optionsFactory = null,
                Func<TunnelError, object?>? errorFactory = null)
            {
                JsonTypeInfo = jsonTypeInfo;
                Transformer = transformer;
                OptionsFactory = optionsFactory;
                ErrorFactory = errorFactory;
            }
        }

        private class LocalAnalyzerDescriptor
        {
            public Func<CsoWorker, string, Task<object?>> Processor { get; }

            public LocalAnalyzerDescriptor(Func<CsoWorker, string, Task<object?>> processor)
            {
                Processor = processor;
            }
        }

        private static readonly Dictionary<AnalyzerType, LocalAnalyzerDescriptor> LocalRegistry = new()
        {
            { AnalyzerType.NetUser, new LocalAnalyzerDescriptor(async (worker, payload) => await worker.QueryNetUserAsync(payload)) },
            { AnalyzerType.Base64, new LocalAnalyzerDescriptor((worker, payload) => Task.FromResult<object?>(worker.QueryBase64(payload))) }
        };

        private static readonly Dictionary<AnalyzerType, TunnelAnalyzerDescriptor> TunnelRegistry = new()
        {
            { AnalyzerType.VirusTotal, new TunnelAnalyzerDescriptor(SourceGenerationContext.Default.VirusTotalObject) },
            { AnalyzerType.AbuseIpDb, new TunnelAnalyzerDescriptor(SourceGenerationContext.Default.AbuseObject) },
            { AnalyzerType.Rdap, new TunnelAnalyzerDescriptor(SourceGenerationContext.Default.RdapResult) },
            { AnalyzerType.Circl, new TunnelAnalyzerDescriptor(SourceGenerationContext.Default.CommonCVEObject, (payload, result) => (result is CommonCVEObject cve && !string.IsNullOrEmpty(cve.Id)) ? cve : null) },
            { AnalyzerType.Shodan, new TunnelAnalyzerDescriptor(SourceGenerationContext.Default.CommonCVEObject, (payload, result) => (result is CommonCVEObject cve && !string.IsNullOrEmpty(cve.Id)) ? cve : null) },
            { AnalyzerType.Whois, new TunnelAnalyzerDescriptor(SourceGenerationContext.Default.WhoisObject) },
            { AnalyzerType.Scamalytics, new TunnelAnalyzerDescriptor(SourceGenerationContext.Default.ScamalyticsObject) },
            { AnalyzerType.Dns, new TunnelAnalyzerDescriptor(SourceGenerationContext.Default.DnsObject,
                optionsFactory: (payload, force, indicator) => new TunnelOptions { Reverse = false, Force = force, UseCustomDns = indicator != IndicatorType.PComputer }) },
            { AnalyzerType.Rdns, new TunnelAnalyzerDescriptor(SourceGenerationContext.Default.DnsObject,
                optionsFactory: (payload, force, indicator) => new TunnelOptions { Reverse = true, Force = force, UseCustomDns = indicator != IndicatorType.PComputer }) },
            { AnalyzerType.Bazaar, new TunnelAnalyzerDescriptor(SourceGenerationContext.Default.BazaarObject) },
            { AnalyzerType.ThreatFox, new TunnelAnalyzerDescriptor(SourceGenerationContext.Default.ThreatFoxObject) },
            { AnalyzerType.Mac, new TunnelAnalyzerDescriptor(SourceGenerationContext.Default.MacVendorResult) },
            { AnalyzerType.Ocr, new TunnelAnalyzerDescriptor(SourceGenerationContext.Default.OcrResult) }
        };

        public event Action<string, string, string, object?>? JobCompleted;

        public void SetTimeout(int seconds) => _backendTimeoutSeconds = Math.Max(5, seconds);

        public CsoWorker(CsoConfig config, ILogger<CsoWorker> logger) : this(config, logger, null)
        {
        }

        public CsoWorker(CsoConfig config, ILogger<CsoWorker> logger, HttpClient? httpClient)
        {
            _config = config;
            _logger = logger;
            if (httpClient == null)
            {
                var handler = new HttpClientHandler();
                handler.ServerCertificateCustomValidationCallback = FormatHelpers.ValidateCsoServerCertificate;

                _httpClient = new HttpClient(handler);
                _disposeHttpClient = true;
            }
            else
            {
                _httpClient = httpClient;
                _disposeHttpClient = false;
            }

            _httpClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", FormatHelpers.ClientUserAgent);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_disposeHttpClient)
            {
                _httpClient.Dispose();
            }
        }

        public void Run(string jobId, AnalyzerType[] analyzers, string queryText, bool force = false, CancellationToken ct = default, IndicatorType indicatorType = IndicatorType.Unknown)
        {
            _logger.LogDebug("Trying to run {Analyzers} with text = '{Text}' (force={Force})",
                string.Join(", ", analyzers), queryText, force);
            foreach (var target in analyzers)
            {
                Task.Run(async () =>
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        var result = await QueryServiceAsync(target, queryText, force, ct, indicatorType);
                        JobCompleted?.Invoke(jobId, AnalyzerMap.ToStringValue(target), queryText, result);
                    }
                    catch (OperationCanceledException)
                    {
                        _logger.LogDebug("Task cancelled for {Target} (id={Id})", target, jobId);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error running task {Target}", target);
                        JobCompleted?.Invoke(jobId, AnalyzerMap.ToStringValue(target), queryText, null);
                    }
                }, ct);
            }
        }

        public async Task<TunnelResponseV1?> QueryServiceAsync(AnalyzerType analyzer, string payload, bool force = false, CancellationToken ct = default, IndicatorType indicatorType = IndicatorType.Unknown)
        {
            if (LocalRegistry.ContainsKey(analyzer))
            {
                return await CallLocalProcessorAsync(analyzer, payload);
            }

            if (TunnelRegistry.TryGetValue(analyzer, out var descriptor))
            {
                var service = analyzer == AnalyzerType.Rdns ? "dns" : AnalyzerMap.ToStringValue(analyzer);
                var options = descriptor.OptionsFactory != null
                    ? descriptor.OptionsFactory(payload, force, indicatorType)
                    : new TunnelOptions { Force = force };

                var response = await CallBackendTunnelAsync(service, payload, options, descriptor.JsonTypeInfo, ct);
                if (response == null) return null;

                if (response.Error != null)
                {
                    return response;
                }

                if (descriptor.Transformer != null && response.Payload != null)
                {
                    response.Payload = descriptor.Transformer(payload, response.Payload);
                }
                return response;
            }

            _logger.LogWarning("Unhandled analyzer type: {Target}", analyzer);
            return null;
        }

        private async Task<TunnelResponseV1?> CallLocalProcessorAsync(AnalyzerType analyzer, string payload)
        {
            if (LocalRegistry.TryGetValue(analyzer, out var descriptor))
            {
                try
                {
                    var result = await descriptor.Processor(this, payload);
                    if (result is TunnelResponseV1 tr) return tr;
                    return new TunnelResponseV1 { Payload = result };
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Local processor {Target} threw an exception", analyzer);
                    return new TunnelResponseV1
                    {
                        Error = new TunnelError
                        {
                            Type = "LocalProcessorError",
                            Message = $"Local execution failed: {ex.Message}",
                            ServerHttpStatusCode = 500
                        }
                    };
                }
            }

            _logger.LogWarning("Unhandled local analyzer type: {Target}", analyzer);
            return null;
        }

        // Sends a request to the backend /tunnel endpoint and returns a typed, deserialized result or an error.
        private async Task<TunnelResponseV1?> CallBackendTunnelAsync(
            string service,
            string payload,
            TunnelOptions options,
            JsonTypeInfo typeInfo,
            CancellationToken ct = default)
        {
            var tunnelUrl = _config.GetTunnelString();
            if (string.IsNullOrEmpty(tunnelUrl))
            {
                return new TunnelResponseV1 { Error = new TunnelError { Type = "ConnectionError", Message = "Backend server URL is not configured." } };
            }

            var cleanedUrl = tunnelUrl.TrimEnd('/');
            var targetUrl = $"{cleanedUrl}/api/v1/tunnel/{service}";

            var content = new StringContent(
                JsonSerializer.Serialize(
                    new TunnelRequestV1 { Payload = payload, Options = options },
                    SourceGenerationContext.Default.TunnelRequestV1),
                Encoding.UTF8, "application/json");

            string? responseBody = null;
            bool timedOut = false;
            int statusCode = 0;

            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(_backendTimeoutSeconds));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
            try
            {
                _logger.LogInformation("Sending backend request: service={Service}, url={Url}", service, targetUrl);
                using var response = await _httpClient.PostAsync(targetUrl, content, linkedCts.Token);
                statusCode = (int)response.StatusCode;
                _logger.LogInformation("Backend responded HTTP {StatusCode} for {Service}", statusCode, service);
                responseBody = await response.Content.ReadAsStringAsync(linkedCts.Token);
            }
            catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
            {
                _logger.LogWarning("Backend request timed out after {Timeout}s", _backendTimeoutSeconds);
                timedOut = true;
            }
            catch (OperationCanceledException)
            {
                _logger.LogDebug("Backend request cancelled");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Backend network error");
                return new TunnelResponseV1 { Error = new TunnelError { Type = "ConnectionError", Message = "Backend server is not reachable.", ServerHttpStatusCode = 0 } };
            }

            return await HandleBackendResponseAsync(service, payload, responseBody, timedOut, statusCode, typeInfo);
        }

        private async Task<TunnelResponseV1?> HandleBackendResponseAsync(
            string service,
            string payload,
            string? responseBody,
            bool timedOut,
            int statusCode,
            JsonTypeInfo typeInfo)
        {
            // --- Response handling ---
            if (timedOut)
            {
                return new TunnelResponseV1 { Error = new TunnelError { Type = "TimeoutError", Message = $"Request timed out after {_backendTimeoutSeconds}s for '{service}'. Increase the timeout in Preferences > General > Backend Timeout, or try again later.", ServerHttpStatusCode = 0 } };
            }

            if (string.IsNullOrEmpty(responseBody))
            {
                return new TunnelResponseV1 { Error = new TunnelError { Type = "ConnectionError", Message = $"Backend server returned an empty response for '{service}'.", ServerHttpStatusCode = 0 } };
            }

            try
            {
                using var doc = JsonDocument.Parse(responseBody);
                var root = doc.RootElement;

                TunnelError? error = null;
                TunnelResponseV1Metadata? metadata = null;
                object? payloadObj = null;

                if (root.TryGetProperty("error", out var errorEl) && errorEl.ValueKind != JsonValueKind.Null)
                    error = (TunnelError?)JsonSerializer.Deserialize(errorEl, SourceGenerationContext.Default.TunnelError);

                if (root.TryGetProperty("metadata", out var metaEl) && metaEl.ValueKind != JsonValueKind.Null)
                    metadata = (TunnelResponseV1Metadata?)JsonSerializer.Deserialize(metaEl, SourceGenerationContext.Default.TunnelResponseV1Metadata);

                if (root.TryGetProperty("payload", out var payloadEl) && payloadEl.ValueKind != JsonValueKind.Null)
                    payloadObj = JsonSerializer.Deserialize(payloadEl, typeInfo);

                var response = new TunnelResponseV1 { Metadata = metadata, Payload = payloadObj, Error = error };

                _logger.LogInformation("Backend response deserialized for {Service}", service);

                if (response.Error != null)
                {
                    response.Error.ServerHttpStatusCode = statusCode;
                    return response;
                }

                if (response.Payload == null && response.Error == null)
                    _logger.LogWarning("Backend returned success but null payload for service {Service}", service);

                _logger.LogDebug("Payload deserialized as {PayloadType} for {Service}", typeInfo.Type.Name, service);

                return response;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Deserialize error for service {Service}", service);
                return new TunnelResponseV1 { Error = new TunnelError { Type = "ParseError", Message = $"Failed to parse backend response: {ex.Message}", ServerHttpStatusCode = statusCode } };
            }
        }

        public async Task<ServerHealthObject> CheckServerHealth(CancellationToken ct = default)
        {
            var baseUrl = _config.GetTunnelString();
            if (string.IsNullOrEmpty(baseUrl))
                return new ServerHealthObject { ErrorMessage = "Backend server URL is not configured." };

            var healthUrl = $"{baseUrl.TrimEnd('/')}/api/v1/health";

            try
            {
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(_backendTimeoutSeconds));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

                using var response = await _httpClient.GetAsync(healthUrl, linkedCts.Token);
                if (response.IsSuccessStatusCode)
                {
                    var responseBody = await response.Content.ReadAsStringAsync(linkedCts.Token);
                    try
                    {
                        var serverHealth = JsonSerializer.Deserialize(responseBody, SourceGenerationContext.Default.ServerHealthObject);
                        if (serverHealth != null)
                            return serverHealth;
                    }
                    catch
                    {
                        _logger.LogWarning("Failed to parse health endpoint JSON response");
                    }
                    return new ServerHealthObject { ErrorMessage = $"Health endpoint returned unexpected response: {responseBody}" };
                }
                return new ServerHealthObject { ErrorMessage = $"Health endpoint returned HTTP {response.StatusCode}." };
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return new ServerHealthObject { ErrorMessage = "Backend server health check was cancelled." };
            }
            catch (OperationCanceledException)
            {
                return new ServerHealthObject { ErrorMessage = $"Backend server health check timed out (> {_backendTimeoutSeconds}s)." };
            }
            catch (Exception ex)
            {
                return new ServerHealthObject { ErrorMessage = $"Backend server is unreachable ({ex.Message})." };
            }
        }

        private async Task<string> QueryNetUserAsync(string user)
        {
            if (!OperatingSystem.IsWindows())
                return "Net user lookup is only available on Windows.";

            try
            {
                using var proc = new System.Diagnostics.Process();
                proc.StartInfo.FileName = "net.exe";
                proc.StartInfo.ArgumentList.Add("user");
                proc.StartInfo.ArgumentList.Add(user);
                proc.StartInfo.ArgumentList.Add("/domain");
                proc.StartInfo.RedirectStandardOutput = true;
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.CreateNoWindow = true;
                proc.Start();

                var output = await proc.StandardOutput.ReadToEndAsync();
                await proc.WaitForExitAsync();
                return output;
            }
            catch (Exception ex)
            {
                return $"Error executing net user: {ex.Message}";
            }
        }

        private string? QueryBase64(string b64)
        {
            try
            {
                var data = Convert.FromBase64String(b64);
                return Encoding.UTF8.GetString(data);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Base64 decode error");
                return null;
            }
        }

    }
}
