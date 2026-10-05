using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CSOToolbox.Client.Lib
{
    public class MockAnalysisClient : IAnalysisClient
    {
        public event Action<string, string, string, object?>? JobCompleted;

        private int _backendTimeoutSeconds = 5;

        public void SetTimeout(int seconds) => _backendTimeoutSeconds = seconds;

        public void Run(string jobId, AnalyzerType[] analyzers, string queryText, bool force = false, CancellationToken ct = default, IndicatorType indicatorType = IndicatorType.Unknown)
        {
            foreach (var target in analyzers)
            {
                Task.Run(async () =>
                {
                    await Task.Delay(100, ct); // simulate minimal latency
                    if (ct.IsCancellationRequested) return;

                    var result = await QueryServiceAsync(target, queryText, force, ct, indicatorType);
                    JobCompleted?.Invoke(jobId, AnalyzerMap.ToStringValue(target), queryText, result);
                }, ct);
            }
        }

        public async Task<TunnelResponseV1?> QueryServiceAsync(AnalyzerType analyzer, string payload, bool force = false, CancellationToken ct = default, IndicatorType indicatorType = IndicatorType.Unknown)
        {
            await Task.Delay(50, ct); // simulate network request latency
            if (ct.IsCancellationRequested) return null;

            var innerResult = analyzer switch
            {
                AnalyzerType.VirusTotal => (object)new VirusTotalObject
                {
                    Data = new List<VTItem>
                    {
                        new VTItem
                        {
                            Attributes = new VTAttributes
                            {
                                TypeDescription = "Mocked File Description",
                                MeaningfulName = "mock_file.exe",
                                LastAnalysisStats = new VTLastAnalysisStats
                                {
                                    Malicious = 0,
                                    Harmless = 70
                                }
                            }
                        }
                    }
                },
                AnalyzerType.AbuseIpDb => new AbuseObject
                {
                    Data = new AbuseDataObject
                    {
                        IpAddress = payload,
                        AbuseConfidenceScore = 15,
                        TotalReports = 2,
                        IsPublic = true,
                        CountryCode = "NL"
                    }
                },
                AnalyzerType.Circl => new CommonCVEObject
                {
                    Id = payload,
                    Summary = "Mocked CIRCL CVE summary"
                },
                AnalyzerType.Shodan => new CommonCVEObject
                {
                    Id = payload,
                    Summary = "Mocked Shodan CVE summary"
                },
                AnalyzerType.NetUser => $"[netuser] Mocked command output for: {payload}",
                AnalyzerType.Base64 => "Mocked decoded base64 string",
                AnalyzerType.Dns => new DnsObject
                {
                    Host = payload,
                    Nameservers = new List<string> { "1.1.1.1" },
                    IsResolvable = true
                },
                AnalyzerType.Rdns => new DnsObject
                {
                    Host = payload,
                    Nameservers = new List<string> { "1.1.1.1" },
                    IsResolvable = true
                },
                AnalyzerType.Whois => new WhoisObject
                {
                    DomainName = payload,
                    Registrar = "Mock Registrar",
                    CreatedDate = "2026-06-20",
                    ExpirationDate = "2027-06-20",
                    UpdatedDate = "2026-06-20",
                    AbuseEmail = "abuse@mockregistrar.com"
                },
                AnalyzerType.Rdap => new RdapResult
                {
                    Handle = "MOCK-HANDLE",
                    LdhName = "example.com",
                    Statuses = new List<string> { "client transfer prohibited", "ok" },
                    Events = new List<RdapEvent>
                    {
                        new RdapEvent { Action = "registration", Date = "2024-01-01T00:00:00Z" },
                        new RdapEvent { Action = "expiration", Date = "2026-01-01T00:00:00Z" },
                    },
                    Entities = new List<RdapEntity>
                    {
                        new RdapEntity { Handle = "MOCK-REG", Roles = new List<string> { "registrar" }, Fn = "Mock Registrar Inc." },
                        new RdapEntity { Handle = "MOCK-ABUSE", Roles = new List<string> { "abuse" }, Email = "abuse@mockregistrar.com", Tel = "+1.555.555.5555" },
                    },
                    Nameservers = new List<RdapNameServer>
                    {
                        new RdapNameServer { LdhName = "ns1.mockdomain.com" },
                        new RdapNameServer { LdhName = "ns2.mockdomain.com" },
                    },
                },
                AnalyzerType.Scamalytics => new ScamalyticsObject
                {
                    Data = new ScamalyticsData
                    {
                        Ip = payload,
                        Score = 10,
                        Risk = "low"
                    }
                },
                AnalyzerType.Bazaar => new BazaarObject
                {
                    Sha256 = payload,
                    FileName = "mock_sample.exe",
                    FileSize = 123456,
                    FileTypeMime = "application/x-dosexec",
                    Signature = "MockMalware",
                    Tags = new List<string> { "mock", "test" },
                },
                AnalyzerType.Mac => new MacVendorResult { Vendor = "Mock Vendor" },
                AnalyzerType.Ocr => new OcrResult
                {
                    Text = "Mock OCR Text"
                },
                _ => null
            };

            if (innerResult == null) return null;
            return new TunnelResponseV1 { Payload = innerResult };
        }

        public Task<ServerHealthObject> CheckServerHealth(CancellationToken ct = default)
        {
            return Task.FromResult(new ServerHealthObject
            {
                Health = "ok",
                Version = "mock-1.0.0",
                OcrBackend = "mock-ocr"
            });
        }

        public void Dispose()
        {
        }
    }
}
