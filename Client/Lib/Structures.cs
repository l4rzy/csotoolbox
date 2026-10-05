using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using Avalonia.Media;

namespace CSOToolbox.Client.Lib
{
    public enum CsoInputSource
    {
        User = 0,
        Clipboard = 1,
        SelectedIndicator = 2,
        PastedText = 3,
        AnalyzerSwitch = 4
    }

    public enum IndicatorType
    {
        Unknown = 0,
        Ip = 1,
        InternalIp = 2,
        Hash = 3,
        Url = 4,
        Mac = 5,
        Cve = 6,
        Base64 = 7,
        User = 8,
        PComputer = 9,
        Domain = 10,
        Email = 11,
        HostPort = 12
    }

    public enum AnalyzerType
    {
        AbuseIpDb,
        VirusTotal,
        Rdns,
        Dns,
        Whois,
        Mac,
        Circl,
        Shodan,
        Base64,
        NetUser,
        Ocr,
        Rdap,
        Scamalytics,
        Bazaar,
        ThreatFox,
        Unknown
    }

    public static class AnalyzerMap
    {
        public static readonly Dictionary<AnalyzerType, string> AnalyzerToString = new()
        {
            { AnalyzerType.AbuseIpDb, "abuseipdb" },
            { AnalyzerType.VirusTotal, "virustotal" },
            { AnalyzerType.Rdns, "rdns" },
            { AnalyzerType.Dns, "dns" },
            { AnalyzerType.Whois, "whois" },
            { AnalyzerType.Rdap, "rdap" },
            { AnalyzerType.Mac, "mac" },
            { AnalyzerType.Circl, "circl" },
            { AnalyzerType.Shodan, "shodan" },
            { AnalyzerType.Base64, "base64" },
            { AnalyzerType.NetUser, "netuser" },
            { AnalyzerType.Ocr, "ocr" },
            { AnalyzerType.Scamalytics, "scamalytics" },
            { AnalyzerType.Bazaar, "bazaar" },
            { AnalyzerType.ThreatFox, "threatfox" },
            { AnalyzerType.Unknown, "unknown" },
        };

        public static string ToStringValue(AnalyzerType type)
        {
            if (AnalyzerToString.TryGetValue(type, out var val))
            {
                return val;
            }
            return "unknown";
        }

        public static readonly Dictionary<IndicatorType, string> IndicatorTypeDisplayNames = new()
        {
            { IndicatorType.Ip, "IP Address" },
            { IndicatorType.InternalIp, "Internal IP" },
            { IndicatorType.Hash, "Hash" },
            { IndicatorType.Url, "URL" },
            { IndicatorType.Domain, "Domain" },
            { IndicatorType.Email, "Email" },
            { IndicatorType.Mac, "MAC Address" },
            { IndicatorType.Cve, "CVE" },
            { IndicatorType.Base64, "Base64" },
            { IndicatorType.User, "Username" },
            { IndicatorType.PComputer, "Computer Name" },
            { IndicatorType.HostPort, "Host:Port" },
        };

        public static string GetIndicatorTypeDisplayName(IndicatorType type)
        {
            if (IndicatorTypeDisplayNames.TryGetValue(type, out var name))
                return name;
            return type.ToString();
        }

        public static readonly Dictionary<IndicatorType, List<AnalyzerType>> AvailableAnalyzers = new()
        {
            { IndicatorType.Ip, new List<AnalyzerType> { AnalyzerType.AbuseIpDb, AnalyzerType.VirusTotal, AnalyzerType.Rdns, AnalyzerType.Rdap, AnalyzerType.Scamalytics, AnalyzerType.ThreatFox } },
            { IndicatorType.InternalIp, new List<AnalyzerType> { AnalyzerType.Rdns } },
            { IndicatorType.Hash, new List<AnalyzerType> { AnalyzerType.VirusTotal, AnalyzerType.Bazaar, AnalyzerType.ThreatFox } },
            { IndicatorType.Url, new List<AnalyzerType> { AnalyzerType.VirusTotal, AnalyzerType.Dns, AnalyzerType.Whois, AnalyzerType.Rdap, AnalyzerType.ThreatFox } },
            { IndicatorType.Domain, new List<AnalyzerType> { AnalyzerType.VirusTotal, AnalyzerType.Dns, AnalyzerType.Whois, AnalyzerType.Rdap, AnalyzerType.ThreatFox } },
            { IndicatorType.Email, new List<AnalyzerType> { AnalyzerType.Dns, AnalyzerType.Whois, AnalyzerType.Rdap } },
            { IndicatorType.Mac, new List<AnalyzerType> { AnalyzerType.Mac } },
            { IndicatorType.Cve, new List<AnalyzerType> { AnalyzerType.Circl, AnalyzerType.Shodan } },
            { IndicatorType.Base64, new List<AnalyzerType> { AnalyzerType.Base64 } },
            { IndicatorType.User, new List<AnalyzerType> { AnalyzerType.NetUser } },
            { IndicatorType.PComputer, new List<AnalyzerType> { AnalyzerType.Dns } },
            { IndicatorType.HostPort, new List<AnalyzerType> { AnalyzerType.VirusTotal, AnalyzerType.Dns, AnalyzerType.Whois, AnalyzerType.Rdap, AnalyzerType.ThreatFox } },
            { IndicatorType.Unknown, new List<AnalyzerType>() }
        };

        public static readonly Dictionary<IndicatorType, AnalyzerType> DefaultAnalyzers = new()
        {
            { IndicatorType.Ip, AnalyzerType.AbuseIpDb },
            { IndicatorType.InternalIp, AnalyzerType.Rdns },
            { IndicatorType.Hash, AnalyzerType.Bazaar },
            { IndicatorType.Url, AnalyzerType.VirusTotal },
            { IndicatorType.Domain, AnalyzerType.Whois },

            { IndicatorType.Mac, AnalyzerType.Mac },
            { IndicatorType.Cve, AnalyzerType.Circl },
            { IndicatorType.Base64, AnalyzerType.Base64 },
            { IndicatorType.User, AnalyzerType.NetUser },
            { IndicatorType.PComputer, AnalyzerType.Dns },
            { IndicatorType.Email, AnalyzerType.Dns },
            { IndicatorType.HostPort, AnalyzerType.ThreatFox },
        };

        public static readonly Dictionary<AnalyzerType, IndicatorType> PrimaryIndicatorType = new()
        {
            { AnalyzerType.AbuseIpDb, IndicatorType.Ip },
            { AnalyzerType.VirusTotal, IndicatorType.Hash },
            { AnalyzerType.Rdns, IndicatorType.InternalIp },
            { AnalyzerType.Dns, IndicatorType.Domain },
            { AnalyzerType.Whois, IndicatorType.Domain },

            { AnalyzerType.Mac, IndicatorType.Mac },
            { AnalyzerType.Circl, IndicatorType.Cve },
            { AnalyzerType.Shodan, IndicatorType.Cve },
            { AnalyzerType.Base64, IndicatorType.Base64 },
            { AnalyzerType.NetUser, IndicatorType.User },
            { AnalyzerType.Rdap, IndicatorType.Ip },
            { AnalyzerType.Ocr, IndicatorType.Unknown },
            { AnalyzerType.Scamalytics, IndicatorType.Ip },
            { AnalyzerType.Bazaar, IndicatorType.Hash },
            { AnalyzerType.ThreatFox, IndicatorType.Hash },
        };

        public static readonly Dictionary<string, string> SourceColors = new()
        {
            { "abuseipdb", "#ff8787" },
            { "virustotal", "#a8e6cf" },
            { "whois", "#ffb088" },
            { "bazaar", "#f8a5c2" },
            { "threatfox", "#82ccdd" },
            { "rdap", "#74b9ff" },
            { "cve", "#fff5c6" },
            { "circl", "#fff5c6" },
            { "circl.lu", "#fff5c6" },
            { "shodan", "#fff5c6" },
            { "dns", "#bffffc" },
            { "rdns", "#81ecec" },
            { "pcomputer", "#dcd1ff" },
            { "mac", "#a29bfe" },
            { "netuser", "#ffe0b2" },
            { "ocr", "#f5f6fa" },
            { "indicators", "#cfd8dc" },
            { "base64", "#98ddca" },
        };

        public static readonly Dictionary<AnalyzerType, string> SourceDisplayNames = new()
        {
            { AnalyzerType.AbuseIpDb, "AbuseIPDB" },
            { AnalyzerType.Scamalytics, "Scamalytics" },
            { AnalyzerType.Bazaar, "MalwareBazaar" },
            { AnalyzerType.VirusTotal, "VirusTotal" },
            { AnalyzerType.Circl, "CVE database" },
            { AnalyzerType.Shodan, "CVE database" },
            { AnalyzerType.Whois, "WHOIS" },
            { AnalyzerType.Rdap, "RDAP" },
            { AnalyzerType.Dns, "DNS" },
            { AnalyzerType.Rdns, "rDNS" },
            { AnalyzerType.ThreatFox, "ThreatFox" },
        };

        public static string GetDisplayName(AnalyzerType type)
            => SourceDisplayNames.TryGetValue(type, out var name) ? name : type.ToString();
    }

    // --- AbuseIPDB Models ---
    public class AbuseReport
    {
        [JsonPropertyName("reportedAt")] public string ReportedAt { get; set; } = "";
        [JsonPropertyName("comment")] public string? Comment { get; set; }
        [JsonPropertyName("categories")] public List<int> Categories { get; set; } = new();
        [JsonPropertyName("reporterId")] public int? ReporterId { get; set; }
        [JsonPropertyName("reporterCountryCode")] public string? ReporterCountryCode { get; set; }
        [JsonPropertyName("reporterCountryName")] public string? ReporterCountryName { get; set; }
    }

    public class AbuseDataObject
    {
        [JsonPropertyName("ipAddress")] public string IpAddress { get; set; } = "";
        [JsonPropertyName("isPublic")] public bool IsPublic { get; set; }
        [JsonPropertyName("ipVersion")] public int IpVersion { get; set; }
        [JsonPropertyName("abuseConfidenceScore")] public int AbuseConfidenceScore { get; set; }
        [JsonPropertyName("countryCode")] public string? CountryCode { get; set; }
        [JsonPropertyName("usageType")] public string? UsageType { get; set; }
        [JsonPropertyName("isp")] public string? Isp { get; set; }
        [JsonPropertyName("domain")] public string? Domain { get; set; }
        [JsonPropertyName("hostnames")] public List<string>? Hostnames { get; set; }
        [JsonPropertyName("isTor")] public bool IsTor { get; set; }
        [JsonPropertyName("totalReports")] public int TotalReports { get; set; }
        [JsonPropertyName("numDistinctUsers")] public int NumDistinctUsers { get; set; }
        [JsonPropertyName("lastReportedAt")] public string? LastReportedAt { get; set; }
        [JsonPropertyName("reports")] public List<AbuseReport>? Reports { get; set; }
    }

    public class AbuseObject
    {
        [JsonPropertyName("data")] public AbuseDataObject? Data { get; set; }
    }

    // --- VirusTotal Models ---
    public class VTLastAnalysisStats
    {
        [JsonPropertyName("harmless")] public int Harmless { get; set; }
        [JsonPropertyName("suspicious")] public int Suspicious { get; set; }
        [JsonPropertyName("timeout")] public int Timeout { get; set; }
        [JsonPropertyName("malicious")] public int Malicious { get; set; }
        [JsonPropertyName("undetected")] public int Undetected { get; set; }
    }

    public class VTSignatureInfo
    {
        [JsonPropertyName("product")] public string? Product { get; set; }
        [JsonPropertyName("verified")] public string? Verified { get; set; }
        [JsonPropertyName("description")] public string? Description { get; set; }
        [JsonPropertyName("file_version")] public string? FileVersion { get; set; }
        [JsonPropertyName("signing_date")] public string? SigningDate { get; set; }
        [JsonPropertyName("signers")] public string? Signers { get; set; }
    }

    public class VTAttributes
    {
        [JsonPropertyName("type_description")] public string? TypeDescription { get; set; }
        [JsonPropertyName("names")] public List<string>? Names { get; set; }
        [JsonPropertyName("signature_info")] public VTSignatureInfo? SignatureInfo { get; set; }
        [JsonPropertyName("size")] public long? Size { get; set; }
        [JsonPropertyName("meaningful_name")] public string? MeaningfulName { get; set; }
        [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
        [JsonPropertyName("sha1")] public string? Sha1 { get; set; }
        [JsonPropertyName("md5")] public string? Md5 { get; set; }
        [JsonPropertyName("magic")] public string? Magic { get; set; }
        [JsonPropertyName("last_analysis_stats")] public VTLastAnalysisStats? LastAnalysisStats { get; set; }
        [JsonPropertyName("reputation")] public int? Reputation { get; set; }

        // IP Attributes
        [JsonPropertyName("asn")] public int? Asn { get; set; }
        [JsonPropertyName("as_owner")] public string? AsOwner { get; set; }
        [JsonPropertyName("network")] public string? Network { get; set; }

        // Domain Attributes
        [JsonPropertyName("registrar")] public string? Registrar { get; set; }
        [JsonPropertyName("creation_date")] public long? CreationDate { get; set; }
        [JsonPropertyName("expiration_date")] public long? ExpirationDate { get; set; }
        [JsonPropertyName("last_update_date")] public long? LastUpdateDate { get; set; }
        [JsonPropertyName("categories")] public Dictionary<string, string>? Categories { get; set; }

        // URL Attributes
        [JsonPropertyName("url")] public string? Url { get; set; }
        [JsonPropertyName("last_http_response_code")] public int? LastHttpResponseCode { get; set; }
        [JsonPropertyName("last_http_response_content_length")] public long? LastHttpResponseContentLength { get; set; }
        [JsonPropertyName("title")] public string? Title { get; set; }
        [JsonPropertyName("times_submitted")] public int? TimesSubmitted { get; set; }
    }

    public class VTItem
    {
        [JsonPropertyName("attributes")] public VTAttributes Attributes { get; set; } = new();
        [JsonPropertyName("type")] public string? Type { get; set; }
        [JsonPropertyName("id")] public string? Id { get; set; }
    }

    public class VTLinks
    {
        [JsonPropertyName("self")] public string? Self { get; set; }
    }

    public class VirusTotalObject
    {
        [JsonPropertyName("data")] public List<VTItem> Data { get; set; } = new();
        [JsonPropertyName("links")] public VTLinks? Links { get; set; }
    }


    public class TunnelError
    {
        [JsonPropertyName("type")] public string? Type { get; set; }
        [JsonPropertyName("message")] public string? Message { get; set; }
        [JsonIgnore] public int ServerHttpStatusCode { get; set; }
    }

    public class TunnelOptions
    {
        [JsonPropertyName("force")] public bool Force { get; set; }
        [JsonPropertyName("reverse")] public bool? Reverse { get; set; }
        [JsonPropertyName("use_custom_dns")] public bool? UseCustomDns { get; set; }
    }

    // --- Common CVE Model (used by CIRCL, Shodan, and other CVE analyzers) ---
    public class CveAccess
    {
        [JsonPropertyName("authentication")] public string? Authentication { get; set; }
        [JsonPropertyName("complexity")] public string? Complexity { get; set; }
        [JsonPropertyName("vector")] public string? Vector { get; set; }
    }

    public class CveImpact
    {
        [JsonPropertyName("availability")] public string? Availability { get; set; }
        [JsonPropertyName("confidentiality")] public string? Confidentiality { get; set; }
        [JsonPropertyName("integrity")] public string? Integrity { get; set; }
    }

    public class CommonCVEObject
    {
        // Common fields (both CIRCL and Shodan provide)
        [JsonPropertyName("id")] public string? Id { get; set; }
        [JsonPropertyName("Published")] public string? Published { get; set; }
        [JsonPropertyName("summary")] public string? Summary { get; set; }
        [JsonPropertyName("cvss")] public double? Cvss { get; set; }
        [JsonPropertyName("assigner")] public string? Assigner { get; set; }

        // CIRCL-only (optional)
        [JsonPropertyName("Modified")] public string? Modified { get; set; }
        [JsonPropertyName("access")] public CveAccess? Access { get; set; }
        [JsonPropertyName("impact")] public CveImpact? Impact { get; set; }

        // Shodan-specific (optional)
        [JsonPropertyName("epss")] public double? Epss { get; set; }
        [JsonPropertyName("kev")] public bool? Kev { get; set; }
        [JsonPropertyName("ransomware_campaign")] public string? RansomwareCampaign { get; set; }
        [JsonPropertyName("references")] public List<string>? References { get; set; }
        [JsonPropertyName("cpes")] public List<string>? Cpes { get; set; }
    }

    public class IPDBObject
    {
        [JsonPropertyName("found")] public bool Found { get; set; }
        [JsonPropertyName("ip")] public string Ip { get; set; } = "";
        [JsonPropertyName("cidr")] public string Cidr { get; set; } = "";
        [JsonPropertyName("usage")] public string Usage { get; set; } = "";
        [JsonPropertyName("location")] public string Location { get; set; } = "";
        [JsonPropertyName("comment")] public string Comment { get; set; } = "";
    }

    public class DnsRecord
    {
        [JsonPropertyName("type")] public string Type { get; set; } = "";
        [JsonPropertyName("value")] public string Value { get; set; } = "";
    }

    public class DnsObject
    {
        [JsonPropertyName("host")] public string Host { get; set; } = "";
        [JsonPropertyName("nameservers")] public List<string> Nameservers { get; set; } = new();
        [JsonPropertyName("isResolvable")] public bool IsResolvable { get; set; }
        [JsonPropertyName("reverse")] public bool Reverse { get; set; }
        [JsonPropertyName("ipdb")] public IPDBObject? Ipdb { get; set; }
        [JsonPropertyName("records")] public List<DnsRecord> Records { get; set; } = new();
    }

    public class ScamalyticsProxy
    {
        [JsonPropertyName("is_datacenter")] public bool IsDatacenter { get; set; }
        [JsonPropertyName("is_vpn")] public bool IsVpn { get; set; }
        [JsonPropertyName("is_apple_icloud_private_relay")] public bool IsAppleIcloudPrivateRelay { get; set; }
        [JsonPropertyName("is_amazon_aws")] public bool IsAmazonAws { get; set; }
        [JsonPropertyName("is_google")] public bool IsGoogle { get; set; }
    }

    public class ScamalyticsData
    {
        [JsonPropertyName("status")] public string Status { get; set; } = "";
        [JsonPropertyName("mode")] public string Mode { get; set; } = "";
        [JsonPropertyName("ip")] public string Ip { get; set; } = "";
        [JsonPropertyName("scamalytics_score")] public int Score { get; set; }
        [JsonPropertyName("scamalytics_risk")] public string Risk { get; set; } = "";
        [JsonPropertyName("scamalytics_url")] public string Url { get; set; } = "";
        [JsonPropertyName("scamalytics_isp")] public string Isp { get; set; } = "";
        [JsonPropertyName("scamalytics_org")] public string Org { get; set; } = "";
        [JsonPropertyName("scamalytics_isp_score")] public int IspScore { get; set; }
        [JsonPropertyName("scamalytics_isp_risk")] public string IspRisk { get; set; } = "";
        [JsonPropertyName("scamalytics_proxy")] public ScamalyticsProxy? Proxy { get; set; }
    }

    public class GeoIPData
    {
        [JsonPropertyName("asn")] public string Asn { get; set; } = "";
        [JsonPropertyName("as_name")] public string AsName { get; set; } = "";
        [JsonPropertyName("ip_geoname_id")] public string GeoNameId { get; set; } = "";
        [JsonPropertyName("ip_location_accuracy_km")] public string LocationAccuracy { get; set; } = "";
        [JsonPropertyName("ip_country_code")] public string CountryCode { get; set; } = "";
        [JsonPropertyName("ip_state_name")] public string StateName { get; set; } = "";
        [JsonPropertyName("ip_district_name")] public string DistrictName { get; set; } = "";
        [JsonPropertyName("ip_city")] public string City { get; set; } = "";
        [JsonPropertyName("ip_metro_code")] public string MetroCode { get; set; } = "";
        [JsonPropertyName("ip_postcode")] public string Postcode { get; set; } = "";
        [JsonPropertyName("ip_geolocation")] public string GeoLocation { get; set; } = "";
        [JsonPropertyName("ip_country_name")] public string CountryName { get; set; } = "";
        [JsonPropertyName("ip_time_zone")] public string TimeZone { get; set; } = "";
        [JsonPropertyName("datasource_name")] public string DatasourceName { get; set; } = "";
        [JsonPropertyName("license_info")] public string LicenseInfo { get; set; } = "";
        [JsonPropertyName("last_updated_timestamp_utc")] public string LastUpdated { get; set; } = "";
        [JsonPropertyName("isp_name")] public string IspName { get; set; } = "";
        [JsonPropertyName("org_name")] public string OrgName { get; set; } = "";
        [JsonPropertyName("domain")] public string Domain { get; set; } = "";
        [JsonPropertyName("ip_continent_code")] public string ContinentCode { get; set; } = "";
        [JsonPropertyName("ip_continent_name")] public string ContinentName { get; set; } = "";
        [JsonPropertyName("ip_range_from")] public string RangeFrom { get; set; } = "";
        [JsonPropertyName("ip_range_to")] public string RangeTo { get; set; } = "";
        [JsonPropertyName("as_domain")] public string AsDomain { get; set; } = "";
        [JsonPropertyName("connection_type")] public string ConnectionType { get; set; } = "";
    }

    public class SecurityBlacklists
    {
        [JsonPropertyName("ip2proxy")] public bool Ip2Proxy { get; set; }
        [JsonPropertyName("firehol")] public bool Firehol { get; set; }
        [JsonPropertyName("ipsum")] public bool Ipsum { get; set; }
        [JsonPropertyName("spamhaus")] public bool Spamhaus { get; set; }
        [JsonPropertyName("spambot")] public bool Spambot { get; set; }
    }

    public class SecurityProxies
    {
        [JsonPropertyName("is_datacenter")] public bool IsDatacenter { get; set; }
        [JsonPropertyName("is_vpn")] public bool IsVpn { get; set; }
        [JsonPropertyName("is_tor")] public bool IsTor { get; set; }
        [JsonPropertyName("proxy_type")] public string ProxyType { get; set; } = "";
        [JsonPropertyName("usage_type")] public string UsageType { get; set; } = "";
    }

    public class SecurityData
    {
        [JsonPropertyName("is_blacklisted_external")] public bool IsBlacklistedExternal { get; set; }
        [JsonPropertyName("blacklists")] public SecurityBlacklists? Blacklists { get; set; }
        [JsonPropertyName("proxies")] public SecurityProxies? Proxies { get; set; }
    }

    public class ScamalyticsObject
    {
        [JsonPropertyName("scamalytics")] public ScamalyticsData? Data { get; set; }
        [JsonPropertyName("geoip")] public GeoIPData? GeoIP { get; set; }
        [JsonPropertyName("security")] public SecurityData? Security { get; set; }
    }

    // --- Bazaar (MalwareBazaar) Models ---
    public class BazaarObject
    {
        [JsonPropertyName("sha256_hash")] public string? Sha256 { get; set; }
        [JsonPropertyName("sha1_hash")] public string? Sha1 { get; set; }
        [JsonPropertyName("md5_hash")] public string? Md5 { get; set; }
        [JsonPropertyName("file_name")] public string? FileName { get; set; }
        [JsonPropertyName("file_size")] public long FileSize { get; set; }
        [JsonPropertyName("file_type_mime")] public string? FileTypeMime { get; set; }
        [JsonPropertyName("file_type")] public string? FileType { get; set; }
        [JsonPropertyName("signature")] public string? Signature { get; set; }
        [JsonPropertyName("delivery_method")] public string? DeliveryMethod { get; set; }
        [JsonPropertyName("first_seen")] public string? FirstSeen { get; set; }
        [JsonPropertyName("last_seen")] public string? LastSeen { get; set; }
        [JsonPropertyName("comment")] public string? Comment { get; set; }
        [JsonPropertyName("tags")] public List<string>? Tags { get; set; }
        [JsonPropertyName("vendor_intel")] public Dictionary<string, JsonElement>? VendorIntel { get; set; }
    }

    public class ThreatFoxObject
    {
        [JsonPropertyName("ioc_type")] public string IocType { get; set; } = "";
        [JsonPropertyName("results")] public List<ThreatFoxResult> Results { get; set; } = new();
    }

    public class ThreatFoxResult
    {
        [JsonPropertyName("id")] public string Id { get; set; } = "";
        [JsonPropertyName("ioc")] public string Ioc { get; set; } = "";
        [JsonPropertyName("threat_type")] public string? ThreatType { get; set; }
        [JsonPropertyName("threat_type_desc")] public string? ThreatTypeDesc { get; set; }
        [JsonPropertyName("ioc_type")] public string? IocType { get; set; }
        [JsonPropertyName("ioc_type_desc")] public string? IocTypeDesc { get; set; }
        [JsonPropertyName("malware")] public string? Malware { get; set; }
        [JsonPropertyName("malware_printable")] public string? MalwarePrintable { get; set; }
        [JsonPropertyName("malware_alias")] public string? MalwareAlias { get; set; }
        [JsonPropertyName("malware_malpedia")] public string? MalwareMalpedia { get; set; }
        [JsonPropertyName("confidence_level")] public int ConfidenceLevel { get; set; }
        [JsonPropertyName("first_seen")] public string? FirstSeen { get; set; }
        [JsonPropertyName("last_seen")] public string? LastSeen { get; set; }
        [JsonPropertyName("reporter")] public string? Reporter { get; set; }
        [JsonPropertyName("reference")] public string? Reference { get; set; }
        [JsonPropertyName("tags")] public List<string>? Tags { get; set; }
        [JsonPropertyName("comment")] public string? Comment { get; set; }
    }

    public class ServerHealthObject
    {
        [JsonIgnore]
        public bool IsOperational => Health == "ok" && string.IsNullOrEmpty(ErrorMessage);

        [JsonPropertyName("health")]
        public string Health { get; set; } = "";

        [JsonPropertyName("version")]
        public string Version { get; set; } = "";

        [JsonPropertyName("ocr_backend")]
        public string OcrBackend { get; set; } = "";

        [JsonPropertyName("service_timeout")]
        public int ServiceTimeout { get; set; }

        [JsonIgnore]
        public string ErrorMessage { get; set; } = "";
    }

    public class TunnelRequestV1
    {
        [JsonPropertyName("payload")] public string? Payload { get; set; }
        [JsonPropertyName("options")] public TunnelOptions? Options { get; set; }
    }

    public class TunnelResponseV1
    {
        [JsonPropertyName("metadata")]
        public TunnelResponseV1Metadata? Metadata { get; set; }
        [JsonPropertyName("payload")] public object? Payload { get; set; }
        [JsonPropertyName("error")] public TunnelError? Error { get; set; }
    }

    public class TunnelResponseV1Metadata
    {
        [JsonPropertyName("version")] public string Version { get; set; } = "";
        [JsonPropertyName("cached")] public bool Cached { get; set; }
    }

    public class WhoisObject
    {
        [JsonPropertyName("domain_name")] public string DomainName { get; set; } = "";
        [JsonPropertyName("registrar")] public string Registrar { get; set; } = "";
        [JsonPropertyName("registrar_iana_id")] public string RegistrarIanaId { get; set; } = "";
        [JsonPropertyName("registrar_url")] public string RegistrarUrl { get; set; } = "";
        [JsonPropertyName("registry_domain_id")] public string RegistryDomainId { get; set; } = "";
        [JsonPropertyName("registrant")] public string Registrant { get; set; } = "";
        [JsonPropertyName("registrant_name")] public string RegistrantName { get; set; } = "";
        [JsonPropertyName("registrant_email")] public string RegistrantEmail { get; set; } = "";
        [JsonPropertyName("registrant_phone")] public string RegistrantPhone { get; set; } = "";
        [JsonPropertyName("admin_org")] public string AdminOrg { get; set; } = "";
        [JsonPropertyName("admin_name")] public string AdminName { get; set; } = "";
        [JsonPropertyName("admin_email")] public string AdminEmail { get; set; } = "";
        [JsonPropertyName("admin_phone")] public string AdminPhone { get; set; } = "";
        [JsonPropertyName("tech_org")] public string TechOrg { get; set; } = "";
        [JsonPropertyName("tech_name")] public string TechName { get; set; } = "";
        [JsonPropertyName("tech_email")] public string TechEmail { get; set; } = "";
        [JsonPropertyName("tech_phone")] public string TechPhone { get; set; } = "";
        [JsonPropertyName("created_date")] public string CreatedDate { get; set; } = "";
        [JsonPropertyName("expiration_date")] public string ExpirationDate { get; set; } = "";
        [JsonPropertyName("updated_date")] public string UpdatedDate { get; set; } = "";
        [JsonPropertyName("abuse_email")] public string AbuseEmail { get; set; } = "";
        [JsonPropertyName("abuse_phone")] public string AbusePhone { get; set; } = "";
        [JsonPropertyName("dnssec")] public string Dnssec { get; set; } = "";
        [JsonPropertyName("statuses")] public List<string> Statuses { get; set; } = new();
        [JsonPropertyName("nameservers")] public List<string> Nameservers { get; set; } = new();
    }

    public class OcrResult
    {
        [JsonPropertyName("text")] public string Text { get; set; } = "";
    }

    public class MacVendorResult
    {
        [JsonPropertyName("vendor")] public string Vendor { get; set; } = "";
    }

    public class RdapEvent
    {
        [JsonPropertyName("action")] public string Action { get; set; } = "";
        [JsonPropertyName("date")] public string Date { get; set; } = "";
    }

    public class RdapEntity
    {
        [JsonPropertyName("handle")] public string Handle { get; set; } = "";
        [JsonPropertyName("roles")] public List<string> Roles { get; set; } = new();
        [JsonPropertyName("fn")] public string Fn { get; set; } = "";
        [JsonPropertyName("email")] public string Email { get; set; } = "";
        [JsonPropertyName("tel")] public string Tel { get; set; } = "";
        [JsonPropertyName("adr")] public string Adr { get; set; } = "";
    }

    public class RdapNameServer
    {
        [JsonPropertyName("ldh_name")] public string LdhName { get; set; } = "";
    }

    public class RdapResult
    {
        [JsonPropertyName("handle")] public string Handle { get; set; } = "";
        [JsonPropertyName("ldh_name")] public string? LdhName { get; set; }
        [JsonPropertyName("unicode_name")] public string? UnicodeName { get; set; }
        [JsonPropertyName("ip_version")] public string? IpVersion { get; set; }
        [JsonPropertyName("start_address")] public string? StartAddress { get; set; }
        [JsonPropertyName("end_address")] public string? EndAddress { get; set; }
        [JsonPropertyName("name")] public string? Name { get; set; }
        [JsonPropertyName("type")] public string? Type { get; set; }
        [JsonPropertyName("country")] public string? Country { get; set; }
        [JsonPropertyName("statuses")] public List<string> Statuses { get; set; } = new();
        [JsonPropertyName("events")] public List<RdapEvent> Events { get; set; } = new();
        [JsonPropertyName("entities")] public List<RdapEntity> Entities { get; set; } = new();
        [JsonPropertyName("nameservers")] public List<RdapNameServer>? Nameservers { get; set; }
        [JsonPropertyName("cidrs")] public List<string>? Cidrs { get; set; }
        [JsonPropertyName("port43")] public string? Port43 { get; set; }
        [JsonPropertyName("secure_dns")] public bool? SecureDns { get; set; }
    }

    [JsonSerializable(typeof(AbuseObject))]
    [JsonSerializable(typeof(VirusTotalObject))]
    [JsonSerializable(typeof(CommonCVEObject))]
    [JsonSerializable(typeof(TunnelRequestV1))]
    [JsonSerializable(typeof(TunnelOptions))]
    [JsonSerializable(typeof(Dictionary<string, List<string>>))]
    [JsonSerializable(typeof(IPDBObject))]
    [JsonSerializable(typeof(DnsObject))]
    [JsonSerializable(typeof(WhoisObject))]
    [JsonSerializable(typeof(List<string>))]
    [JsonSerializable(typeof(Dictionary<string, string>))]
    [JsonSerializable(typeof(DnsRecord))]
    [JsonSerializable(typeof(List<DnsRecord>))]
    [JsonSerializable(typeof(OcrResult))]
    [JsonSerializable(typeof(MacVendorResult))]
    [JsonSerializable(typeof(TunnelError))]
    [JsonSerializable(typeof(TunnelResponseV1))]
    [JsonSerializable(typeof(TunnelResponseV1Metadata))]
    [JsonSerializable(typeof(ScamalyticsObject))]
    [JsonSerializable(typeof(string))]
    [JsonSerializable(typeof(JsonElement))]
    [JsonSerializable(typeof(RdapResult))]
    [JsonSerializable(typeof(BazaarObject))]
    [JsonSerializable(typeof(ThreatFoxObject))]
    [JsonSerializable(typeof(ThreatFoxResult))]
    [JsonSerializable(typeof(CSOToolbox.Client.Helpers.UpdateCheckResult))]
    [JsonSerializable(typeof(ServerHealthObject))]
    public partial class SourceGenerationContext : JsonSerializerContext
    {
    }

    public static class AnalyzerTypeParser
    {
        public static AnalyzerType Parse(string? value)
        {
            if (string.IsNullOrEmpty(value)) return AnalyzerType.Unknown;
            return value.ToLower().Trim() switch
            {
                "abuseipdb" => AnalyzerType.AbuseIpDb,
                "virustotal" => AnalyzerType.VirusTotal,
                "rdns" => AnalyzerType.Rdns,
                "dns" => AnalyzerType.Dns,
                "whois" => AnalyzerType.Whois,
                "mac" => AnalyzerType.Mac,
                "circl.lu" => AnalyzerType.Circl,
                "circl" => AnalyzerType.Circl,
                "shodan" => AnalyzerType.Shodan,
                "base64" => AnalyzerType.Base64,
                "netuser" => AnalyzerType.NetUser,
                "ocr" => AnalyzerType.Ocr,
                "rdap" => AnalyzerType.Rdap,
                "scamalytics" => AnalyzerType.Scamalytics,
                "bazaar" => AnalyzerType.Bazaar,
                "threatfox" => AnalyzerType.ThreatFox,
                _ => AnalyzerType.Unknown
            };
        }
    }

    public static class AppConstants
    {
        public const string SslCertificateHash = GeneratedCertificatePin.Sha256;
        public static bool SslPinningDisabled = false;
    }

    public class AnalyzerOption
    {
        public AnalyzerType Type { get; set; }
        public string Name { get; set; } = "";
        public IImage? Icon { get; set; }
    }

}
