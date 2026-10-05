using System;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace CSOToolbox.Client.Lib
{
    /// <summary>
    /// Classifies text to detect indicator types (IP, hash, URL, CVE, etc.).
    /// <para>This class is <b>not thread-safe</b>. Must only be called from a
    /// single thread (the Avalonia UI thread via Dispatcher).</para>
    /// </summary>
    public class CsoIndicatorExtractor
    {
        private readonly CsoConfig _config;
        private readonly ILogger<CsoIndicatorExtractor> _logger;
        public string LastProcessedInputText { get; private set; } = "";
        public CsoInputSource InputSource { get; private set; }
        public string RawInputText { get; private set; } = "";
        public string PrimaryIndicatorText { get; private set; } = "";
        public int TotalMatchCount { get; private set; }
        public bool CanAutoInsert { get; private set; }
        public bool HasMultipleMatches { get; private set; }
        public bool EnableAutoCorrection { get; private set; } = true;
        public bool WasProcessingSkipped { get; private set; }
        public string StatusMessage { get; private set; } = "";
        public Dictionary<string, List<string>> MatchesByCategory { get; private set; } = new();

        private IndicatorType? _overriddenIndicatorType = null;

        public CsoIndicatorExtractor(CsoConfig config, ILogger<CsoIndicatorExtractor> logger)
        {
            _config = config;
            _logger = logger;
            Reset();
        }

        public void Reset()
        {
            InputSource = CsoInputSource.User;
            RawInputText = "";
            PrimaryIndicatorText = "";
            TotalMatchCount = 0;
            CanAutoInsert = false;
            HasMultipleMatches = false;
            EnableAutoCorrection = true;
            WasProcessingSkipped = false;
            StatusMessage = "";
            MatchesByCategory = new Dictionary<string, List<string>>();
            _overriddenIndicatorType = null;
        }

        public void Process(CsoInputSource source, string text, IndicatorType? explicitIndicatorType = null)
        {
            Reset();
            text = CsoStatelessIndicatorExtractor.Refang(text);
            if (source != CsoInputSource.PastedText && text.Length > _config.GetClipboardMaxLength())
            {
                _logger.LogDebug("Clipboard content too big, skipping");
                WasProcessingSkipped = true;
                StatusMessage = "Content too big!";
                return;
            }

            if (text == LastProcessedInputText && source != CsoInputSource.User && source != CsoInputSource.SelectedIndicator && source != CsoInputSource.PastedText)
            {
                _logger.LogDebug("Processing skipped — input unchanged from last: '{Text}'", text);
                WasProcessingSkipped = true;
                StatusMessage = "Nothing new!";
                return;
            }

            if (string.IsNullOrEmpty(text))
            {
                _logger.LogDebug("Processing skipped — empty input");
                WasProcessingSkipped = true;
                StatusMessage = "Empty input!";
                return;
            }

            InputSource = source;
            LastProcessedInputText = text;

            if (source == CsoInputSource.SelectedIndicator)
            {
                EnableAutoCorrection = false;
                RawInputText = text;
                PrimaryIndicatorText = text;
                CanAutoInsert = true;
                if (explicitIndicatorType.HasValue)
                    _overriddenIndicatorType = explicitIndicatorType.Value;
                return;
            }

            if (source == CsoInputSource.PastedText)
                EnableAutoCorrection = false;

            _logger.LogDebug("Analyzing '{Text}...'", text[..Math.Min(30, text.Length)]);
            RawInputText = text;
            TotalMatchCount = 0;
            var lastOne = "";

            foreach (var def in CsoStatelessIndicatorExtractor.Definitions)
            {
                if (!def.IsSubstringMatch) continue;

                var matches = def.Regex.Matches(RawInputText);
                if (matches.Count == 0) continue;

                var list = new List<string>();
                foreach (Match m in matches)
                {
                    if (def.Validator == null || def.Validator(m.Value))
                    {
                        list.Add(m.Value);
                    }
                }

                if (list.Count > 0)
                {
                    lastOne = list[0];
                    TotalMatchCount += list.Count;
                    MatchesByCategory[def.Key] = list;
                }
            }

            // Hash deduplication — keep only the longest hash type
            string[] hashPriority = { "sha256", "sha224", "sha1", "md5" };
            string? matchedHashType = null;
            foreach (var t in hashPriority)
            {
                if (MatchesByCategory.ContainsKey(t))
                {
                    matchedHashType = t;
                    break;
                }
            }
            if (matchedHashType != null)
            {
                foreach (var t in hashPriority)
                {
                    if (t == matchedHashType) continue;
                    if (MatchesByCategory.Remove(t, out var removed))
                    {
                        TotalMatchCount -= removed.Count;
                    }
                }
                if (MatchesByCategory.TryGetValue(matchedHashType, out var hashList) && hashList.Count > 0)
                    lastOne = hashList[0];
            }

            if (TotalMatchCount > 1)
            {
                HasMultipleMatches = true;
                PrimaryIndicatorText = RawInputText;
                _logger.LogDebug("Complex input: {Keys}", string.Join(", ", MatchesByCategory.Keys));
            }
            else if (TotalMatchCount == 1)
            {
                PrimaryIndicatorText = lastOne;
                CanAutoInsert = true;
            }
            else
            {
                PrimaryIndicatorText = RawInputText;
            }
        }

        public bool HasComplexData() => HasMultipleMatches || RawInputText != PrimaryIndicatorText;

        public IndicatorType GetPrimaryIndicatorType()
        {
            if (_overriddenIndicatorType.HasValue)
                return _overriddenIndicatorType.Value;

            IndicatorType result;
            // Mixed-case hex: both hash and base64 match; mixed case → base64 wins
            if (IsHash() && IsBase64())
                result = CsoStatelessIndicatorExtractor.HasMixedCase(PrimaryIndicatorText) ? IndicatorType.Base64 : IndicatorType.Hash;
            else if (IsInternalIp()) result = IndicatorType.InternalIp;
            else if (IsIp()) result = IndicatorType.Ip;
            else if (IsHash()) result = IndicatorType.Hash;
            else if (IsCve()) result = IndicatorType.Cve;
            else if (IsUrl()) result = IndicatorType.Url;
    else if (IsEmail()) result = IndicatorType.Email;
    else if (IsHostPort()) result = IndicatorType.HostPort;
    else if (IsDomain()) result = IndicatorType.Domain;
            else if (IsMac()) result = IndicatorType.Mac;
            else if (IsBase64()) result = IndicatorType.Base64;
            else if (IsUser()) result = IndicatorType.User;
            else if (IsPComputer()) result = IndicatorType.PComputer;
            else result = IndicatorType.Unknown;

            _logger.LogInformation("Indicator classified as {Type} for '{Text}'", result, PrimaryIndicatorText);
            return result;
        }

        private bool TryParseIp(string text, out IPAddress ip)
        {
            ip = IPAddress.None;
            if (!text.Contains('.') && !text.Contains(':')) return false;
            if (IPAddress.TryParse(text, out var parsedIp))
            {
                ip = parsedIp!;
                return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 || CsoStatelessIndicatorExtractor.IsFullIPv4(text);
            }
            return false;
        }

        public bool IsIp() => TryParseIp(PrimaryIndicatorText, out _);

        public bool IsInternalIp() => TryParseIp(PrimaryIndicatorText, out var ip) && CsoStatelessIndicatorExtractor.IsInternalIPAddress(ip);

        public bool IsHash() => CsoStatelessIndicatorExtractor.Classify(PrimaryIndicatorText) == IndicatorType.Hash;

        public bool IsMac() => CsoStatelessIndicatorExtractor.Classify(PrimaryIndicatorText) == IndicatorType.Mac;

        public bool IsBase64() => CsoStatelessIndicatorExtractor.CheckBase64(RawInputText);

        public bool IsCve()
            => MatchesByCategory.ContainsKey("cve") || CsoStatelessIndicatorExtractor.Classify(PrimaryIndicatorText) == IndicatorType.Cve;

        public bool IsUser() => MatchesByCategory.ContainsKey("user");

        public bool IsPComputer()
            => MatchesByCategory.ContainsKey("pcomputer") || CsoStatelessIndicatorExtractor.Classify(PrimaryIndicatorText) == IndicatorType.PComputer;

        public bool IsUrl()
        {
            if (Uri.TryCreate(PrimaryIndicatorText, UriKind.Absolute, out var uri))
                return uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps;
            return false;
        }

        public bool IsDomain() => CsoStatelessIndicatorExtractor.Classify(PrimaryIndicatorText) == IndicatorType.Domain;

        public bool IsHostPort()
        {
            if (CsoStatelessIndicatorExtractor.Classify(PrimaryIndicatorText) != IndicatorType.HostPort)
                return false;
            // Exclude strings that parse as absolute HTTP/HTTPS URLs
            if (Uri.TryCreate(PrimaryIndicatorText, UriKind.Absolute, out var uri) &&
                (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
                return false;
            return true;
        }

        public bool IsEmail()
            => MatchesByCategory.ContainsKey("email") || CsoStatelessIndicatorExtractor.Classify(PrimaryIndicatorText) == IndicatorType.Email;
    }
}
