using System;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;

namespace CSOToolbox.Client.Lib
{
    public static class CsoStatelessIndicatorExtractor
    {
        private static readonly Dictionary<string, IndicatorType> IndicatorTypeKey = new(StringComparer.OrdinalIgnoreCase)
        {
            { "ipv4", IndicatorType.Ip },
            { "ipv6", IndicatorType.Ip },
            { "internalip", IndicatorType.InternalIp },
            { "hash", IndicatorType.Hash },
            { "sha256", IndicatorType.Hash },
            { "sha224", IndicatorType.Hash },
            { "sha1", IndicatorType.Hash },
            { "md5", IndicatorType.Hash },
            { "url", IndicatorType.Url },
            { "email", IndicatorType.Email },
            { "domain", IndicatorType.Domain },
            { "mac", IndicatorType.Mac },
            { "cve", IndicatorType.Cve },
            { "base64", IndicatorType.Base64 },
            { "pcomputer", IndicatorType.PComputer },
            { "user", IndicatorType.User },
            { "hostport", IndicatorType.HostPort },
        };

        private static readonly Regex Ipv4Regex = new(@"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})", RegexOptions.Compiled);
        private static readonly Regex Ipv6Regex = new(
            @"(?<![0-9a-fA-F])[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){7}(?![0-9a-fA-F])|" +
            @"(?<![0-9a-fA-F])[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,6}::(?:[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,5})?(?![0-9a-fA-F])|" +
            @"(?:(?:^|(?<![0-9a-fA-F])))::[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,6}(?![0-9a-fA-F])|" +
            @"(?:(?:^|(?<![0-9a-fA-F])))::ffff:(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9a-fA-F])|" +
            @"(?<![0-9a-fA-F])[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,5}:((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![0-9a-fA-F])|" +
            @"(?<![0-9a-fA-F])fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}(?![0-9a-fA-F])",
            RegexOptions.Compiled);
        private static readonly Regex Sha256Regex = new(@"(?<!(?<![g-zG-Z_])[a-fA-F0-9])([a-fA-F0-9]{64})(?![a-fA-F0-9](?![g-zG-Z_]))", RegexOptions.Compiled);
        private static readonly Regex Sha224Regex = new(@"(?<!(?<![g-zG-Z_])[a-fA-F0-9])([a-fA-F0-9]{56})(?![a-fA-F0-9](?![g-zG-Z_]))", RegexOptions.Compiled);
        private static readonly Regex Sha1Regex = new(@"(?<!(?<![g-zG-Z_])[a-fA-F0-9])([a-fA-F0-9]{40})(?![a-fA-F0-9](?![g-zG-Z_]))", RegexOptions.Compiled);
        private static readonly Regex Md5Regex = new(@"(?<!(?<![g-zG-Z_])[a-fA-F0-9])([a-fA-F0-9]{32})(?![a-fA-F0-9](?![g-zG-Z_]))", RegexOptions.Compiled);
        private static readonly Regex EmailRegex = new(@"(?<![a-zA-Z0-9])[\w\-\.]+@([\w\-]+\.)+[\w\-]{2,6}(?![a-zA-Z0-9])", RegexOptions.Compiled);
        private static readonly Regex CveRegex = new(@"((CVE|cve)-\d{4}-\d{4,7})(?!\d)", RegexOptions.Compiled);
        private static readonly Regex UrlRegex = new(@"(?<![a-zA-Z0-9])(https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9]{2,6}([-a-zA-Z0-9()@:%_\+.~#?&\/\/=]*))(?![a-zA-Z0-9])", RegexOptions.Compiled);
        private static readonly Regex PcomputerRegex = new(@"(PCOMP|pcomp)(-|_)([0-9]{7})(?![0-9])", RegexOptions.Compiled);
        private static readonly Regex Base64Regex = new(@"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})(?![A-Za-z0-9+/=])", RegexOptions.Compiled);
        private static readonly Regex MacRegex = new(@"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", RegexOptions.Compiled);
        private static readonly Regex DomainRegex = new(@"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$", RegexOptions.Compiled);
        private static readonly Regex HostPortRegex = new(
            @"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}):(\d{1,5})",
            RegexOptions.Compiled);

        internal class IndicatorDefinition
        {
            public string Key { get; }
            public IndicatorType Type { get; }
            public Regex Regex { get; }
            public bool IsSubstringMatch { get; }
            public Func<string, bool>? Validator { get; }

            public IndicatorDefinition(
                string key,
                IndicatorType type,
                Regex regex,
                bool isSubstringMatch,
                Func<string, bool>? validator = null)
            {
                Key = key;
                Type = type;
                Regex = regex;
                IsSubstringMatch = isSubstringMatch;
                Validator = validator;
            }
        }

        internal static readonly List<IndicatorDefinition> Definitions = new()
        {
            new IndicatorDefinition("hostport", IndicatorType.HostPort, HostPortRegex, isSubstringMatch: true,
                val => int.TryParse(val.Split(':')[^1], out var p) && p > 0 && p <= 65535),
            new IndicatorDefinition("ipv4", IndicatorType.Ip, Ipv4Regex, isSubstringMatch: true, val => IsFullIPv4(val)),
            new IndicatorDefinition("ipv6", IndicatorType.Ip, Ipv6Regex, isSubstringMatch: true),
            new IndicatorDefinition("sha256", IndicatorType.Hash, Sha256Regex, isSubstringMatch: true),
            new IndicatorDefinition("sha224", IndicatorType.Hash, Sha224Regex, isSubstringMatch: true),
            new IndicatorDefinition("sha1", IndicatorType.Hash, Sha1Regex, isSubstringMatch: true),
            new IndicatorDefinition("md5", IndicatorType.Hash, Md5Regex, isSubstringMatch: true),
            new IndicatorDefinition("url", IndicatorType.Url, UrlRegex, isSubstringMatch: true, val => Uri.TryCreate(val, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == "ftp")),
            new IndicatorDefinition("email", IndicatorType.Email, EmailRegex, isSubstringMatch: true),
            new IndicatorDefinition("domain", IndicatorType.Domain, DomainRegex, isSubstringMatch: false),
            new IndicatorDefinition("mac", IndicatorType.Mac, MacRegex, isSubstringMatch: false),
            new IndicatorDefinition("cve", IndicatorType.Cve, CveRegex, isSubstringMatch: true),
            new IndicatorDefinition("pcomputer", IndicatorType.PComputer, PcomputerRegex, isSubstringMatch: true),
            new IndicatorDefinition("base64", IndicatorType.Base64, Base64Regex, isSubstringMatch: false, val => CheckBase64(val))
        };

        public static bool IsFullIPv4(string text) =>
            text.Split('.').Length == 4
            && IPAddress.TryParse(text, out var ip)
            && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;

        public static bool IsInternalIPAddress(IPAddress ip)
        {
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var bytes = ip.GetAddressBytes();
                return bytes[0] == 10
                    || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                    || (bytes[0] == 192 && bytes[1] == 168)
                    || bytes[0] == 127
                    || (bytes[0] == 169 && bytes[1] == 254);
            }
            else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                if (ip.IsIPv6LinkLocal || IPAddress.IsLoopback(ip)) return true;
                var bytes = ip.GetAddressBytes();
                return (bytes[0] & 0xFE) == 0xFC;
            }
            return false;
        }

        public static IndicatorType GetIndicatorTypeKey(string? key)
        {
            if (!string.IsNullOrEmpty(key) && IndicatorTypeKey.TryGetValue(key, out var type))
                return type;
            return IndicatorType.Unknown;
        }

        public static bool CheckBase64(string val)
        {
            var text = val.Trim();
            if (text.Length < 4 || text.Length % 4 != 0) return false;
            foreach (var c in text)
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='))
                    return false;

            var firstPadding = text.IndexOf('=');
            if (firstPadding != -1)
            {
                if (firstPadding < text.Length - 2) return false;
                if (firstPadding == text.Length - 2 && text[text.Length - 1] != '=') return false;
            }

            if (text.Contains('=')) return true;
            if (text.Length >= 16)
            {
                var hasUpper = false; var hasLower = false; var hasDigit = false;
                foreach (var c in text)
                {
                    if (char.IsUpper(c)) hasUpper = true;
                    else if (char.IsLower(c)) hasLower = true;
                    else if (char.IsDigit(c)) hasDigit = true;
                }
                return hasUpper && hasLower && (hasDigit || text.Contains('+') || text.Contains('/'));
            }
            return false;
        }

        public static bool HasMixedCase(string text)
        {
            bool hasUpper = false, hasLower = false;
            foreach (var c in text)
            {
                if (char.IsUpper(c)) hasUpper = true;
                else if (char.IsLower(c)) hasLower = true;
                if (hasUpper && hasLower) return true;
            }
            return false;
        }

        private static (IndicatorDefinition? Def, IndicatorType ClassifiedType) ClassifyInternal(string trimmed, bool strict)
        {
            if (strict)
            {
                if (HostPortRegex.IsMatch(trimmed))
                    return (Definitions.Find(d => d.Key == "hostport"), IndicatorType.HostPort);
                if (Ipv4Regex.IsMatch(trimmed))
                    return (Definitions.Find(d => d.Key == "ipv4"), IndicatorType.Ip);
                if (Ipv6Regex.IsMatch(trimmed))
                    return (Definitions.Find(d => d.Key == "ipv6"), IndicatorType.Ip);
            }
            else if (IPAddress.TryParse(trimmed, out var ip) &&
                     (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 || IsFullIPv4(trimmed)))
            {
                if (IsInternalIPAddress(ip))
                    return (null, IndicatorType.InternalIp);
                return (Definitions.Find(d => d.Key == "ipv4"), IndicatorType.Ip);
            }

            foreach (var def in Definitions)
            {
                if (def.Key == "ipv4" || def.Key == "ipv6") continue;

                if (def.Regex.IsMatch(trimmed))
                {
                    if (def.Validator == null || def.Validator(trimmed))
                    {
                        return (def, def.Type);
                    }
                }
            }

            return (null, IndicatorType.Unknown);
        }

        public static IndicatorType Classify(string? text, bool strict = false)
        {
            if (string.IsNullOrEmpty(text))
                return IndicatorType.Unknown;

            var refanged = Refang(text);
            var trimmed = refanged.Trim();

            return ClassifyInternal(trimmed, strict).ClassifiedType;
        }

        public static string Refang(string? input)
        {
            if (string.IsNullOrEmpty(input)) return "";

            string result = input;
            result = Regex.Replace(result, @"\[\.\]|\(\.\)|\[d\]|\(d\)|\[dot\]|\(dot\)", ".", RegexOptions.IgnoreCase);
            result = Regex.Replace(result, @"\[at\]|\(at\)|\[@\]|\(@\)", "@", RegexOptions.IgnoreCase);
            result = Regex.Replace(result, @"\[:\]|\(:\)", ":", RegexOptions.IgnoreCase);
            result = Regex.Replace(result, @"\bhxxp(s)?\b", m => "http" + (m.Groups[1].Success ? "s" : ""), RegexOptions.IgnoreCase);

            return result;
        }

        public static (string? Text, IndicatorType Type) TryExtractIndicator(string? text)
        {
            if (string.IsNullOrEmpty(text))
                return (null, IndicatorType.Unknown);

            var refanged = Refang(text);
            var trimmed = refanged.Trim();

            var parts = trimmed.Split(new[] { ' ', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var part in parts)
            {
                var clean = part.Trim('.', ',', ';', ':', '"', '\'', ')', ']', '}', '(', '[', '{', '<', '>', '!', '?');
                if (string.IsNullOrEmpty(clean)) continue;

                var (def, classified) = ClassifyInternal(clean, strict: true);
                if (classified == IndicatorType.Unknown) continue;

                string extracted = clean;
                if (def != null && def.IsSubstringMatch)
                {
                    var m = def.Regex.Match(clean);
                    if (m.Success)
                    {
                        extracted = m.Value;
                    }
                }

                return (extracted, classified);
            }

            return (null, IndicatorType.Unknown);
        }
    }
}
