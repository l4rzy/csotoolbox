using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Http;
using Microsoft.Extensions.Logging.Abstractions;

namespace CSOToolbox.Client.Lib
{
    public static class TestRunner
    {
        public static void RunTests()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("========================================");
            Console.WriteLine("  Running C# CsoIndicatorExtractor Unit Tests...  ");
            Console.WriteLine("========================================");
            Console.ResetColor();

            var config = new CsoConfig();
            var analyzer = new CsoIndicatorExtractor(config, NullLogger<CsoIndicatorExtractor>.Instance);
            int passed = 0;
            int total = 0;

            void AssertEqual<T>(string testName, T expected, T actual)
            {
                total++;
                if (EqualityComparer<T>.Default.Equals(expected, actual))
                {
                    passed++;
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[PASS] {testName}");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[FAIL] {testName} - Expected: {expected}, Actual: {actual}");
                }
                Console.ResetColor();
            }

            void AssertNotEqual<T>(string testName, T notExpected, T actual)
            {
                total++;
                if (!EqualityComparer<T>.Default.Equals(notExpected, actual))
                {
                    passed++;
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[PASS] {testName}");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[FAIL] {testName} - Did not expect: {notExpected}, Actual: {actual}");
                }
                Console.ResetColor();
            }

            void AssertTrue(string testName, bool actual) => AssertEqual(testName, true, actual);
            void AssertFalse(string testName, bool actual) => AssertEqual(testName, false, actual);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n--- Classification Tests ---");
            Console.ResetColor();

            // ── IPv4 Tests ──
            analyzer.Process(CsoInputSource.User, "8.8.8.8");
            AssertEqual("IPv4 public IP", IndicatorType.Ip, analyzer.GetPrimaryIndicatorType());
            AssertEqual("IPv4 public Insertable", true, analyzer.CanAutoInsert);
            AssertEqual("IPv4 public Content", "8.8.8.8", analyzer.PrimaryIndicatorText);

            analyzer.Process(CsoInputSource.User, "10.0.0.1");
            AssertEqual("IPv4 internal 10.x.x.x", IndicatorType.InternalIp, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "172.16.0.1");
            AssertEqual("IPv4 internal 172.16.x.x", IndicatorType.InternalIp, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "172.31.255.255");
            AssertEqual("IPv4 internal 172.31.x.x", IndicatorType.InternalIp, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "172.32.0.1");
            AssertEqual("IPv4 public 172.32.x.x (not internal)", IndicatorType.Ip, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "192.168.0.1");
            AssertEqual("IPv4 internal 192.168.x.x", IndicatorType.InternalIp, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "127.0.0.1");
            AssertEqual("IPv4 loopback 127.x.x.x", IndicatorType.InternalIp, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "169.254.1.1");
            AssertEqual("IPv4 link-local 169.254.x.x", IndicatorType.InternalIp, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "1.1.1.1");
            AssertEqual("IPv4 public 1.1.1.1", IndicatorType.Ip, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "0.0.0.0");
            AssertEqual("IPv4 public 0.0.0.0", IndicatorType.Ip, analyzer.GetPrimaryIndicatorType());

            // ── IPv6 Tests ──
            analyzer.Process(CsoInputSource.User, "fe80::1");
            AssertEqual("IPv6 link-local fe80::1", IndicatorType.InternalIp, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "::1");
            AssertEqual("IPv6 loopback ::1", IndicatorType.InternalIp, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "fd12::1");
            AssertEqual("IPv6 unique-local fd00::/8", IndicatorType.InternalIp, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "2001:db8::1");
            AssertEqual("IPv6 public 2001:db8::1", IndicatorType.Ip, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "2606:4700:4700::1111");
            AssertEqual("IPv6 public Cloudflare DNS", IndicatorType.Ip, analyzer.GetPrimaryIndicatorType());

            // ── Hash Tests ──
            analyzer.Process(CsoInputSource.User, "44d88612fe8a8f36dec7492c3000b9e4");
            AssertEqual("Hash MD5 (32 hex)", IndicatorType.Hash, analyzer.GetPrimaryIndicatorType());
            AssertEqual("Hash MD5 Content", "44d88612fe8a8f36dec7492c3000b9e4", analyzer.PrimaryIndicatorText);

            analyzer.Process(CsoInputSource.User, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
            AssertEqual("Hash SHA1 (40 hex)", IndicatorType.Hash, analyzer.GetPrimaryIndicatorType());
            AssertEqual("Hash SHA1 Content", "da39a3ee5e6b4b0d3255bfef95601890afd80709", analyzer.PrimaryIndicatorText);

            analyzer.Process(CsoInputSource.User, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
            AssertEqual("Hash SHA224 (56 hex)", IndicatorType.Hash, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
            AssertEqual("Hash SHA256 (64 hex)", IndicatorType.Hash, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
            AssertEqual("Hash SHA256 uppercase", IndicatorType.Hash, analyzer.GetPrimaryIndicatorType());

            // 31 hex chars — not a valid hash
            analyzer.Process(CsoInputSource.User, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            AssertEqual("Hash non-match (31 hex chars)", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            // ── Mixed-case hex: both hash and base64 ──
            // 32-char mixed hex: valid both as md5 hash and unpadded base64
            analyzer.Process(CsoInputSource.User, "1a2B3c4D5e6F7a8b9c0d1e2f3a4b5c6d");
            AssertEqual("Mixed-case hex → Base64 wins", IndicatorType.Base64, analyzer.GetPrimaryIndicatorType());
            AssertEqual("Mixed-case hex Total is 1 (md5 match)", 1, analyzer.TotalMatchCount);

            // All-lower hex → hash wins
            analyzer.Process(CsoInputSource.User, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            AssertEqual("All-lower hex → Hash wins", IndicatorType.Hash, analyzer.GetPrimaryIndicatorType());

            // All-upper hex → hash wins
            analyzer.Process(CsoInputSource.User, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            AssertEqual("All-upper hex → Hash wins", IndicatorType.Hash, analyzer.GetPrimaryIndicatorType());

            // ── URL Tests ──
            analyzer.Process(CsoInputSource.User, "https://github.com/google/deepmind");
            AssertEqual("URL https with path", IndicatorType.Url, analyzer.GetPrimaryIndicatorType());
            AssertEqual("URL Content", "https://github.com/google/deepmind", analyzer.PrimaryIndicatorText);

            analyzer.Process(CsoInputSource.User, "http://example.com");
            AssertEqual("URL http", IndicatorType.Url, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "https://example.com/path?query=value&foo=bar#frag");
            AssertEqual("URL with query params", IndicatorType.Url, analyzer.GetPrimaryIndicatorType());

            // ── Email Tests ──
            analyzer.Process(CsoInputSource.User, "test.user_name@gmail.com");
            AssertEqual("Email simple", IndicatorType.Email, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "user+tag@company.co.uk");
            AssertEqual("Email with + tag", IndicatorType.Email, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "admin@localhost");
            AssertFalse("Email admin@localhost is not a domain", analyzer.IsDomain());

            // ── Domain Tests ──
            analyzer.Process(CsoInputSource.User, "deepmind.google.ca");
            AssertEqual("Domain multi-level", IndicatorType.Domain, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "example.com");
            AssertEqual("Domain simple", IndicatorType.Domain, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "sub.domain.example.com");
            AssertEqual("Domain deep subdomain", IndicatorType.Domain, analyzer.GetPrimaryIndicatorType());

            // ── HostPort Tests ──
            analyzer.Process(CsoInputSource.User, "example.com:443");
            AssertEqual("HostPort domain + port", IndicatorType.HostPort, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "github.com:2331");
            AssertEqual("HostPort domain + nonstandard port", IndicatorType.HostPort, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "192.168.1.1:8080");
            AssertEqual("HostPort IPv4 + port", IndicatorType.HostPort, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "https://example.com:443/path");
            AssertEqual("HostPort https URL not hostport", IndicatorType.Url, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "example.com:99999");
            AssertEqual("HostPort port > 65535 not hostport", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "example.com:0");
            AssertEqual("HostPort port 0 not hostport", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            // ── CVE Tests ──
            analyzer.Process(CsoInputSource.User, "CVE-2026-12345");
            AssertEqual("CVE standard", IndicatorType.Cve, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "cve-2026-12345");
            AssertEqual("CVE lowercase", IndicatorType.Cve, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "CVE-2024-21626");
            AssertEqual("CVE 5-digit ID", IndicatorType.Cve, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "CVE-2026-1234567");
            AssertEqual("CVE 7-digit ID", IndicatorType.Cve, analyzer.GetPrimaryIndicatorType());

            // ── MAC Address Tests ──
            analyzer.Process(CsoInputSource.User, "00-1A-2B-3C-4D-5E");
            AssertEqual("MAC hyphen separated", IndicatorType.Mac, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "00:1A:2B:3C:4D:5E");
            AssertEqual("MAC colon separated", IndicatorType.Mac, analyzer.GetPrimaryIndicatorType());

            // ── Base64 Tests ──
            analyzer.Process(CsoInputSource.User, "SGVsbG8gV29ybGQ=");
            AssertEqual("Base64 with padding", IndicatorType.Base64, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "SGVsbG8gV29ybGQh");
            AssertEqual("Base64 no padding (16 chars, 12 input bytes)", IndicatorType.Base64, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "aGVsbG8=");
            AssertEqual("Base64 short with padding", IndicatorType.Base64, analyzer.GetPrimaryIndicatorType());

            // short base64 without padding (< 16 chars) should not match
            analyzer.Process(CsoInputSource.User, "aGVsbG8");
            AssertNotEqual("Base64 short no padding not detected", IndicatorType.Base64, analyzer.GetPrimaryIndicatorType());

            // ── PComputer Tests ──
            analyzer.Process(CsoInputSource.User, "PCOMP-1234567");
            AssertEqual("PComputer generic format", IndicatorType.PComputer, analyzer.GetPrimaryIndicatorType());

            // ── Unknown / Garbage ──
            analyzer.Process(CsoInputSource.User, "this is complete garbage !@#$%^&*()");
            AssertEqual("Garbage text Unknown", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());
            AssertEqual("Garbage text Total 0", 0, analyzer.TotalMatchCount);

            // ── Empty / Edge ──
            analyzer.Process(CsoInputSource.User, "");
            AssertTrue("Empty string Skipped", analyzer.WasProcessingSkipped);

            analyzer.Process(CsoInputSource.User, "   ");
            AssertFalse("Whitespace not Skipped", analyzer.WasProcessingSkipped);
            AssertEqual("Whitespace Total 0", 0, analyzer.TotalMatchCount);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n--- Complex / Multi-Object Tests ---");
            Console.ResetColor();

            // ── Complex: URL containing CVE ──
            analyzer.Process(CsoInputSource.User, "https://cvedb.shodan.io/cve/CVE-2026-3143");
            AssertTrue("URL+CVE IsComplex", analyzer.HasComplexData());
            AssertTrue("URL+CVE ClassifiedIndicators has url", analyzer.MatchesByCategory.ContainsKey("url"));
            AssertTrue("URL+CVE ClassifiedIndicators has cve", analyzer.MatchesByCategory.ContainsKey("cve"));
            AssertEqual("URL+CVE Total matches", 2, analyzer.TotalMatchCount);
            AssertEqual("URL+CVE primary type (IsCve checked before IsUrl)", IndicatorType.Cve, analyzer.GetPrimaryIndicatorType());

            // ── Complex: IP + Email ──
            analyzer.Process(CsoInputSource.User, "8.8.8.8 and test@gmail.com");
            AssertTrue("IP+Email IsComplex", analyzer.HasComplexData());
            AssertTrue("IP+Email ClassifiedIndicators has ipv4", analyzer.MatchesByCategory.ContainsKey("ipv4"));
            AssertTrue("IP+Email ClassifiedIndicators has email", analyzer.MatchesByCategory.ContainsKey("email"));
            AssertEqual("IP+Email Total", 2, analyzer.TotalMatchCount);

            // ── Complex: Multiple same type ──
            analyzer.Process(CsoInputSource.User, "8.8.8.8 and 1.1.1.1");
            AssertTrue("Multi-IP IsComplex", analyzer.HasComplexData());
            AssertEqual("Multi-IP Total", 2, analyzer.TotalMatchCount);
            AssertEqual("Multi-IP ClassifiedIndicators ipv4 count", 2, analyzer.MatchesByCategory["ipv4"].Count);

            // ── Complex: Domain + Email ──
            // Note: "domain" regex uses ^...$ anchors, so it only matches whole lines, not substrings
            // Only email is found by the substring categorizers
            analyzer.Process(CsoInputSource.User, "example.com and admin@example.com");
            AssertTrue("Domain+Email HasComplexData", analyzer.HasComplexData()); // Text != Content
            AssertEqual("Domain+Email Total", 1, analyzer.TotalMatchCount);
            AssertFalse("Domain+Email ClassifiedIndicators has no domain key", analyzer.MatchesByCategory.ContainsKey("domain"));
            AssertTrue("Domain+Email ClassifiedIndicators has email", analyzer.MatchesByCategory.ContainsKey("email"));

            // ── Complex: Hash + CVE ──
            analyzer.Process(CsoInputSource.User, "44d88612fe8a8f36dec7492c3000b9e4 and CVE-2026-12345");
            AssertTrue("Hash+CVE IsComplex", analyzer.HasComplexData());
            AssertTrue("Hash+CVE ClassifiedIndicators has md5", analyzer.MatchesByCategory.ContainsKey("md5"));
            AssertTrue("Hash+CVE ClassifiedIndicators has cve", analyzer.MatchesByCategory.ContainsKey("cve"));

            // ── Complex: Many objects ──
            analyzer.Process(CsoInputSource.User, "8.8.8.8 test@gmail.com CVE-2026-12345 https://example.com");
            AssertTrue("Four-object IsComplex", analyzer.HasComplexData());
            AssertEqual("Four-object Total", 4, analyzer.TotalMatchCount);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n--- GenericReport + ExplicitType Tests ---");
            Console.ResetColor();

            // ── GenericReport with explicit URL type ──
            analyzer.Process(CsoInputSource.SelectedIndicator, "https://cvedb.shodan.io/cve/CVE-2026-3143", IndicatorType.Url);
            AssertEqual("GenericReport URL type preserved", IndicatorType.Url, analyzer.GetPrimaryIndicatorType());
            AssertEqual("GenericReport URL Content set", "https://cvedb.shodan.io/cve/CVE-2026-3143", analyzer.PrimaryIndicatorText);
            AssertFalse("GenericReport IsComplex false", analyzer.HasComplexData());

            // ── GenericReport with explicit CVE type ──
            analyzer.Process(CsoInputSource.SelectedIndicator, "CVE-2026-12345", IndicatorType.Cve);
            AssertEqual("GenericReport CVE type preserved", IndicatorType.Cve, analyzer.GetPrimaryIndicatorType());
            AssertEqual("GenericReport CVE Content", "CVE-2026-12345", analyzer.PrimaryIndicatorText);

            // ── GenericReport with explicit Hash type ──
            analyzer.Process(CsoInputSource.SelectedIndicator, "44d88612fe8a8f36dec7492c3000b9e4", IndicatorType.Hash);
            AssertEqual("GenericReport Hash type preserved", IndicatorType.Hash, analyzer.GetPrimaryIndicatorType());

            // ── GenericReport with explicit Ip type ──
            analyzer.Process(CsoInputSource.SelectedIndicator, "8.8.8.8", IndicatorType.Ip);
            AssertEqual("GenericReport Ip type preserved", IndicatorType.Ip, analyzer.GetPrimaryIndicatorType());

            // ── GenericReport with explicit Email type ──
            analyzer.Process(CsoInputSource.SelectedIndicator, "test@gmail.com", IndicatorType.Email);
            AssertEqual("GenericReport Email type preserved", IndicatorType.Email, analyzer.GetPrimaryIndicatorType());

            // ── GenericReport with explicit Domain type ──
            analyzer.Process(CsoInputSource.SelectedIndicator, "example.com", IndicatorType.Domain);
            AssertEqual("GenericReport Domain type preserved", IndicatorType.Domain, analyzer.GetPrimaryIndicatorType());

            // ── GenericReport with explicit Mac type ──
            analyzer.Process(CsoInputSource.SelectedIndicator, "00-1A-2B-3C-4D-5E", IndicatorType.Mac);
            AssertEqual("GenericReport Mac type preserved", IndicatorType.Mac, analyzer.GetPrimaryIndicatorType());

            // ── GenericReport with explicit InternalIp type ──
            analyzer.Process(CsoInputSource.SelectedIndicator, "192.168.1.1", IndicatorType.InternalIp);
            AssertEqual("GenericReport InternalIp type preserved", IndicatorType.InternalIp, analyzer.GetPrimaryIndicatorType());

            // ── GenericReport with explicit PComputer type ──
            analyzer.Process(CsoInputSource.SelectedIndicator, "PCOMP-1234567", IndicatorType.PComputer);
            AssertEqual("GenericReport PComputer type preserved", IndicatorType.PComputer, analyzer.GetPrimaryIndicatorType());

            // ── GenericReport without explicit type (fallback) ──
            analyzer.Process(CsoInputSource.SelectedIndicator, "8.8.8.8");
            AssertEqual("GenericReport no explicit type falls through to Ip", IndicatorType.Ip, analyzer.GetPrimaryIndicatorType());

            // ── GenericReport with unknown content (no type, no fallback) ──
            analyzer.Process(CsoInputSource.SelectedIndicator, "some random text");
            AssertEqual("GenericReport garbage gets Unknown", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            // ── GenericReport: explicit type survives new GenericReport ──
            analyzer.Process(CsoInputSource.SelectedIndicator, "CVE-2026-12345", IndicatorType.Cve);
            AssertEqual("GenericReport explicit Cve", IndicatorType.Cve, analyzer.GetPrimaryIndicatorType());
            // now a new Process(User) resets everything
            analyzer.Process(CsoInputSource.User, "8.8.8.8");
            AssertEqual("Process(User) after GenericReport resets type to Ip", IndicatorType.Ip, analyzer.GetPrimaryIndicatorType());

            // ── GenericReport: explicit type with URL containing CVE ──
            // This simulates the actual bug scenario
            analyzer.Process(CsoInputSource.SelectedIndicator, "https://cvedb.shodan.io/cve/CVE-2026-3143", IndicatorType.Url);
            AssertEqual("URL-with-CVE explicit type is Url", IndicatorType.Url, analyzer.GetPrimaryIndicatorType());
            AssertFalse("URL-with-CVE IsComplex false", analyzer.HasComplexData());

            // ── GenericReport: explicit CVE type for a bare CVE ──
            analyzer.Process(CsoInputSource.SelectedIndicator, "CVE-2026-12345", IndicatorType.Cve);
            AssertEqual("Bare CVE explicit type is Cve", IndicatorType.Cve, analyzer.GetPrimaryIndicatorType());

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n--- GetIndicatorTypeKey Tests ---");
            Console.ResetColor();

            AssertEqual("Key ipv4 → Ip", IndicatorType.Ip, CsoStatelessIndicatorExtractor.GetIndicatorTypeKey("ipv4"));
            AssertEqual("Key ipv6 → Ip", IndicatorType.Ip, CsoStatelessIndicatorExtractor.GetIndicatorTypeKey("ipv6"));
            AssertEqual("Key internalip → InternalIp", IndicatorType.InternalIp, CsoStatelessIndicatorExtractor.GetIndicatorTypeKey("internalip"));
            AssertEqual("Key hash → Hash", IndicatorType.Hash, CsoStatelessIndicatorExtractor.GetIndicatorTypeKey("hash"));
            AssertEqual("Key sha256 → Hash", IndicatorType.Hash, CsoStatelessIndicatorExtractor.GetIndicatorTypeKey("sha256"));
            AssertEqual("Key url → Url", IndicatorType.Url, CsoStatelessIndicatorExtractor.GetIndicatorTypeKey("url"));
            AssertEqual("Key email → Email", IndicatorType.Email, CsoStatelessIndicatorExtractor.GetIndicatorTypeKey("email"));
            AssertEqual("Key domain → Domain", IndicatorType.Domain, CsoStatelessIndicatorExtractor.GetIndicatorTypeKey("domain"));
            AssertEqual("Key mac → Mac", IndicatorType.Mac, CsoStatelessIndicatorExtractor.GetIndicatorTypeKey("mac"));
            AssertEqual("Key cve → Cve", IndicatorType.Cve, CsoStatelessIndicatorExtractor.GetIndicatorTypeKey("cve"));
            AssertEqual("Key base64 → Base64", IndicatorType.Base64, CsoStatelessIndicatorExtractor.GetIndicatorTypeKey("base64"));
            AssertEqual("Key pcomputer → PComputer", IndicatorType.PComputer, CsoStatelessIndicatorExtractor.GetIndicatorTypeKey("pcomputer"));
            AssertEqual("Key unknown → Unknown", IndicatorType.Unknown, CsoStatelessIndicatorExtractor.GetIndicatorTypeKey("unknown"));
            AssertEqual("Key null → Unknown", IndicatorType.Unknown, CsoStatelessIndicatorExtractor.GetIndicatorTypeKey(null));
            AssertEqual("Key empty → Unknown", IndicatorType.Unknown, CsoStatelessIndicatorExtractor.GetIndicatorTypeKey(""));

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n--- Static Classify() Tests ---");
            Console.ResetColor();

            AssertEqual("Classify IPv4 public", IndicatorType.Ip, CsoStatelessIndicatorExtractor.Classify("8.8.8.8"));
            AssertEqual("Classify IPv4 internal", IndicatorType.InternalIp, CsoStatelessIndicatorExtractor.Classify("192.168.1.1"));
            AssertEqual("Classify IPv6 public", IndicatorType.Ip, CsoStatelessIndicatorExtractor.Classify("2001:db8::1"));
            AssertEqual("Classify hash (MD5)", IndicatorType.Hash, CsoStatelessIndicatorExtractor.Classify("44d88612fe8a8f36dec7492c3000b9e4"));
            AssertEqual("Classify hash (SHA256)", IndicatorType.Hash, CsoStatelessIndicatorExtractor.Classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
            AssertEqual("Classify URL", IndicatorType.Url, CsoStatelessIndicatorExtractor.Classify("https://example.com"));
            AssertEqual("Classify email", IndicatorType.Email, CsoStatelessIndicatorExtractor.Classify("test@gmail.com"));
            AssertEqual("Classify domain", IndicatorType.Domain, CsoStatelessIndicatorExtractor.Classify("example.com"));
            AssertEqual("Classify mac", IndicatorType.Mac, CsoStatelessIndicatorExtractor.Classify("00-1A-2B-3C-4D-5E"));
            AssertEqual("Classify cve", IndicatorType.Cve, CsoStatelessIndicatorExtractor.Classify("CVE-2026-12345"));
            AssertEqual("Classify pcomputer", IndicatorType.PComputer, CsoStatelessIndicatorExtractor.Classify("PCOMP-1234567"));
            AssertEqual("Classify garbage", IndicatorType.Unknown, CsoStatelessIndicatorExtractor.Classify("this is garbage text"));
            AssertEqual("Classify URL with CVE path", IndicatorType.Url, CsoStatelessIndicatorExtractor.Classify("https://cvedb.shodan.io/cve/CVE-2026-3143"));
            AssertEqual("Classify empty", IndicatorType.Unknown, CsoStatelessIndicatorExtractor.Classify(""));
            AssertEqual("Classify null", IndicatorType.Unknown, CsoStatelessIndicatorExtractor.Classify(null));

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n--- TryExtractIndicator Tests ---");
            Console.ResetColor();

            AssertEqual("Extract clean domain", ("example.com", IndicatorType.Domain), CsoStatelessIndicatorExtractor.TryExtractIndicator("example.com"));
            AssertEqual("Extract IP from MX record", ("1.2.3.4", IndicatorType.Ip), CsoStatelessIndicatorExtractor.TryExtractIndicator("10 1.2.3.4"));
            AssertEqual("Extract domain from MX record", ("mail.example.com", IndicatorType.Domain), CsoStatelessIndicatorExtractor.TryExtractIndicator("10 mail.example.com"));
            AssertEqual("Extract domain with trailing dot", ("mail.example.com", IndicatorType.Domain), CsoStatelessIndicatorExtractor.TryExtractIndicator("mail.example.com."));
            AssertEqual("Extract IP from mixed text", ("8.8.8.8", IndicatorType.Ip), CsoStatelessIndicatorExtractor.TryExtractIndicator("some text with 8.8.8.8 here"));
            AssertEqual("Extract CVE from text", ("CVE-2026-12345", IndicatorType.Cve), CsoStatelessIndicatorExtractor.TryExtractIndicator("CVE-2026-12345 is a vulnerability"));
            AssertEqual("Extract hash from text", ("44d88612fe8a8f36dec7492c3000b9e4", IndicatorType.Hash), CsoStatelessIndicatorExtractor.TryExtractIndicator("md5: 44d88612fe8a8f36dec7492c3000b9e4"));
            AssertEqual("Extract url from text", ("https://evil.com", IndicatorType.Url), CsoStatelessIndicatorExtractor.TryExtractIndicator("check https://evil.com now"));
            AssertEqual("Extract email from text", ("user@evil.com", IndicatorType.Email), CsoStatelessIndicatorExtractor.TryExtractIndicator("contact user@evil.com"));
            AssertEqual("Extract email with angle bracket", ("user@evil.com", IndicatorType.Email), CsoStatelessIndicatorExtractor.TryExtractIndicator("<user@evil.com>"));
            AssertEqual("Extract null returns null", (null, IndicatorType.Unknown), CsoStatelessIndicatorExtractor.TryExtractIndicator(null));
            AssertEqual("Extract empty returns null", (null, IndicatorType.Unknown), CsoStatelessIndicatorExtractor.TryExtractIndicator(""));
            AssertEqual("Extract unknown returns null", (null, IndicatorType.Unknown), CsoStatelessIndicatorExtractor.TryExtractIndicator("this is just text"));
            AssertEqual("Extract IPv6", ("2001:db8::1", IndicatorType.Ip), CsoStatelessIndicatorExtractor.TryExtractIndicator("2001:db8::1"));
            AssertEqual("Extract IPv6 link-local", ("fe80::1", IndicatorType.Ip), CsoStatelessIndicatorExtractor.TryExtractIndicator("fe80::1"));
            AssertEqual("Extract IPv6 from MX text", ("2001:db8::1", IndicatorType.Ip), CsoStatelessIndicatorExtractor.TryExtractIndicator("10 2001:db8::1"));

            // ── Refanging Tests ──
            AssertEqual("Refang dots brackets", "1.1.1.1", CsoStatelessIndicatorExtractor.Refang("1.1.1[.]1"));
            AssertEqual("Refang dots parentheses", "1.1.1.1", CsoStatelessIndicatorExtractor.Refang("1.1.1(.)1"));
            AssertEqual("Refang dots letter d brackets", "1.1.1.1", CsoStatelessIndicatorExtractor.Refang("1.1.1[d]1"));
            AssertEqual("Refang dots word dot brackets", "1.1.1.1", CsoStatelessIndicatorExtractor.Refang("1.1.1[dot]1"));
            AssertEqual("Refang email at bracket", "test@example.com", CsoStatelessIndicatorExtractor.Refang("test[at]example.com"));
            AssertEqual("Refang email at parentheses", "test@example.com", CsoStatelessIndicatorExtractor.Refang("test(at)example.com"));
            AssertEqual("Refang email @ sign bracket", "test@example.com", CsoStatelessIndicatorExtractor.Refang("test[@]example.com"));
            AssertEqual("Refang colons bracket", "127.0.0.1:80", CsoStatelessIndicatorExtractor.Refang("127.0.0.1[:]80"));
            AssertEqual("Refang hxxps url", "https://example.com", CsoStatelessIndicatorExtractor.Refang("hxxps://example[.]com"));
            AssertEqual("Refang hxxp url with colons", "http://example.com", CsoStatelessIndicatorExtractor.Refang("hxxp[:]//example[.]com"));

            AssertEqual("Refang mixed case hXXps", "https://example.com", CsoStatelessIndicatorExtractor.Refang("hXXps://example[.]com"));
            AssertEqual("Refang hxxp in parens", "(http)://example.com", CsoStatelessIndicatorExtractor.Refang("(hxxp)://example.com"));
            AssertEqual("Refang hxxp in brackets", "[http]://example.com", CsoStatelessIndicatorExtractor.Refang("[hxxp]://example.com"));
            AssertEqual("Refang hxxp without scheme", "http example.com", CsoStatelessIndicatorExtractor.Refang("hxxp example.com"));
            AssertEqual("Refang dot (d) variant", "example.com", CsoStatelessIndicatorExtractor.Refang("example(d)com"));
            AssertEqual("Refang dot at end", "example.", CsoStatelessIndicatorExtractor.Refang("example[.]"));
            AssertEqual("Refang combined email+domain", "test@example.com", CsoStatelessIndicatorExtractor.Refang("test[at]example[.]com"));
            AssertEqual("Refang URL with port", "example.com:8080", CsoStatelessIndicatorExtractor.Refang("example[.]com[:]8080"));
            AssertEqual("Refang clean input unchanged", "example.com", CsoStatelessIndicatorExtractor.Refang("example.com"));
            AssertEqual("Refang null input", "", CsoStatelessIndicatorExtractor.Refang(null));
            AssertEqual("Refang empty input", "", CsoStatelessIndicatorExtractor.Refang(""));

            AssertEqual("Extract CVE embedded in text", ("CVE-2026-31431", IndicatorType.Cve), CsoStatelessIndicatorExtractor.TryExtractIndicator("hiiiCVE-2026-31431reliable"));

            // ── Fault-Tolerant Regex Tests ──
            AssertEqual("Extract MD5 embedded", ("44d88612fe8a8f36dec7492c3000b9e4", IndicatorType.Hash), CsoStatelessIndicatorExtractor.TryExtractIndicator("xxx44d88612fe8a8f36dec7492c3000b9e4xxx"));
            AssertEqual("Extract SHA1 embedded", ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IndicatorType.Hash), CsoStatelessIndicatorExtractor.TryExtractIndicator("zzzda39a3ee5e6b4b0d3255bfef95601890afd80709zzz"));
            AssertEqual("Extract SHA256 embedded", ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IndicatorType.Hash), CsoStatelessIndicatorExtractor.TryExtractIndicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
            AssertEqual("Extract SHA256 with trailing nonhex", ("896eb442ada77eb5d7db92a83ddb234926a46e5fa238e23cc2e190588e5aef01", IndicatorType.Hash), CsoStatelessIndicatorExtractor.TryExtractIndicator("896eb442ada77eb5d7db92a83ddb234926a46e5fa238e23cc2e190588e5aef01paapaa"));
            AssertEqual("Extract email embedded", ("xxxuser@example.comxxx", IndicatorType.Email), CsoStatelessIndicatorExtractor.TryExtractIndicator("xxxuser@example.comxxx"));
            AssertEqual("Extract PComputer embedded", ("PCOMP-1234567", IndicatorType.PComputer), CsoStatelessIndicatorExtractor.TryExtractIndicator("xxxPCOMP-1234567xxx"));

            AssertEqual("Extract defanged IPv4", ("1.1.1.1", IndicatorType.Ip), CsoStatelessIndicatorExtractor.TryExtractIndicator("1.1.1[.]1"));
            AssertEqual("Extract defanged URL", ("https://example.com", IndicatorType.Url), CsoStatelessIndicatorExtractor.TryExtractIndicator("hxxps[:]//example[.]com"));
            AssertEqual("Extract defanged domain", ("example.com", IndicatorType.Domain), CsoStatelessIndicatorExtractor.TryExtractIndicator("example[.]com"));

            // ── Behaviors.txt tests ──
            AssertEqual("Extract IP behavior 1", ("182.93.50.90", IndicatorType.Ip), CsoStatelessIndicatorExtractor.TryExtractIndicator("182.93.50.901"));
            AssertEqual("Extract IP behavior 2", ("182.93.50.90", IndicatorType.Ip), CsoStatelessIndicatorExtractor.TryExtractIndicator("182.93.50.90abc"));
            AssertEqual("Extract IP behavior 3", ("182.93.50.90", IndicatorType.Ip), CsoStatelessIndicatorExtractor.TryExtractIndicator("13182.93.50.90"));
            AssertEqual("Extract IP behavior 4", ("182.93.50.90", IndicatorType.Ip), CsoStatelessIndicatorExtractor.TryExtractIndicator("abc182.93.50.90"));
            AssertEqual("Extract IP behavior 5", ("82.93.50.90", IndicatorType.Ip), CsoStatelessIndicatorExtractor.TryExtractIndicator("13282.93.50.90"));
            AssertEqual("Extract IP behavior 6", ("82.93.50.190", IndicatorType.Ip), CsoStatelessIndicatorExtractor.TryExtractIndicator("13282.93.50.1902"));
            AssertEqual("Extract IP behavior 7", ("82.93.50.90", IndicatorType.Ip), CsoStatelessIndicatorExtractor.TryExtractIndicator("13282.93.50.901"));

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n--- ClassifiedIndicators Tests ---");
            Console.ResetColor();

            analyzer.Process(CsoInputSource.User, "8.8.8.8");
            AssertTrue("ClassifiedIndicators ipv4 present for IP", analyzer.MatchesByCategory.ContainsKey("ipv4"));
            AssertEqual("ClassifiedIndicators ipv4 count", 1, analyzer.MatchesByCategory["ipv4"].Count);
            AssertEqual("ClassifiedIndicators ipv4 value", "8.8.8.8", analyzer.MatchesByCategory["ipv4"][0]);

            analyzer.Process(CsoInputSource.User, "test@gmail.com and CVE-2026-12345");
            AssertTrue("ClassifiedIndicators email present", analyzer.MatchesByCategory.ContainsKey("email"));
            AssertTrue("ClassifiedIndicators cve present", analyzer.MatchesByCategory.ContainsKey("cve"));
            AssertEqual("ClassifiedIndicators email count", 1, analyzer.MatchesByCategory["email"].Count);
            AssertEqual("ClassifiedIndicators cve count", 1, analyzer.MatchesByCategory["cve"].Count);

            // ── Duplicate detection ──
            analyzer.Process(CsoInputSource.Clipboard, "8.8.8.8");
            analyzer.Process(CsoInputSource.Clipboard, "8.8.8.8");
            AssertTrue("Duplicate clipboard input Skipped", analyzer.WasProcessingSkipped);
            AssertEqual("Duplicate clipboard message", "Nothing new!", analyzer.StatusMessage);

            // Variable-length CVE: min 4 digits
            analyzer.Process(CsoInputSource.User, "CVE-2024-0001");
            AssertEqual("CVE 4-digit ID (shortest)", IndicatorType.Cve, analyzer.GetPrimaryIndicatorType());

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n--- Edge Case Tests ---");
            Console.ResetColor();

            // ── IPv4 Boundary Edge Cases ──
            analyzer.Process(CsoInputSource.User, "999.999.999.999");
            AssertEqual("IPv4 invalid octets > 255", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "256.1.1.1");
            AssertEqual("IPv4 first octet 256", IndicatorType.Ip, analyzer.GetPrimaryIndicatorType());
            AssertEqual("IPv4 first octet 256 Content", "56.1.1.1", analyzer.PrimaryIndicatorText);

            analyzer.Process(CsoInputSource.User, "1.2.3");
            AssertEqual("IPv4 only 3 octets", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            // ── Hash Hex-Boundary Edge Cases ──
            analyzer.Process(CsoInputSource.User, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            AssertEqual("Hash 33 hex chars (not 32 or 40)", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            AssertEqual("Hash 65 hex chars (not 64)", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "44d88612fe8a8f36dec7492c3000b9g4");
            AssertEqual("Hash 32 chars with non-hex 'g'", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            // Hash surrounded by hex chars — boundary assertions should prevent match
            analyzer.Process(CsoInputSource.User, "abcdef44d88612fe8a8f36dec7492c3000b9e4abcdef");
            AssertEqual("Hash surrounded by hex chars → no match", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            // Hash surrounded by non-hex chars — boundary allows match (OCR fault tolerance)
            analyzer.Process(CsoInputSource.User, "xyz44d88612fe8a8f36dec7492c3000b9e4xyz");
            AssertEqual("Hash surrounded by non-hex chars → still matches", 1, analyzer.TotalMatchCount);

            // ── CVE Boundary Edge Cases ──
            analyzer.Process(CsoInputSource.User, "CVE-2026-123");
            AssertEqual("CVE only 3-digit ID (too short)", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "CVE-2026-12345678");
            AssertEqual("CVE 8-digit ID (too long)", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "Cve-2026-12345");
            AssertEqual("CVE mixed-case prefix", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            // ── Domain Edge Cases ──
            analyzer.Process(CsoInputSource.User, "example..com");
            AssertEqual("Domain consecutive dots", IndicatorType.Domain, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "example.toolongx");
            AssertEqual("Domain TLD > 6 chars", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            // ── MAC Address Edge Cases ──
            analyzer.Process(CsoInputSource.User, "aa:bb:cc:dd:ee:ff");
            AssertEqual("MAC lowercase", IndicatorType.Mac, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "00:1A-2B:3C-4D:5E");
            AssertEqual("MAC mixed separators", IndicatorType.Mac, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "00:1A:2B:3C:4D");
            AssertEqual("MAC only 5 groups (too few)", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "00:1A:2B:3C:4D:5E:FF");
            AssertEqual("MAC 7 groups (too many)", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            // ── Email Edge Cases ──
            analyzer.Process(CsoInputSource.User, ".user@gmail.com");
            AssertEqual("Email leading dot", IndicatorType.Email, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "user..name@gmail.com");
            AssertEqual("Email consecutive dots in local", IndicatorType.Email, analyzer.GetPrimaryIndicatorType());

            // ── Base64 Edge Cases ──
            analyzer.Process(CsoInputSource.User, "SGVs+G8gV/9ybGQ=");
            AssertEqual("Base64 with + and / chars", IndicatorType.Base64, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "SG=sbG8gV29ybGQ=");
            AssertEqual("Base64 padding in middle → not base64", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            analyzer.Process(CsoInputSource.User, "AAAA");
            AssertEqual("Base64 4 chars no padding → not base64", IndicatorType.Unknown, analyzer.GetPrimaryIndicatorType());

            // ── PastedText Source Edge Cases ──
            config.SetClipboardMaxLength(1024);
            string pastedOverLimit = new string('a', 1025);
            analyzer.Process(CsoInputSource.PastedText, pastedOverLimit);
            AssertFalse("PastedText bypasses clipboard max length", analyzer.WasProcessingSkipped);
            config.SetClipboardMaxLength(8192); // restore default

            // ── Refang Edge Cases ──
            AssertEqual("Refang uppercase [DOT]", "example.com", CsoStatelessIndicatorExtractor.Refang("example[DOT]com"));
            AssertEqual("Refang mixed case (Dot)", "example.com", CsoStatelessIndicatorExtractor.Refang("example(Dot)com"));
            AssertEqual("Refang hxxp inside longer word not matched", "shxxps://example.com", CsoStatelessIndicatorExtractor.Refang("shxxps://example.com"));

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n--- AvailableAnalyzers Tests ---");
            Console.ResetColor();

            AssertTrue("Hash AvailableAnalyzers has VirusTotal",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.Hash].Contains(AnalyzerType.VirusTotal));
            AssertTrue("Url AvailableAnalyzers has Dns",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.Url].Contains(AnalyzerType.Dns));
            AssertTrue("Url AvailableAnalyzers has Whois",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.Url].Contains(AnalyzerType.Whois));
            AssertTrue("Url AvailableAnalyzers has VirusTotal",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.Url].Contains(AnalyzerType.VirusTotal));
            AssertTrue("Ip AvailableAnalyzers has AbuseIpDb",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.Ip].Contains(AnalyzerType.AbuseIpDb));
            AssertTrue("Ip AvailableAnalyzers has VirusTotal",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.Ip].Contains(AnalyzerType.VirusTotal));
            AssertTrue("Ip AvailableAnalyzers has Rdns",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.Ip].Contains(AnalyzerType.Rdns));
            AssertTrue("Cve AvailableAnalyzers has Circl",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.Cve].Contains(AnalyzerType.Circl));
            AssertTrue("Cve AvailableAnalyzers has Shodan",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.Cve].Contains(AnalyzerType.Shodan));
            AssertTrue("Domain AvailableAnalyzers has VirusTotal",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.Domain].Contains(AnalyzerType.VirusTotal));
            AssertTrue("Domain AvailableAnalyzers has Dns",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.Domain].Contains(AnalyzerType.Dns));
            AssertTrue("Domain AvailableAnalyzers has Whois",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.Domain].Contains(AnalyzerType.Whois));
            AssertTrue("Base64 AvailableAnalyzers has Base64",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.Base64].Contains(AnalyzerType.Base64));
            AssertTrue("Mac AvailableAnalyzers has Mac",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.Mac].Contains(AnalyzerType.Mac));
            AssertTrue("InternalIp AvailableAnalyzers has Rdns",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.InternalIp].Contains(AnalyzerType.Rdns));
            AssertTrue("PComputer AvailableAnalyzers has Dns",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.PComputer].Contains(AnalyzerType.Dns));
            AssertTrue("User AvailableAnalyzers has NetUser",
                AnalyzerMap.AvailableAnalyzers[IndicatorType.User].Contains(AnalyzerType.NetUser));

            // PrimaryIndicatorType reverse lookup
            AssertEqual("Primary: VirusTotal → Hash", IndicatorType.Hash, AnalyzerMap.PrimaryIndicatorType[AnalyzerType.VirusTotal]);
            AssertEqual("Primary: AbuseIpDb → Ip", IndicatorType.Ip, AnalyzerMap.PrimaryIndicatorType[AnalyzerType.AbuseIpDb]);
            AssertEqual("Primary: Circl → Cve", IndicatorType.Cve, AnalyzerMap.PrimaryIndicatorType[AnalyzerType.Circl]);
            AssertEqual("Primary: Shodan → Cve", IndicatorType.Cve, AnalyzerMap.PrimaryIndicatorType[AnalyzerType.Shodan]);
            AssertEqual("Primary: Dns → Domain", IndicatorType.Domain, AnalyzerMap.PrimaryIndicatorType[AnalyzerType.Dns]);
            AssertEqual("Primary: Whois → Domain", IndicatorType.Domain, AnalyzerMap.PrimaryIndicatorType[AnalyzerType.Whois]);
            AssertEqual("Primary: Base64 → Base64", IndicatorType.Base64, AnalyzerMap.PrimaryIndicatorType[AnalyzerType.Base64]);

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n--- Default Analyzer Invariant Tests ---");
            Console.ResetColor();

            // For every IndicatorType: the default analyzer must be valid and present in AvailableAnalyzers
            void AssertDefaultValid(IndicatorType type, string label)
            {
                var def = config.GetDefaultAnalyzer(type);
                AssertNotEqual($"{label} default is not Unknown", AnalyzerType.Unknown, def);
                AssertTrue($"{label} default {def} is in AvailableAnalyzers",
                    AnalyzerMap.AvailableAnalyzers[type].Contains(def));
            }

            AssertDefaultValid(IndicatorType.Ip, "Ip");
            AssertDefaultValid(IndicatorType.InternalIp, "InternalIp");
            AssertDefaultValid(IndicatorType.Hash, "Hash");
            AssertDefaultValid(IndicatorType.Url, "Url");
            AssertDefaultValid(IndicatorType.Domain, "Domain");
            AssertDefaultValid(IndicatorType.Email, "Email");
            AssertDefaultValid(IndicatorType.Mac, "Mac");
            AssertDefaultValid(IndicatorType.Cve, "Cve");
            AssertDefaultValid(IndicatorType.Base64, "Base64");
            AssertDefaultValid(IndicatorType.User, "User");
            AssertDefaultValid(IndicatorType.PComputer, "PComputer");

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n--- History & Config Tests ---");
            Console.ResetColor();

            // Original tests preserved
            config.SetClipboardMaxLength(1024);
            AssertEqual("Clipboard Limit Config Return", 1024, config.GetClipboardMaxLength());

            string overLimitText = new string('a', 1025);
            analyzer.Process(CsoInputSource.Clipboard, overLimitText);
            AssertTrue("Clipboard Limit Exceeded", analyzer.WasProcessingSkipped);
            AssertEqual("Clipboard Limit Exceeded Message", "Content too big!", analyzer.StatusMessage);

            string underLimitText = new string('a', 1023);
            analyzer.Process(CsoInputSource.Clipboard, underLimitText);
            AssertFalse("Clipboard Limit Within Limit", analyzer.WasProcessingSkipped);

            config.SetClipboardMaxLength(10);
            AssertEqual("Clipboard Limit Fallback to Default", 16384, config.GetClipboardMaxLength());

            config.SetHistoryLimit(10);
            AssertEqual("History Limit Config Return", 10, config.GetHistoryLimit());

            var history = new CsoHistory(config);
            for (int i = 1; i <= 11; i++)
            {
                history.Append("user", $"item{i}", null, DateTime.UtcNow);
            }
            AssertEqual("History Limit Pruning Count", 10, history.GetAllEntries().Count);
            AssertEqual("History Limit Pruned Oldest", "item2", history.GetAllEntries()[0].text);
            AssertEqual("History Limit Pruned Newest", "item11", history.GetAllEntries()[9].text);
            AssertTrue("History Limit Dictionary Pruned", history.FindEntry("item1") == null);
            AssertTrue("History Limit Dictionary Kept", history.FindEntry("item2") != null);

            config.SetHistoryLimit(0);
            AssertEqual("History Limit Unlimited Config", 0, config.GetHistoryLimit());
            var historyUnlimited = new CsoHistory(config);
            for (int i = 1; i <= 12; i++)
            {
                historyUnlimited.Append("user", $"item{i}", null, DateTime.UtcNow);
            }
            AssertEqual("History Limit Unlimited Count", 12, historyUnlimited.GetAllEntries().Count);

            config.SetHistoryLimit(5);
            AssertEqual("History Limit Fallback to Default", 100, config.GetHistoryLimit());

            // ── CsoWorker & IAnalysisClient Decoupled Tests ──
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n--- Decoupled CsoWorker Tests (Mock HTTP) ---");
            Console.ResetColor();

            RunWorkerTests(
                (name, exp, act) => AssertEqual(name, exp, act),
                (name, exp, act) => AssertEqual(name, exp, act),
                (name, act) => AssertTrue(name, act)
            ).GetAwaiter().GetResult();

            Console.WriteLine();
            if (passed == total)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"SUCCESS: All {passed}/{total} tests passed!");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"FAILURE: {passed}/{total} tests passed.");
                throw new Exception("Some tests failed.");
            }
            Console.ResetColor();
            Console.WriteLine("========================================");
        }

        private class MockHttpMessageHandler : System.Net.Http.HttpMessageHandler
        {
            private readonly Func<System.Net.Http.HttpRequestMessage, Task<System.Net.Http.HttpResponseMessage>> _handler;

            public MockHttpMessageHandler(Func<System.Net.Http.HttpRequestMessage, Task<System.Net.Http.HttpResponseMessage>> handler)
            {
                _handler = handler;
            }

            protected override Task<System.Net.Http.HttpResponseMessage> SendAsync(System.Net.Http.HttpRequestMessage request, CancellationToken cancellationToken)
            {
                return _handler(request);
            }
        }

        private static async Task RunWorkerTests(
            Action<string, string, string> assertStringEqual,
            Action<string, int, int> assertIntEqual,
            Action<string, bool> assertTrue)
        {
            var config = new CsoConfig();
            config.Set("general", "backend", "http://mock-backend");

            var mockHandler = new MockHttpMessageHandler(async req =>
            {
                var path = req.RequestUri?.PathAndQuery ?? "";
                if (path.EndsWith("/health"))
                {
                    return new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK)
                    {
                        Content = new System.Net.Http.StringContent(
                            "{\"health\": \"ok\", \"version\": \"1.2.3\", \"ocr_backend\": \"tesseract\"}",
                            System.Text.Encoding.UTF8, "application/json")
                    };
                }
                else if (path.Contains("/api/v1/tunnel/"))
                {
                    var segments = path.TrimEnd('/').Split('/');
                    var service = segments[segments.Length - 1];
                    if (service == "virustotal")
                    {
                        return new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK)
                        {
                            Content = new System.Net.Http.StringContent(
                                "{\"payload\": {\"data\": [{\"attributes\": {\"magic\": \"PE32 executable\", \"last_analysis_stats\": {\"malicious\": 0, \"harmless\": 70}}}]}}",
                                System.Text.Encoding.UTF8, "application/json")
                        };
                    }
                }
                return new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.NotFound);
            });

            using var httpClient = new System.Net.Http.HttpClient(mockHandler);
            using var worker = new CsoWorker(config, Microsoft.Extensions.Logging.Abstractions.NullLogger<CsoWorker>.Instance, httpClient);

            // Test CheckServerHealth
            var health = await worker.CheckServerHealth();
            assertTrue("Mocked CheckServerHealth IsOperational", health.IsOperational);
            assertStringEqual("Mocked CheckServerHealth Version", "1.2.3", health.Version);

            // Test direct query resolution via QueryServiceAsync
            var queryResult = await worker.QueryServiceAsync(AnalyzerType.VirusTotal, "44d88612fe8a8f36dec7492c3000b9e4");
            assertTrue("QueryServiceAsync returned TunnelResponseV1", queryResult is TunnelResponseV1);
            var vtDirect = queryResult?.Payload as VirusTotalObject;
            assertTrue("QueryServiceAsync resolved VirusTotalObject in payload", vtDirect != null);
            if (vtDirect != null)
            {
                assertIntEqual("VirusTotalObject direct malicious count is 0", 0, vtDirect.Data[0].Attributes.LastAnalysisStats?.Malicious ?? -1);
                assertIntEqual("VirusTotalObject direct harmless count is 70", 70, vtDirect.Data[0].Attributes.LastAnalysisStats?.Harmless ?? -1);
            }

            // Test Run and event propagation
            var tcs = new TaskCompletionSource<object?>();
            worker.JobCompleted += (id, service, indicator, data) =>
            {
                if (id == "test-job" && service == "virustotal")
                {
                    tcs.TrySetResult(data);
                }
            };

            worker.Run("test-job", new[] { AnalyzerType.VirusTotal }, "44d88612fe8a8f36dec7492c3000b9e4");
            var result = await tcs.Task;
            assertTrue("JobCompleted received TunnelResponse", result is TunnelResponseV1);
            var vt = (result as TunnelResponseV1)?.Payload as VirusTotalObject;
            assertTrue("JobCompleted payload is VirusTotalObject", vt != null);
            if (vt != null)
            {
                assertIntEqual("VirusTotalObject malicious count is 0", 0, vt.Data[0].Attributes.LastAnalysisStats?.Malicious ?? -1);
                assertIntEqual("VirusTotalObject harmless count is 70", 70, vt.Data[0].Attributes.LastAnalysisStats?.Harmless ?? -1);
            }
        }
    }
}
