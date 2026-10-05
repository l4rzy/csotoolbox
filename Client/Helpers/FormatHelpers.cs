using System;
using System.Globalization;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using CSOToolbox.Client.Lib;
using Microsoft.Extensions.Logging;
using Avalonia;
using Avalonia.Controls.Documents;
using Avalonia.Media;

namespace CSOToolbox.Client.Helpers;

public static class FormatHelpers
{
    public static ILogger? Logger { get; set; }

    public static string ClientUserAgent
    {
        get
        {
            var version = UpdateChecker.GetCurrentVersionString();
            return $"CSO Toolbox Client {version} - {RuntimeInformation.OSDescription}";
        }
    }

    public static bool ValidateCsoServerCertificate(
        HttpRequestMessage message,
        X509Certificate2? cert,
        X509Chain? chain,
        SslPolicyErrors errors)
    {
        if (AppConstants.SslPinningDisabled)
            return true;

        if (cert == null) return false;

        var hashBytes = cert.GetCertHash(HashAlgorithmName.SHA256);
        var hashString = Convert.ToHexString(hashBytes).ToLowerInvariant();

        // Pin to the CSO self-signed cert SHA-256 fingerprint
        bool match = hashString == AppConstants.SslCertificateHash;

        if (!match)
            Logger?.LogWarning("Certificate pinning FAILED — expected {Hash}, got {Actual}",
                AppConstants.SslCertificateHash, hashString);

        return match;
    }

    public static string FormatBytes(long bytes)
    {
        string[] suffix = { "B", "KB", "MB", "GB", "TB" };
        int i = 0;
        double dblBid = bytes;
        while (dblBid >= 1024 && i < suffix.Length - 1)
        {
            dblBid /= 1024.0;
            i++;
        }
        return $"{dblBid:0.##} {suffix[i]}";
    }

    public static SolidColorBrush GetInterpolatedScoreBrush(double score, double maxScore = 100)
    {
        double percent = Math.Clamp(score / maxScore, 0.0, 1.0);
        byte r, g, b;
        if (percent < 0.5)
        {
            double t = percent * 2.0;
            r = (byte)(76 + (255 - 76) * t);
            g = (byte)(175 + (235 - 175) * t);
            b = (byte)(80 + (59 - 80) * t);
        }
        else
        {
            double t = (percent - 0.5) * 2.0;
            r = (byte)(255 + (244 - 255) * t);
            g = (byte)(235 + (67 - 235) * t);
            b = (byte)(59 + (54 - 59) * t);
        }
        return new SolidColorBrush(Color.FromRgb(r, g, b));
    }

    public static Geometry CreatePieSlice(double cx, double cy, double radius, double startAngleDegrees, double endAngleDegrees)
    {
        double startRad = startAngleDegrees * Math.PI / 180.0;
        double endRad = endAngleDegrees * Math.PI / 180.0;

        var startPoint = new Point(cx + radius * Math.Cos(startRad), cy + radius * Math.Sin(startRad));
        var endPoint = new Point(cx + radius * Math.Cos(endRad), cy + radius * Math.Sin(endRad));

        bool isLargeArc = (endAngleDegrees - startAngleDegrees) > 180.0;

        var figure = new PathFigure
        {
            StartPoint = new Point(cx, cy),
            IsClosed = true,
            Segments = new PathSegments
            {
                new LineSegment { Point = startPoint },
                new ArcSegment
                {
                    Point = endPoint,
                    Size = new Size(radius, radius),
                    RotationAngle = 0,
                    IsLargeArc = isLargeArc,
                    SweepDirection = SweepDirection.Clockwise
                }
            }
        };

        return new PathGeometry { Figures = new PathFigures { figure } };
    }

    public static string? CountryCodeToFlag(string? countryCode)
    {
        if (string.IsNullOrEmpty(countryCode) || countryCode.Length != 2) return null;
        countryCode = countryCode.ToUpperInvariant();
        int first = 0x1F1E6 + (countryCode[0] - 'A');
        int second = 0x1F1E6 + (countryCode[1] - 'A');
        return char.ConvertFromUtf32(first) + char.ConvertFromUtf32(second);
    }

    public static string CountryCodeToName(string countryCode)
    {
        try
        {
            var region = new RegionInfo(countryCode.ToUpperInvariant());
            return region.EnglishName;
        }
        catch
        {
            return countryCode.ToUpperInvariant();
        }
    }

    public static void SetCountryTextWithFlag(Avalonia.Controls.TextBlock textBlock, string? countryCode, string? countryName)
    {
        textBlock.Text = null;
        textBlock.Inlines?.Clear();

        if (!string.IsNullOrEmpty(countryCode))
        {
            var name = !string.IsNullOrEmpty(countryName) ? countryName : CountryCodeToName(countryCode);
            var flag = CountryCodeToFlag(countryCode);
            if (flag != null)
            {
                textBlock.Inlines = new InlineCollection
                {
                    new Run { Text = $"{name} " },
                    new Run
                    {
                        Text = flag,
                        FontFamily = new FontFamily("avares://Client/Resources/TwemojiCountryFlags.ttf#Twemoji Mozilla, Noto Color Emoji, Apple Color Emoji, Segoe UI Emoji")
                    }
                };
            }
            else
            {
                textBlock.Text = name;
            }
        }
        else
        {
            textBlock.Text = "N/A";
        }
    }
}
