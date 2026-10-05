using System;
using Avalonia;
using Avalonia.Controls;
using CSOToolbox.Client.Helpers;
using CSOToolbox.Client.Lib;

namespace CSOToolbox.Client
{
    public partial class MainWindow : Window
    {
        private void RenderScamalyticsReport(ScamalyticsObject result)
        {

            var d = result.Data!;
            _txtScamalyticsScore!.Text = $"{d.Score}";
            var riskStr = string.IsNullOrEmpty(d.Risk) ? "Unknown" : char.ToUpper(d.Risk[0]) + d.Risk.Substring(1);
            _txtScamalyticsRisk!.Text = $"This IP is categorized as {riskStr} Risk";
            _progressScamalyticsScore!.Value = d.Score;

            var scoreBrush = FormatHelpers.GetInterpolatedScoreBrush(d.Score);
            _progressScamalyticsScore.Foreground = scoreBrush;
            _txtScamalyticsScore.Foreground = scoreBrush;

            var geo = result.GeoIP;
            if (geo != null)
            {
                FormatHelpers.SetCountryTextWithFlag(_txtScamalyticsCountry!, geo.CountryCode, geo.CountryName);
                _txtScamalyticsCity!.Text = !string.IsNullOrEmpty(geo.City) ? geo.City : "N/A";
                _txtScamalyticsOrg!.Text = !string.IsNullOrEmpty(geo.AsName) ? geo.AsName + (!string.IsNullOrEmpty(geo.AsDomain) ? $" ({geo.AsDomain})" : "") : "N/A";
                _txtScamalyticsTimeZone!.Text = !string.IsNullOrEmpty(geo.TimeZone) ? geo.TimeZone : "N/A";
                _txtScamalyticsLocation!.Text = !string.IsNullOrEmpty(geo.GeoLocation) ? geo.GeoLocation : "N/A";
                _txtScamalyticsIsp!.Text = !string.IsNullOrEmpty(geo.IspName) ? geo.IspName : "N/A";
            }

            if (result.Security != null)
            {
                if (result.Security.Blacklists != null)
                {
                    var bl = result.Security.Blacklists;
                    int blCount = (bl.Ip2Proxy ? 1 : 0) + (bl.Firehol ? 1 : 0) + (bl.Ipsum ? 1 : 0) +
                                  (bl.Spamhaus ? 1 : 0) + (bl.Spambot ? 1 : 0);
                    var blStatus = result.Security.IsBlacklistedExternal ? "Yes" : "No";
                    _txtScamalyticsBlacklisted!.Text = $"{blStatus} ({blCount}/5)";
                    _txtScamalyticsBlacklisted.Foreground = Avalonia.Media.Brush.Parse(result.Security.IsBlacklistedExternal ? DraculaColors.Red : DraculaColors.Green);
                }

                if (result.Security.Proxies != null)
                {
                    var proxyType = result.Security.Proxies.ProxyType ?? "";
                    var hasProxy = !string.IsNullOrEmpty(proxyType);
                    _txtScamalyticsProxy!.Text = hasProxy ? $"Yes ({proxyType})" : "No";
                    _txtScamalyticsProxy.Foreground = Avalonia.Media.Brush.Parse(hasProxy ? DraculaColors.Red : DraculaColors.Green);

                    SetBooleanIndicator(_txtScamalyticsDatacenter!, result.Security.Proxies.IsDatacenter, DraculaColors.Orange);
                    SetBooleanIndicator(_txtScamalyticsVpn!, result.Security.Proxies.IsVpn, DraculaColors.Red);
                    SetBooleanIndicator(_txtScamalyticsTor!, result.Security.Proxies.IsTor, DraculaColors.Red);
                }
            }

            if (d.Proxy != null)
            {
                SetBooleanIndicator(_txtScamalyticsIcloudRelay!, d.Proxy.IsAppleIcloudPrivateRelay, DraculaColors.Orange);
                SetBooleanIndicator(_txtScamalyticsAws!, d.Proxy.IsAmazonAws, DraculaColors.Orange);
                SetBooleanIndicator(_txtScamalyticsGoogle!, d.Proxy.IsGoogle, DraculaColors.Orange);
            }

            _panelScamalytics!.IsVisible = true;
        }
    }
}
