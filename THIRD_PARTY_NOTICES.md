# Third-party notices

The following bundled assets have licenses separate from the CSO Toolbox source code.

## Inconsolata

`Client/Resources/Inconsolata-Regular.ttf` is Inconsolata, Copyright 2006 The Inconsolata Project Authors. It is licensed under the SIL Open Font License, Version 1.1. The license text is included in [licenses/OFL-1.1.txt](licenses/OFL-1.1.txt). Upstream source: [googlefonts/Inconsolata](https://github.com/googlefonts/Inconsolata).

## Twemoji Mozilla

`Client/Resources/TwemojiCountryFlags.ttf` identifies itself as Twemoji Mozilla. The font project is maintained by Mozilla and incorporates Twemoji artwork, which is licensed under CC BY 4.0. See the upstream [Mozilla font project license](https://github.com/mozilla/twemoji-colr/blob/master/LICENSE.md) for the separate code and artwork terms. The artwork attribution and license are available at [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

## Service icons

`Client/Resources/Services/` contains small icons named for external services. The former icon-fetching script recorded these source URLs:

| Icon | Source |
| --- | --- |
| `abuseipdb.png` | [abuseipdb.com](https://www.abuseipdb.com/favicon-32x32.png) |
| `virustotal.png` | [virustotal.com](https://www.virustotal.com/gui/images/favicon.svg) |
| `bazaar.png` | [bazaar.abuse.ch](https://bazaar.abuse.ch/favicon) |
| `threatfox.png` | [threatfox.abuse.ch](https://threatfox.abuse.ch/favicon) |
| `scamalytics.png` | [scamalytics.com](https://scamalytics.com/wp-content/uploads/2016/06/icon_128.png) |
| `circl.png` | [circl.lu](https://circl.lu/favicon) |
| `shodan.png` | [shodan.io](https://www.shodan.io/static/img/favicon.png) |
| `whois.png` | [lookup.icann.org](https://lookup.icann.org/favicon) |
| `dns.png` | [cloudflare.com](https://cloudflare.com/favicon) |
| `mac.png` | [macaddress.io](https://macaddress.io/images/favicon_package/fav-6x.png) |
| `base64.png` | [base-64.com](https://base-64.com/favicon.ico) |
| `netuser.png` | [microsoft.com](https://www.microsoft.com/favicon.ico) |
| `rdap.png` | Source not recorded |

These files identify external services; they are not project logos. Their source URLs are not proof of redistribution permission. Confirm each provider's terms before shipping them in release packages, and replace any asset that cannot be redistributed. Confirm the provenance and terms for the app icon as well.

## Other dependencies

The .NET and Python dependencies are declared in `Client/Client.csproj` and `Server/requirements.txt`. Consult each dependency's license and include any notices required for a binary release.
