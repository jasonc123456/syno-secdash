# Third-party notices

SecDash bundles or downloads the following third-party components.

| Component | Version | License | Location |
|---|---|---|---|
| [MaxMind DB Python reader](https://github.com/maxmind/MaxMind-DB-Reader-python) | 2.6.3 (pure-Python mode) | Apache-2.0 | `package/lib/vendor/maxminddb/` (license included) |
| [Chart.js](https://www.chartjs.org/) | 4.5.1 | MIT | `package/ui/vendor/chart.umd.min.js` |
| [jsVectorMap](https://github.com/themustafaomar/jsvectormap) | 1.7.0 | MIT | `package/ui/vendor/jsvectormap.min.*`, `world.js` |
| [Twemoji Country Flags](https://github.com/talkjs/country-flag-emoji-polyfill) font | 0.1.10 | font build MIT; flag art from [Twemoji](https://github.com/jdecked/twemoji), CC BY 4.0 | `package/ui/vendor/TwemojiCountryFlags.woff2` |
| [DB-IP Lite databases](https://db-ip.com/db/lite.php) | monthly | CC BY 4.0 | Country Lite is bundled at build time; City Lite and ASN Lite are downloaded on the NAS |
| [IANA RDAP bootstrap registry](https://data.iana.org/rdap/) | ipv4 2019-06-07, ipv6 2024-11-01 | public registry data from IANA | `package/lib/rdap_bootstrap.json` |

IP geolocation data is provided by [DB-IP](https://db-ip.com) under the
[Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/).
The dashboard shows this attribution in its footer.

Country flag artwork is from Twemoji (Copyright Twitter, Inc. and other contributors),
licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), via the
"Twemoji Country Flags" font subset by TalkJS (MIT). The dashboard credits it in its footer.

"Synology" and "DSM" are trademarks of Synology Inc. This project is not
affiliated with or endorsed by Synology Inc.
