# Polarity Mandiant Threat Intelligence Integration

Provides automated access to indicators of compromise (IOCs), CVE information, as well as information on the adversary from the Mandiant Threat Intelligence API.

## About Mandiant Threat Intelligence

The Mandiant Threat Intelligence API provides machine-to-machine-integration with the most contextually rich threat intelligence data available on the market today. The API provides automated access to indicators of compromise (IOCs)—IP addresses, domain names, URLs used by threat actors—as well as information on the adversary, to further enrich integrations. The API supports Python, Java, PHP, C++, and C# programming languages.

For more information please see www.FireEye.com/intel

> Due to the way collection searches work, when Indicator searching is enabled, the integration requires two lookups per entity.

<img src="./assets/overlay.png" width="50%"/>

## Mandiant Threat Intelligence Options

### Mandiant Threat Intelligence REST URL

The URL for the Mandiant Threat Intelligence API. Defaults to `https://api.intelligence.fireeye.com`.

### Mandiant Threat Intelligence Public Key

Your Mandiant Threat Intelligence API public key

### Mandiant Threat Intelligence Private Key

Your Mandiant Threat Intelligence API private key.

### Enable Indicator Search

If checked, the integration will return Indicator results from the Mandiant Threat Intelligence API. Enabling this option requires the integration to issue an extra REST API lookup request per entity. When disabled, the integration will only return results if an entity is associated with Malware, a Threat Actor or Vulnerability.

### Ignored Entities

Comma separated list of entities that you never want looked up. Should be set to "Only admins can view and edit".

### Ignored Domains Regex

Domains that match the given regex will not be looked up (if blank, no domains will be black listed). Should be set to "Only admins can view and edit".


## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision-making.  For more information about the Polarity platform please see:

https://polarity.io/
