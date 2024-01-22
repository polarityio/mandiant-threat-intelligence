# Polarity Mandiant Threat Intelligence Integration

Provides automated access to indicators of compromise (IOCs), CVE information, as well as information on the adversary from the Mandiant Threat Intelligence API.

The Polarity Mandiant Threat Intelligence integration allows Polarity to search the Mandiant Threat Intelligence API for indicators of compromise (IOCs) including IP addresses, domain names, emails, URLs, hashes, and CVEs.  The integration also allows Polarity to search for free form text.


| Entity Types                                                                | API Endpoint            | Notes                                                                                                                                                                             |
|-----------------------------------------------------------------------------|-------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CVE                                                                         | /v4/vulnerability       | Results based on selected **Vulnerability Rating Sources** via the integration options                                                                                            |
| Threat Actor (custom.threatActor) -- a string 3 to 30 characters in length. | /v2/actor/{{actorName}} | Search on specific threat actor names (e.g., apt43, UNC3782). The **Enable Threat Actor Search** option must be checked and the "custom.threatActor" entity type must be enabled. 
| IP, MD5, SHA1, SHA256, Domain, Email, URL                                   | /v4/indicator           | Takes into account the **Minimum ThreatScore to Display** integration option when returning results                                                                               |



## About Mandiant Threat Intelligence

The Mandiant Threat Intelligence API provides machine-to-machine-integration with the most contextually rich threat intelligence data available on the market today. The API provides automated access to indicators of compromise (IOCs)—IP addresses, domain names, URLs used by threat actors—as well as information on the adversary, to further enrich integrations. The API supports Python, Java, PHP, C++, and C# programming languages.

For more information please see https://www.mandiant.com/advantage/threat-intelligence

| ![overlay window hash result](assets/hash.png) | ![overlay window ip result](assets/ip.png) | ![overlay window cve result](assets/cve.png) |
|---|--|--|
|*Hash Result* | *IP Result* | *CVE Result*|



## Mandiant Threat Intelligence Integration Options

### Mandiant URL
The URL for the Mandiant Threat Intelligence V4 API.  Defaults to `https://api.intelligence.mandiant.com`. Leave empty if your keys are not compatible with this API version.

### Public Key
Your Mandiant Threat Intelligence API public key

### Private Key
Your Mandiant Threat Intelligence API private key.

### Minimum ThreatScore to Display
The minimum ThreatScore (0-100) required for indicators to be displayed [default is 60].  Indicators with a ThreatScore above 60 are considered malicious.

### Enable Threat Actor Search
If checked, the integration will search threat actors by name.

### Vulnerability Rating Sources
Only return results for Vulnerabilities that come from the Rating Sources selected here.

### Ignored Entities
Comma separated list of entities that you never want looked up. Should be set to "Only admins can view and edit".

### Ignored Domains Regex
Domains that match the given regex will not be looked up (if blank, no domains will be black listed).  Should be set to "Only admins can view and edit".

### Max Concurrent Requests
Maximum number of concurrent requests.  Integration must be restarted after changing this option. Defaults to 20.

### Minimum Time Between Lookups
Minimum amount of time in milliseconds between lookups. Integration must be restarted after changing this option. Defaults to 100.


## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision-making.  For more information about the Polarity platform please see:

https://polarity.io/
