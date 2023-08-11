# Polarity Mandiant Threat Intelligence Integration

Provides automated access to indicators of compromise (IOCs), CVE information, as well as information on the adversary from the Mandiant Threat Intelligence API.

## About Mandiant Threat Intelligence

The Mandiant Threat Intelligence API provides machine-to-machine-integration with the most contextually rich threat intelligence data available on the market today. The API provides automated access to indicators of compromise (IOCs)—IP addresses, domain names, URLs used by threat actors—as well as information on the adversary, to further enrich integrations. The API supports Python, Java, PHP, C++, and C# programming languages.

For more information please see www.FireEye.com/intel

| ![overlay window hash result](assets/hash.png) | ![overlay window ip result](assets/ip.png) | ![overlay window cve result](assets/cve.png) |
|---|--|--|
|*Hash Result* | *IP Result* | *CVE Result*|



## Mandiant Threat Intelligence Integration Options

### API Query Version
Which Version of the API(s) to query: V3, V4, or both.

### Mandiant V3 URL
The URL for the Mandiant Threat Intelligence V3 API.  Defaults to `https://api.intelligence.fireeye.com`.

### V3 Public Key
Your Mandiant Threat Intelligence V3 API public key

### V3 Private Key
Your Mandiant Threat Intelligence V3 API private key.

### Mandiant V4 URL
The URL for the Mandiant Threat Intelligence V4 API.  Defaults to `https://api.intelligence.mandiant.com`.

### V4 Public Key
Your Mandiant Threat Intelligence V4 API public key

### V4 Private Key
Your Mandiant Threat Intelligence V4 API private key.

### Minimum MScore to Display
The minimum MScore (0-100) required for indicators to be displayed [default is 51].  Indicators with a MScore above 50 are considered suspicious and/or malicious.

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
