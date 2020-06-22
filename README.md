# Polarity FireEye Intel API Integration

Searches Threat Actors, Malware, Vulnerabilities and Indicators for supported entity types.  

![overlay](./assets/overlay.png)  

## FireEye Intel API Options

### FireEye Intel API REST URL

The URL for the FireEye Intel API. Defaults to `https://api.intelligence.fireeye.com`.

### Intel API Public Key

Your FireEye Intel API public key

### Intel API Private Key

Your FireEye Intel API private key.

### Enable Indicator Search

If checked, the integration will return Indicator results from the FireEye Intel API. Enabling this option requires the integration to issue an extra REST API lookup request per entity.

### Blocklisted Entities

Comma separated list of entities that you never want looked up. Should be set to "Only admins can view and edit".

### Domain Blocklist Regex

Domains that match the given regex will not be looked up (if blank, no domains will be black listed). Should be set to "Only admins can view and edit".


## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision-making.  For more information about the Polarity platform please see:

https://polarity.io/
