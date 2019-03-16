# scan2elk
Put your scan results from Nessus, Nmap, testssl etc. into Elasticsearch.

Currently supported (also check https://github.com/happyc0ding/vulnscan-parser!):
* Nessus
* testssl
* Nmap
* sslyze

# Requirements
see requirements.txt, also install https://github.com/happyc0ding/vulnscan-parser (I recommend using "pip install -e" for now).

# Configuration and elk mappings
See "config" folder.

# Indices
The data is parsed in several indices:
* finding: Contains finding entries (finding name, severity, ...)
* host: Contains hosts (IP address, hostnames, ...)
* service: Service info (port, protocol, detected service, ...)
* certificate: Parsed X509 certificates (common name, san, fingerprint, ...)
* cipher: Parsed SSL/TLS ciphers (cipher name, bit size, tls protocol, ...)

# Usage
Start elasticsearch (and modify db.yaml if necessary).
```
./scan2elk -dir /path/to/scan/results -project my_project_name
```
This will create several indices for every source:
* finding
* host
* service
* certificate
* cipher

--> i.e. index "finding_nessus_my_project_name" containing all findings, "host_nessus_my_project_name", ..., "host_nmap_my_project_name", ...
