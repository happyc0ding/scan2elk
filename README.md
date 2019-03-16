# scan2elk
Put your scan results from Nessus, Nmap, testssl etc. into Elasticsearch.

Currently supported (also check https://github.com/happyc0ding/vulnscan-parser!):
* Nessus
* testssl
* Nmap
* sslyze

# Requirements
See requirements.txt, also install https://github.com/happyc0ding/vulnscan-parser (I recommend using "pip install -e" for now).

When using testssl, I recommend the following parameters: `-E -U -S -P -s` in order to produce usable results.

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

Let's assume you have the following files in "/path/to/scan/results":
* file1.nessus (Nessus XML v2)
* host1.xml (Nmap XML)
* host1.json (testssl Json or Json pretty)
```
./scan2elk -dir /path/to/scan/results -project myprojectname
```
This will create several indices for every source:
* finding
* host
* service
* certificate
* cipher

--> Results in i.e. index "finding_nessus_myprojectname" containing all findings, "host_nessus_myprojectname", ..., "host_nmap_myprojectname", ...

You can now query elk:
* (In "host_nessus_myprojectname") ip:10.0.0.1
* (In "finding_nessus_myprojectname") ip:10.0.0.1 AND pluginName:SSL AND severity:>2
* ...

For displaying raw results the script "interactive.py" will help you (tab completion is available for every command!), i.e.:
```
./interactive.py
> setproject myprojectname
> setindices finding_testssl_myprojectname
> settemplate raw
> search NOT severity:OK AND hostname:example.org
> quit
```
or
```
./interactive.py "setproject myprojectname" "setindices finding_testssl_myprojectname" "settemplate raw"
> search NOT severity:OK AND hostname:example.org
```
This will help you for debugging which fields are available and which results your query will produce.
