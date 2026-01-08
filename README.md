# Web Sploit 
A bug bounty automation framework that automates enumeration and vulnerability discovery for web applications.

### Subdomain Enumeration Module

<img width="1516" height="720" alt="image" src="https://github.com/user-attachments/assets/534533fc-9796-40c3-bd89-cc64ceb363e3" />

#### Passive Subdomains Enumeration
Collect subdomains from various DNS data providers.

Free Sources:
- anubis
- commoncrawl
- crtsh
- digitorus
- hackertarget
- rapiddns
- sitedossier
- threatcrowd
- waybackarchive
- hudsonrock

Paid Sources:
- c99
- security trails
- virus total
- choas
- shodan
- digital yama
- pugrecon
- dns dumpster

#### Active Subdomains Enumeration 
Generate permutations using Gemini.
Brute forces to check for live ones.

#### Web fingerprinting 

For live subdomains, fingerprint web applications (URL, Status Code, Content Length and Tech Stack).

#### DNS Enumeration 
Get CNAMEs & IPs for live targets
