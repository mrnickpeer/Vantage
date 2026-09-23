# Vantage - Roadmap & Future Enhancements

## Planned Features (v3.0 Candidate)

### 1. Visual Link Analysis (Node Graphing)
**The Problem:** 
Currently, Vantage presents its findings in clean, tactical data cards. However, infrastructure investigations are inherently relational. A single IP address might host 15 domains, and those domains might share a single SSL certificate (crt.sh), which might be registered to one specific ASN. 

**The Improvement:** 
Implement a lightweight, built-in **Visual Node Graph** (similar to Maltego or SpiderFoot) using a library like Cytoscape.js or D3.js. 

**How it works:** 
When the analyst types in a domain, Vantage automatically draws a central node. As the WHOIS, DNS, and Certificate modules finish running, it visually branches out into connected nodes. 

**Why it matters:** 
SOC analysts are highly visual. Allowing them to physically see the web of infrastructure—and double-click an IP node to pivot and expand the graph further—would turn Vantage into a full-blown threat-hunting canvas right inside the browser.

### 2. Automated Tech-Stack Fingerprinting
**The Problem:**
Vantage excels at enumerating subdomains, DNS records, and mapping out infrastructure topology. However, knowing that a subdomain exists is only the first step; analysts also need to know what services and technologies are running on those endpoints to evaluate potential attack surfaces.

**The Improvement:**
Introduce **Automated Tech-Stack Fingerprinting** for discovered endpoints.

**How it works:**
When Vantage discovers a subdomain or IP, it performs a lightweight HTTP header analysis and basic fingerprinting (similar to Wappalyzer). It identifies the server environment, CMS, frameworks, and CDNs (e.g., Nginx, WordPress, AWS, React, Cloudflare) and applies sleek, visually distinct badges next to each node in the dashboard.

**Why it matters:**
This instantly upgrades Vantage from a raw enumeration tool to a comprehensive reconnaissance dashboard. It allows analysts to immediately map a target's technological attack surface at a glance, highlighting high-value targets (like outdated CMS instances or exposed dev environments) without requiring manual inspection.
