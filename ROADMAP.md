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
