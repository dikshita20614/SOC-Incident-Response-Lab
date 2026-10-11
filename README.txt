# Enterprise Security Operations & Threat Hunting Lab (SIEM / KQL / Incident Response)

## Executive Summary
This project demonstrates an end-to-end Security Operations Center (SOC) workflow covering **Detection Engineering**, **Packet Analysis**, **Active Incident Containment**, and **Cloud-Native SIEM Threat Hunting**. 

The lab is structured into three progressive modules:
1. **Module 1:** Malware Execution, C2 Network Triage & Automated Firewall Mitigation
2. **Module 2:** IAM Brute-Force Analytics & Log Aggregation in Splunk
3. **Module 3:** Cloud SIEM Threat Hunting & Detection Engineering in Microsoft Sentinel (SC-200 Aligned)

---

## 🛠️ Core Skills & Tools Demonstrated
* **SIEM Platforms:** Splunk Enterprise, Microsoft Sentinel
* **Query Languages:** Kusto Query Language (KQL), Splunk Search Processing Language (SPL)
* **Network Analysis:** Wireshark, Protocol Filtering, TCP C2 Tracking
* **Host Security & Mitigation:** Windows PowerShell, Windows Defender Firewall
* **Framework Alignment:** MITRE ATT&CK (Execution, Initial Access, Command and Control)

---

## 🔍 Module 1: Malware Execution & Network Containment

### 1. Process Creation Logging (Splunk)
Monitored endpoint telemetry to catch suspicious process creation (`Invoice.exe` / Event ID 4688), revealing parent process execution via command prompt.

![Splunk Process Log](assets/splunk_process_log.png)

### 2. Network Triage (Wireshark)
Captured and analyzed network packets on local interfaces to identify outbound TCP C2 communication attempts targeting non-standard ports.

![Wireshark Traffic Capture](assets/wireshark_c2.png)

### 3. Incident Containment (Windows Firewall)
Executed a Host-Based Containment action via PowerShell, adding an outbound firewall rule to isolate and block outbound traffic to malicious IP indicators.

![Firewall Block Rule](assets/firewall_block.png)

---

## 🔐 Module 2: IAM Brute-Force Aggregation (Splunk)

Analyzed Windows Security Event logs for repeated authentication failures (`EventCode=4625`). Built an aggregated statistical table grouping logons by workstation, source, and time to detect initial access brute-force campaigns.

![Splunk IAM Brute Force Table](assets/splunk_iam_bruteforce.png)

```spl
index=* EventCode=4625 | stats count by _time, source, EventCode


---

## ☁️ Module 3: Cloud SIEM & KQL Threat Hunting (Microsoft Sentinel)

Aligned with the **Microsoft SC-200 (Security Operations Analyst)** framework, this module showcases proactive threat hunting and detection engineering inside **Microsoft Sentinel** and **Microsoft Defender**.

### 1. Workspace Ingestion & Connector Overview
Configured Log Analytics Workspace (`soc-sentinel-workspace`) and established active data connectors to stream cloud identity and authorization logs.

![Sentinel Overview Dashboard](assets/sentinel_overview.png)

### 2. KQL Proactive Threat Hunting
Wrote custom **Kusto Query Language (KQL)** queries to identify non-interactive sign-in anomalies across identities and IP ranges.

![KQL Threat Hunting](assets/kql_threat_hunting.png)

```kql
AADNonInteractiveUserSignInLogs
| summarize SignInCount = count() by UserPrincipalName, IPAddress, ResultType
| order by SignInCount desc