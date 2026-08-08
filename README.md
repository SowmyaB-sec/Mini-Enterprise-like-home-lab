# Building a realistic SIEM + SOAR environment with multi-cloud log ingestion, custom detections, and automated response using Azure Arc and Microsoft Sentinel

### 1. Project Overview

This project involved designing and implementing a realistic and practical Security Information and Event Management (SIEM) and Security Orchestration, Automation and Response (SOAR) laboratory environment using Microsoft Sentinel. The goal was to create an end-to-end security operations environment capable of:
-	Ingesting authentication logs from a non-Azure Linux host 
-	Detecting simulated brute-force attacks using custom KQL 
-	Automatically notifying a SOC analyst via a Logic App playbook 
-	Providing visual evidence of detections for investigation

Due to technical restrictions inherent in the Azure for Students subscription (limited VM SKUs and regional availability), a hybrid multi-cloud approach was adopted. A free-tier Ubuntu virtual machine hosted on Oracle Cloud Infrastructure was onboarded into Azure using Azure Arc, allowing authentic Linux authentication logs to be collected and analysed within Microsoft Sentinel.
 

### 2. Objectives
-	Deploy Microsoft Sentinel on a cost-controlled Log Analytics workspace 
-	Onboard an external Linux machine using Azure Arc
-	Collect real Linux authentication (Syslog) data 
-	Develop custom detection logic for SSH brute-force attacks (MITRE ATT&CK T1110)
-	Implement automated response using Azure Logic Apps 
-	Document the full SOC workflow: log collection → detection → automated notification 
-	Maintain strict cost control within the $100 educational credit


### 3. Core Stack
Core stack:
-	**Microsoft Sentinel** — SIEM/SOAR platform
-	**Log Analytics Workspace** — log storage and query engine (KQL)
-	**Azure Arc** — connects a non-Azure VM (Oracle Cloud) into Azure's management plane
-	**Azure Monitor Agent (AMA) + Data Collection Rules (DCR)** — log forwarding pipeline
-	**Oracle Cloud Always Free Tier (Ampere VM, Ubuntu 22.04)** — the internet-facing	Linux host generating real Syslog/auth data
-	**Azure Logic Apps** — SOAR-style automated detection and alerting

### 4. Architecture 

No traditional databases, queues or storage accounts were used beyond the log analytics workspace (which acts as the central log database). 

### 5. Methodology
Chosen Methodology: Hybrid Multi-Cloud with Azure Arc
**Reason/Justification**
-	Azure Arc is Microsoft’s officially supported mechanism for managing and monitoring non-Azure machines. 
-	It allowed real Linux authentication telemetry to be collected without depending on restricted Azure VM SKUs. 
-	Oracle Cloud Always Free tier provided a permanent, zero-cost Linux host. 
-	The approach still fully satisfied the original project goals: multi-source capable SIEM, detection engineering, and SOAR.

### 6. Implementation Summary

**Phase 1 – Foundation & Cost Governance**
-	Created a dedicated Resource Group. 
-	Configured Azure Cost Management budgets and alerts ($50 / $80 / $100 thresholds). 
-	Created a Log Analytics workspace 
-	Enabled Microsoft Sentinel on the workspace  
-	Applied a daily data ingestion cap of 1 GB to protect the educational credit.

**Phase 2 – Data Source Acquisition (Critical Challenge)**
Attempted to deploy native Azure Windows and Linux virtual machines; Native Azure VMs were not chosen as they were unfeasible within the educational subscription constraints.

**Phase 3 – Multi-Cloud Solution using Azure Arc**
-	Provisioned an Always Free Ubuntu 22.04 virtual machine on Oracle Cloud Infrastructure. 
-	Installed and configured the Azure Connected Machine agent (Azure Arc). 
-	Successfully onboarded the non-Azure machine into the Azure control plane. 
-	Deployed the Azure Monitor Agent (AMA) extension onto the Arc-enabled machine. 
-	Created a Data Collection Rule (DCR) targeting the auth and authpriv Syslog facilities at Information level — the facilities that contain SSH authentication events.

**Phase 4 – Validation of Data Ingestion**
-	Confirmed Heartbeat records from the Arc machine. 
-	Confirmed Syslog records arriving in the Log Analytics workspace. 
-	Generated controlled failed SSH authentication attempts from an external machine. 
-	Verified that the failed login events were correctly parsed and queryable in the Syslog table.

**Phase 5 – Detection Engineering**
-	Developed and validated custom KQL detection queries focused on MITRE ATT&CK technique T1110 (Brute Force). 
-	Primary detection: Multiple failed SSH authentication attempts (≥ 5) within a 5-minute window on the same host. 
-	Secondary detection concept: Successful authentication following a series of failures (possible credential compromise). 
-	Queries were saved for reuse and documentation.

**Phase 6 – Automated Response (SOAR)**
-	Designed and deployed an Azure Logic App (Consumption plan). 
-	Configured recurrence trigger
-	The playbook periodically executes the brute-force detection query – Action: Run the brute-force KQL query against the Log Analytics workspace
-	When matching events are found, it sends an email notification to a designated “SOC” address. 
-	This demonstrates automated alerting without requiring a fully functional Analytics rule UI (which had been migrated to the Microsoft Defender portal and was inaccessible due to Entra ID role limitations).

### 7. KQL Queries, Results and Findings

**1.	Detection – Linux SSH Brute Force**
```
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage has_any ("Failed Password", "authentication failure", "Invalid user", "Failed none")
| extend SourceIP =  extract(@"from ([0-9\.]+)", 1, SyslogMessage)
| extend TargetUser = case(
    SyslogMessage matches regex @"Invalid user \S+", extract(@"Invalid user (\S+)", 1, SyslogMessage),
    SyslogMessage matches regex @"for invalid user \S+", extract(@"for invalid user (\S+)", 1, SyslogMessage),
    SyslogMessage matches regex @"for \S+", extract(@"for (\S+)", 1, SyslogMessage),
    SyslogMessage matches regex @"user=\S+", extract(@"user=(\S+)", 1, SyslogMessage),
    ""
)
| where isnotempty(TargetUser)
| summarize 
    FailedAttempts = count(),
    DistinctUsers = dcount(TargetUser),
    Users = make_set(TargetUser, 10),
     SourceIPs = make_set(SourceIP, 10)
    by Computer, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| project TimeGenerated, Computer, FailedAttempts, DistinctUsers, Users, SourceIPs
| sort by FailedAttempts desc
```
The query found 3 five-minute bursts of repeated authentication failures on linux-siem-lab.
-	The largest spike was 42 failed attempts in one 5-minute window from 1 source IP, spread across 10 usernames.
-	A second burst had 15 failed attempts from 2 source IPs across 4 usernames.
-	A smaller burst had 6 failed attempts from 1 source IP across 3 usernames.

**2.	Detection - Successful Logins after failed Logins**

```
Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage has_any ("Invalid user", "Failed password", "authentication failure")
| extend SourceIP = extract(@"from ([0-9\.]+)", 1, SyslogMessage)
| extend TargetUser = extract(@"Invalid user (\S+)", 1, SyslogMessage)
| where isnotempty(SourceIP)
| project Computer, SourceIP, TargetUser, FailureTime = TimeGenerated
| join kind=inner (
    Syslog
    | where TimeGenerated > ago(24h)
    | where SyslogMessage has_any ("Accepted password", "Accepted publickey")
    | extend SourceIP = extract(@"from ([0-9\.]+)", 1, SyslogMessage)
    | extend TargetUser = extract(@"for (\S+)", 1, SyslogMessage)
    | where isnotempty(SourceIP)
    | project Computer, SourceIP, TargetUser, SuccessTime = TimeGenerated
    )
    on Computer, SourceIP
| where SuccessTime > FailureTime
| summarize
    FailureCount = count(),
    FirstFailure = min(FailureTime),
    SuccessfulLogin = min(SuccessTime),
    Users = make_set(TargetUser)
    by Computer, SourceIP
| where FailureCount >= 3
| extend Detection = "Successful Login After SSH Failures"
| extend Severity = "High"
| project
    Detection,
    Severity,
    Computer,
    SourceIP,
    FailureCount,
    Users,
    FirstFailure,
    SuccessfulLogin
```
| Time bin (UTC)	| Computer	| Failed attempts	| Distinct users	| Usernames seen	 | Source IPs seen | 
|------|-----|------|-------|-------|--------|
|2026-08-07 14:55	| linux-siem-lab| 	42	| 10	| admin, oracle, usuario, test, user, ftpuser, test1, test2, pi, baikal	|  <mark style="color: black; background-color: black;">220.85.210.200</mark> |
2026-08-08 12:15	linux-siem-lab	15	4	baduser, suser, juser, kuser	89.101.203.182 / 140.238.73.67
2026-08-08 10:55	linux-siem-lab	6	3	baduser, juser, suser	89.101.203.182


