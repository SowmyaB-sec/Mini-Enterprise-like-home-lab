# Building a realistic SIEM + SOAR environment with multi-cloud log ingestion, custom detections, and automated response using Azure Arc and Microsoft Sentinel

### 1. Project Overview

This project involved designing and implementing a realistic and practical Security Information and Event Management (SIEM) and Security Orchestration, Automation and Response (SOAR) laboratory environment using Microsoft Sentinel. The goal was to create an end-to-end security operations environment capable of:
-	Ingesting authentication logs from a non-Azure Linux host 
-	Detecting simulated brute-force attacks using custom KQL 
-	Automatically notifying a SOC analyst via a Logic App playbook 
-	Providing visual evidence of detections for investigation

Due to technical restrictions inherent in the Azure for Students subscription (limited VM SKUs and regional availability), a hybrid multi-cloud approach was adopted. A free-tier Ubuntu virtual machine hosted on Oracle Cloud Infrastructure was onboarded into Azure using Azure Arc, allowing authentic Linux authentication logs to be collected and analysed within Microsoft Sentinel.
 
----

### 2. Objectives
-	Deploy Microsoft Sentinel on a cost-controlled Log Analytics workspace 
-	Onboard an external Linux machine using Azure Arc
-	Collect real Linux authentication (Syslog) data 
-	Develop custom detection logic for SSH brute-force attacks (MITRE ATT&CK T1110)
-	Implement automated response using Azure Logic Apps 
-	Document the full SOC workflow: log collection → detection → automated notification 
-	Maintain strict cost control within the $100 educational credit

----

### 3. Core Stack
Core stack:
-	**Microsoft Sentinel** — SIEM/SOAR platform
-	**Log Analytics Workspace** — log storage and query engine (KQL)
-	**Azure Arc** — connects a non-Azure VM (Oracle Cloud) into Azure's management plane
-	**Azure Monitor Agent (AMA) + Data Collection Rules (DCR)** — log forwarding pipeline
-	**Oracle Cloud Always Free Tier (Ampere VM, Ubuntu 22.04)** — the internet-facing	Linux host generating real Syslog/auth data
-	**Azure Logic Apps** — SOAR-style automated detection and alerting

----

### 4. Architecture 
<img width="742" height="1251" alt="Architecture diagram" src="https://github.com/user-attachments/assets/65cea7b0-057c-4d78-888a-55cb566f98ae" />

No traditional databases, queues or storage accounts were used beyond the log analytics workspace (which acts as the central log database). 

----

### 5. Methodology
Chosen Methodology: Hybrid Multi-Cloud with Azure Arc
**Reason/Justification**
-	Azure Arc is Microsoft’s officially supported mechanism for managing and monitoring non-Azure machines. 
-	It allowed real Linux authentication telemetry to be collected without depending on restricted Azure VM SKUs. 
-	Oracle Cloud Always Free tier provided a permanent, zero-cost Linux host. 
-	The approach still fully satisfied the original project goals: multi-source capable SIEM, detection engineering, and SOAR.

----

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

----

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
<img width="302" height="513" alt="Query 1" src="https://github.com/user-attachments/assets/884b9bb1-cdc8-4e23-b911-303bba9bbb6c" />

The query found 3 five-minute bursts of repeated authentication failures on linux-siem-lab.
-	The largest spike was 42 failed attempts in one 5-minute window from 1 source IP, spread across 10 usernames.
-	A second burst had 15 failed attempts from 2 source IPs across 4 usernames.
-	A smaller burst had 6 failed attempts from 1 source IP across 3 usernames.

| Time bin (UTC)	| Computer	| Failed attempts	| Distinct users	| Usernames seen	 | Source IPs seen | 
|------|-----|------|-------|-------|--------|
|2026-08-07 14:55	| linux-siem-lab | 	42	| 10	| admin, oracle, usuario, test, user, ftpuser, test1, test2, pi, baikal	| ⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛ |
|2026-08-08 12:15	| linux-siem-lab	| 15 |	4	|  baduser, suser, juser, kuser	| ⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛/⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛ |
| 2026-08-08 10:55	| linux-siem-lab|	6	| 3	| baduser, juser, suser	| ⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛ |

**Interpretation**
-	This pattern is more consistent with automated password guessing or credential stuffing than with a single user mistyping a password.
-	The first burst is especially notable because it tried many different usernames from one IP, which is a common sign of a scanning or brute-force pattern.
-	The later bursts re-use some of the same usernames, suggesting the activity may be repeated probing rather than isolated noise.
  
**What this means operationally**
-	If the host is internet-facing, these patterns would suggest potential intrusion attempts.
-	If the host is internal-only, it could still indicate malicious lateral probing or a misconfigured automation job repeatedly authenticating with bad credentials.
-	This query only shows failed auth events where a username could be extracted, so the true total could be higher if some messages didn’t match the parsing pattern.


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
<img width="377" height="316" alt="Query 2" src="https://github.com/user-attachments/assets/5c0dc6a2-beae-493f-a208-ea62b56db895" />

**What the query found**
-	It returned 1 high-severity match on linux-siem-lab.
-	The same source IP, ⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛, generated 29 SSH failures before a successful login.
-	Timing was notable as the failure and successful login happened with very little time difference. The first failure was at 2026-08-08 10:56:26 UTC, and the successful login happened at 2026-08-08 10:57:16 UTC.
-	The failed usernames included juser, suser, and baduser.


**Interpretion**
-	This pattern is consistent with brute-force or credential-stuffing behavior, especially because success followed shortly after many failures from the same IP.
-	One important thing to notice/remember is that the query correlates by computer + source IP, not by exact username, so the failed usernames and successful username may not be the same account.

**3. Recent Failed Login Events**
```
Syslog
| where TimeGenerated > ago(6h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage has_any ("Failed password", "authentication failure", "Invalid user")
| summarize FailedAttempts = count() by bin(TimeGenerated, 15m)
| order by TimeGenerated asc
```
<img width="286" height="242" alt="Query 3-1" src="https://github.com/user-attachments/assets/3b1ff32b-8142-4422-846e-7ac9c52f08c4" />

<img width="1398" height="511" alt="Query 3-2" src="https://github.com/user-attachments/assets/d2014321-4169-4889-8836-afd2be2ec19c" />


**What this query found**
The executed query found 54 failed authentication attempts in the last 6 hours, spread across 5 non-empty 15-minute buckets.
|UTC time bucket|	Failed attempts	|Interpretation|
|-----|----|----|
|10:45	| 12	 | Moderate burst of failures |
|11:00	| 8 |	Still elevated |
|11:15	|2	| Activity dropped off |
| 11:30	|2	 | Low level continued|
| 12:15	| 30	| Largest spike in the window |

**Interpretation**
-	This looks like repeated failed login activity, likely from one or more sources trying SSH or another auth path on the Linux host.
-	Because the query only counted failures, it does not tell us whether any successful logins happened before or after these attempts.


**4. Hunting Query**
```
Syslog
| where Facility in ("auth", "authpriv")
| where SyslogMessage has_any ("Failed password", "authentication failure", "Invalid user")
| extend SourceIP = extract(@"from (\S+)", 1, SyslogMessage)
| extend TargetUser = extract(@"for (invalid user )?(\S+)", 2, SyslogMessage)
| summarize FailedAttempts = count(), Users = make_set(TargetUser), IPs = make_set(SourceIP) by Computer, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| sort by FailedAttempts desc
| extend Detection="Potential SSH Brute Force"
| project TimeGenerated, Computer, FailedAttempts, Users, IPs
```

<img width="1020" height="370" alt="Query 4-1" src="https://github.com/user-attachments/assets/3fec1216-c945-4271-b3f6-13af068e2f42" />

<img width="1305" height="430" alt="Query 4-2" src="https://github.com/user-attachments/assets/0cdc733f-45eb-4d65-892a-c135d8804772" />


**What the query found**
The results are consistent with repeated SSH login failures against linux-siem-lab over the last 24 hours, which is a common pattern for a brute-force or password-spraying attempt.

|Time (UTC) | 	Computer	| Failed attempts|	Notable pattern|
|----|------|-----|------|
|2026-08-07 14:55	|linux-siem-lab	|68	| Largest burst; multiple usernames tried|
| 2026-08-08 12:15	| linux-siem-lab |	30	| Two source IPs seen in the same 5-minute window|
| 2026-08-07 13:05	| linux-siem-lab	| 12	| Multiple source IPs |
| 2026-08-08 10:55	| linux-siem-lab	| 12	| Repeated source activity |
| 2026-08-07 13:00 / 14:10 / 14:15 / 14:00 / 13:30 / 11:05 |	linux-siem-lab |	6 | each	Smaller but recurring clusters |

**Interpretation**
-	The 68-attempt spike with many usernames (admin, oracle, usuario, test, user, ftpuser, test1, test2) is the strongest indicator of automated credential guessing.
-	The same host keeps appearing in multiple buckets, so this looks like persistent targeting, not a one-off typo or user mistake.
-	The extracted Users and IPs fields include some empty/odd values because the regex pulls data directly from log text; that means the detection is useful, but the field parsing is a bit noisy.

**5.	Top IP'S**
```
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage has_any ("Failed password", "Invalid user")
| extend SourceIP = extract(@"from ([0-9\.]+)", 1, SyslogMessage)
| where isnotempty(SourceIP)
| summarize Attempts = count() by SourceIP
| top 10 by Attempts
| render barchart
```

<img width="230" height="338" alt="Query 5-1" src="https://github.com/user-attachments/assets/d5127e85-b96e-4ada-8489-966c738f8862" />

<img width="1209" height="422" alt="Query 5-2" src="https://github.com/user-attachments/assets/2dbbde29-9236-4fee-ac5b-61007366c0b9" />



The query shows failed SSH authentication activity from 10 source IPs in the last 24 hours, which is a common pattern for password spraying or brute-force probing.

| Source IP	| Failed attempts |
|------------|-----------|
|⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛|	42|
|⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛|	31 |
|⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛	| 17|
|⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛|	7|
|⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛	| 7|
|⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛|	5|
|⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛|	1 |
| ⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛|	1|
|⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛|	1|
|⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛|	1|

**What the query means**
-	The activity is concentrated: the top 3 IPs account for 90 of 113 attempts.
-	The log filters (auth / authpriv, plus Failed password / Invalid user) mean this is login failure evidence, not normal traffic.
-	This looks more like hostile authentication probing than an application issue.

----

### 8. Automated Response - Azure Logic App (SOAR)

An Azure Logic App (Consumption plan) was created to act as the automated response playbook. The playbook was designed with the following logic:

**1. Trigger**  
   A Recurrence trigger was configured to run the playbook at regular intervals (every 10 minutes during testing).

**2. Data Retrieval**
   The playbook executes a KQL query against the Log Analytics workspace to retrieve recent failed SSH authentication events that meet the brute-force threshold (≥ 5 failed attempts within a 5-minute window).

**3. Condition Evaluation**
   A Condition control was added to evaluate the query results:
   - *If* the query returns one or more matching records (i.e., a potential brute-force attack is detected),
   - *Then* proceed to the notification action.
   - *Else* take no further action (to avoid alert fatigue).

**4.Automated Response Action**  
   When the condition evaluates to true, the playbook sends an email notification to a designated SOC analyst address. The email contains a clear subject line and body indicating that Linux SSH brute-force activity has been detected and requires investigation.
 
 <img width="526" height="669" alt="Logic Apps designer" src="https://github.com/user-attachments/assets/84831788-1559-4981-8e46-bf5290b35c26" />

 <img width="497" height="469" alt="Recurrence" src="https://github.com/user-attachments/assets/d8355ced-8861-466f-82a5-bc7a8d514bb9" />

 <img width="561" height="545" alt="Query code" src="https://github.com/user-attachments/assets/c4b8749b-4f47-4f77-b035-caa0fbd97f75" />




**Why This Approach?**
- Demonstrates real SOAR principles: *orchestration* (querying Sentinel data), *automation* (scheduled execution + conditional logic), and *response* (email notification).
- Works even though the full Microsoft Sentinel Analytics / Automation Rules interface was restricted due to portal migration and permission limitations.
- Keeps the solution cost-effective (Logic Apps Consumption plan only incurs charges when the playbook runs).

----
### 9.	MITRE ATT&CK Mapping

| Technique ID	| Technique Name	| Implementation |
|--------|----------|----------|
|T1110|	Brute Force	|Custom KQL detection on failed SSH authentication |
| T1078	| Valid Accounts	| Monitoring of successful logins after failures |
| T1021.004	| Remote Services: SSH	| Primary attack surface monitored |


