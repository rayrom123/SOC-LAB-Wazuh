# SOC Automation Lab: Wazuh, Sysmon, Atomic Red Team, Shuffle SOAR, and Gmail

## Overview

This project is a small SOC automation lab built to simulate, detect, triage, and notify on Windows endpoint security events.

The lab uses Atomic Red Team to generate MITRE ATT&CK-based activity on a Windows endpoint, Sysmon and Wazuh Agent to collect telemetry, Wazuh Manager to detect suspicious behavior, Shuffle SOAR to filter and process alerts, and Gmail API to send incident notifications.

The first validated use case detects Atomic Red Team `T1033` user discovery activity and sends a Gmail alert with an observed end-to-end notification latency of approximately 6 seconds.

## Lab Architecture

The diagram below shows the main alert flow from the Windows endpoint to Wazuh, Shuffle SOAR, and Gmail.

![SOC lab architecture](shuffle%20architecture.png)

```text
Windows 10 Endpoint VM
  - Wazuh Agent
  - Sysmon
  - Atomic Red Team
  - Invoke-AtomicRedTeam
        |
        | Endpoint telemetry
        v
Ubuntu Server VM
  - Wazuh Manager
  - Wazuh Indexer
  - Wazuh Dashboard
        |
        | Wazuh integration webhook
        v
Shuffle SOAR
  - Webhook trigger
  - Python alert filter
  - Gmail API action
        |
        | Incident notification
        v
Gmail
  - SOC_LAB label/filter
```

## Network Layout

```text
Host-only network: 192.168.81.0/24

Ubuntu Wazuh Server: 192.168.81.101
Windows Target VM:   192.168.81.102
```

The host-only network is used for lab communication between Wazuh and the Windows endpoint. NAT is used on both VMs for Internet access when installing packages and tools.

## Components

| Component | Purpose |
|---|---|
| Wazuh Manager | Central SIEM/XDR manager for receiving endpoint telemetry and generating alerts |
| Wazuh Dashboard | Web interface for threat hunting and alert review |
| Wazuh Agent | Installed on the Windows endpoint to forward Windows/Sysmon events |
| Sysmon | Provides detailed Windows process, file, and network telemetry |
| Atomic Red Team | Generates controlled MITRE ATT&CK technique simulations |
| Shuffle SOAR | Receives Wazuh alerts, filters relevant cases, and triggers response actions |
| Gmail API | Sends SOC lab incident notifications |

## Implemented Detection Case

### CASE-001: Atomic T1033 User Discovery

**Goal:** Simulate account/user discovery on a Windows endpoint.

**Atomic Red Team technique:**

```text
T1033 - System Owner/User Discovery
```

**Command executed by Atomic Red Team:**

```text
whoami /all
```

**Observed Wazuh alert:**

```text
Rule ID: 92032
Rule level: 3
Description: Suspicious Windows cmd shell execution
MITRE mapping:
  - T1087 Account Discovery
  - T1059.003 Windows Command Shell
```

**Example evidence:**

```text
Agent: window1
Agent IP: 192.168.81.102
CommandLine: whoami /all
ParentCommandLine: "cmd.exe" /c whoami /all
```

## Planned Detection Cases

### CASE-002: System and Process Discovery

**Goal:** Simulate host and process enumeration after initial command execution.

**Atomic Red Team techniques:**

```text
T1082 - System Information Discovery
T1057 - Process Discovery
T1016 - System Network Configuration Discovery
```

**Expected commands:**

```text
systeminfo
tasklist
ipconfig /all
```

**Expected outcome:**

Wazuh should detect suspicious discovery activity from the Windows endpoint. Shuffle should classify the alert as a discovery case and send a labeled Gmail notification.

### CASE-003: Scheduled Task Persistence

**Goal:** Simulate basic persistence through Windows scheduled tasks.

**Atomic Red Team technique:**

```text
T1053.005 - Scheduled Task/Job: Scheduled Task
```

**Expected command pattern:**

```text
schtasks
```

**Expected outcome:**

Wazuh should detect scheduled task creation or suspicious command execution. Shuffle should classify the alert as a persistence case and send a Gmail notification.

## Shuffle SOAR Workflow

The Shuffle workflow currently follows this structure:

```text
Wazuh webhook
  -> evaluate_rule_level
  -> send_alert_email
```

### Wazuh Integration

Wazuh sends alerts to Shuffle using an integration block in:

```text
/var/ossec/etc/ossec.conf
```

Example structure:

```xml
<integration>
  <name>shuffle</name>
  <hook_url>SHUFFLE_WEBHOOK_URL</hook_url>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

Do not commit real webhook URLs, API keys, OAuth client secrets, or passwords.

### Alert Filtering Logic

The Python step filters Wazuh alerts so Gmail is not flooded by noisy events.

The current logic sends email only when the alert matches one of the selected lab cases:

```text
CASE-001: command line contains whoami
CASE-002: command line contains systeminfo, tasklist, or ipconfig
CASE-003: command line contains schtasks, New-ScheduledTask, or Register-ScheduledTask
```

## Gmail Notification

Gmail notifications use a subject prefix:

```text
[SOC-LAB]
```

A Gmail filter applies the label:

```text
SOC_LAB
```

This keeps lab notifications organized and prevents the inbox from being flooded.

Example email subject:

```text
[SOC-LAB] CASE-001 Atomic T1033 User Discovery
```

Example email body:

```text
SOC Lab Alert

Case: CASE-001 Atomic T1033 User Discovery
Agent: window1
Agent IP: 192.168.81.102
Rule: 92032
Level: 3
Description: Suspicious Windows cmd shell execution

CommandLine:
whoami /all

Parent:
"cmd.exe" /c whoami /all

Timestamp:
2026-09-15T18:11:14.586+0000
```

## Latency Measurement

For the first validated case, Wazuh generated an alert at:

```text
2026-09-15T18:11:14.586+0000
```

Gmail received the notification at:

```text
Tue, 15 Sep 2026 13:11:21 -0500
```

Converted to UTC:

```text
2026-09-15T18:11:21Z
```

Approximate end-to-end latency:

```text
6.4 seconds
```

## Atomic Red Team Commands

Set the Atomic Red Team path:

```powershell
$Atomics = "C:\AtomicRedTeam\atomics"
```

Run CASE-001:

```powershell
Invoke-AtomicTest T1033 -TestNumbers 8 -PathToAtomicsFolder $Atomics
```

Run CASE-002:

```powershell
Invoke-AtomicTest T1082 -TestNumbers 1 -PathToAtomicsFolder $Atomics
Invoke-AtomicTest T1057 -TestNumbers 2 -PathToAtomicsFolder $Atomics
Invoke-AtomicTest T1016 -TestNumbers 1 -PathToAtomicsFolder $Atomics
```

Preview CASE-003 before running:

```powershell
Invoke-AtomicTest T1053.005 -ShowDetailsBrief -PathToAtomicsFolder $Atomics
```

Run and clean up CASE-003:

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1 -PathToAtomicsFolder $Atomics
Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup -PathToAtomicsFolder $Atomics
```

## Screenshots

Add screenshots here:

```text
screenshots/
  wazuh-agent-active.png
  wazuh-threat-hunting-t1033.png
  shuffle-workflow.png
  shuffle-run-success.png
  gmail-soc-lab-label.png
```

## Current Status

- Wazuh Manager is deployed on Ubuntu Server.
- Windows endpoint is registered and active in Wazuh.
- Sysmon events are collected by Wazuh.
- Atomic Red Team is installed and able to run `T1033`.
- Wazuh alerts are forwarded to Shuffle through webhook integration.
- Shuffle filters matching Atomic case alerts.
- Gmail API sends incident notifications.
- Gmail label `SOC_LAB` is used to organize SOC lab notifications.

## Roadmap

- Add CASE-002 and CASE-003 to the Shuffle filtering logic.
- Add VirusTotal enrichment for hashes, IP addresses, and domains.
- Add TheHive case creation for selected high-value alerts.
- Build a C# SOC dashboard that stores Wazuh and Shuffle alerts in SQLite.
- Add incident timeline visualization per Atomic Red Team scenario.
- Add false positive handling and analyst verdicts.

## Security Notes

- This lab is intended for local, controlled security testing only.
- Do not run destructive Atomic Red Team tests without reviewing their commands.
- Do not commit credentials, OAuth client secrets, API keys, or webhook URLs.
- Keep attack simulation inside the lab network.

## Resume Bullet

```text
Built a MITRE ATT&CK-based SOC automation lab using Wazuh, Sysmon, Atomic Red Team, Shuffle SOAR, and Gmail API to detect Windows endpoint discovery behavior, filter noisy alerts, and send labeled incident notifications with approximately 6-second end-to-end latency.
```
