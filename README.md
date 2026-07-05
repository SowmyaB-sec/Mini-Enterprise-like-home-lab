# Mini-Enterprise-like-home-lab

### Architecture & Environment Setup

This project implements a small enterprise-style Active Directory environment for detection engineering practive. The lab simulates a realistic corporate setup consisting of a Domain Controller, a domain-joined endpoint, an attacker workstation, and a dedicated SIEM platform. All components are isolated in a virtual environment (VirtualBox) to ensure safety. 

The environment was build/developed using VirtualBox on a Windows 11 Host Machine with a storage limit of 100GB. Dynamic (thin-provisioned) disks were used to optimize storage usage. 

### Infrastructure Components

| Machine Name | Operating System | Role | IP Address | vCPU | RAM | Disk (Allocated) |
|---------------|------------------|------|------------|------|-----|------------------|
| DC01 | Windows Server 2022 | Domain Controller + DNS | 192.168.10.10 | 2 | 4 GB | 40 GB |
| WIN10-CLIENT | Windows 10 | Domain-joined Workstation | 192.168.10.20 | 2 | 4 GB | 35-40 GB |
| ATTACKER | Kali Linux | Red Team / Attack Platform | 192.168.10.30 | 2 | 2-4 GB | 20-25 GB |
| SIEM | Ubuntu 22.04/24.04 | Wazuh SIEM Server | 192.168.10.40 | 2 | 4-6 GB | 30-40 GB |


**Total allocated disk space:** ~125-145 GB 

### Network Layout:
- **Network Type:** Isolated Internal Network (AD_LAB)
- **Subnet:** DC01 (192.168.10.10) - This serves as the primary DNS server for the entire lab
- No internet access during the attack simulations (This is temporaily enabled for updates and tool downloads)

### Logging Flow:
Windows Even Logs + Sysmon &rarr; Wazuh Agnet (on the windows host ) &rarr; Wazuh Manager (on ubuntu) &rarr; wazuh dashboar + Elasticsearch
