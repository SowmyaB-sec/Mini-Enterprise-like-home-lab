# Mini-Enterprise-like-home-lab

Architecture & Environment Setup

This project implements a small enterprise-style Active Directory environment for detection engineering practive. The lab simulates a realistic corporate setup consisting of a Domain Controller, a domain-joined endpoint, an attacker workstation, and a dedicated SIEM platform. All components are isolated in a virtual environment (VirtualBox) to ensure safety. 

The environment was build/developed using VirtualBox on a Windows 11 Host Machine with a storage limit of 100GB. Dynamic (thin-provisioned) disks were used to optimize storage usage. 

Infrastructure Components

| Machine Name | Operating System |
| DC01    | Windows Server 2022|
|WIN10-CLIENT | Windows 10 |
|Attacker | Kali Linux |
|SIEM | Ubuntu 22.04|
