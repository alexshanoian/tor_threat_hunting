<img width="150" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/alexshanoian/tor_threat_hunting/blob/main/tor_threat_hunting_event_creation.md) 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "as21" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-05-29T16:19:10.5186936Z`. These events began at `2025-05-29T16:05:49.8468302Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "alex-threat-hun"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "as21"
| where Timestamp >= datetime(2025-05-29T16:05:49.8468302Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/6e7f515a-97b5-4002-b49f-215befeb1789">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents for any ProcessCommandLine that contained the string ‘tor-browser-windows-x86_64-portable-14.5.3.exe’. Based on the logs returned at '2025-05-29T16:07:43.8394086Z' a user named "as21" on the device "alex-threat-hun" initiated the execution of a file named "tor-browser-windows-x86_64-portable-14.5.3.exe using a command that initiated a silent installation."

**Query used to locate event:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/d73f9627-60ce-47ab-89c3-02ea581e287f">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents for any indication that user ‘as21’ actually opened the tor browser. There was evidence that they did open it at: '2025-05-29T16:08:14.1995522Z'. There were several other instances of Firefox as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "alex-threat-hun"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/ef39e51d-2cd2-4973-8c3f-540d81de7cbd">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any known Tor Ports. At '2025-05-29T16:08:34.3522629Z', the user account "as21" on the device "alex-threat-hun" successfully initiated a network connection using the process "tor.exe" to the remote IP address '150.230.20.28' over TCP port '9001'. Port '9001' is commonly associated with Tor's default relay communication, indicating that the Tor client established a connection to a Tor relay node. There were a couple connections to the clear web as well.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "alex-threat-hun"
| where InitiatingProcessAccountName == 'as21'
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "443", "80")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/96237bee-ca0e-4a58-94c9-e9a9f1764c90">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** User "as21" initiated a rename of the file tor-browser-windows-x86_64-portable-14.5.3.exe located in the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\as21\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-05-29T09:07:43Z`
- **Event:** User "as21" initiated a silent installation of tor-browser-windows-x86_64-portable-14.5.3.exe.
- **Action:** Process creation with silent install parameters detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\as21\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe'

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-05-29T09:08:14Z`
- **Event:** firefox.exe was launched multiple times from the TOR Browser directory, indicating the start of browser processes.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\as21\Desktop\Tor Browser\Browser\TorBrowser\Tor\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-05-29T09:08:34Z`
- **Event:** tor.exe successfully connected to a TOR relay node at remote IP 150.230.20.28 on port 9001.
- **Action:** Connection success.
- **File Path:** `C:\Users\as21\Desktop\Tor Browser\Browser\TorBrowser\Tor\firefox.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamp:** `2025-05-29T09:11:32Z`
- **Event:** firefox.exe spawned multiple processes, suggesting active browser usage or multiple tabs open.
- **Action:** Multiple process creations detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-05-29T09:19:10Z'
- **Event:** User "as21" created a file named tor-shopping-list.txt on the desktop, possibly indicating planning or notes related to TOR usage.
- **Action:** File creation detected.
- **File Path:** 'C:\Users\as21\Desktop\tor-shopping-list.txt'

---

## Summary

The logs indicate that user 'as21' downloaded and installed the Tor Browser on the 'alex-threat-hun' device. The user conducted multiple successful connections to the Tor network, suggesting active browsing activity through Tor. Several files and processes related to Tor were created, and network communications typical of Tor usage were established successfully. The creation of tor-shopping-list.txt could suggest specific intentions or continues usage post-installation. The pattern of events reflects typical behavior associated with installing and using the Tor Browser for anonymous web browsing, raising possible concerns about the nature of content being accessed.

---

## Response Taken

TOR usage was confirmed on the endpoint alex-threat-hun. The device was isolated and the user's direct manager was notified.

---
