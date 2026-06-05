# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-06-03T01:01:30`. These events began at `2026-06-02T21:38:31`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "jvm"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-06-03T01:01:30)
| order by Timestamp desc
| project Timestamp, DeviceName,FolderPath,Account=InitiatingProcessAccountName,FileName, SHA256
```
<<img width="956" height="439" alt="image" src="https://github.com/user-attachments/assets/a087c458-6a86-4bc9-9077-1de4dc0edb7e" />
>

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2026-06-02T21:38:31`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where FileName startswith "tor"
| where DeviceName =="jvm"
| project Timestamp, DeviceName, ActionType, FileName,ProcessCommandLine

```
<<img width="917" height="354" alt="image" src="https://github.com/user-attachments/assets/63854114-92e6-42a6-b7e1-6e99dc1315e9" />
>

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2026-06-02T21:38:31`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "jvm"
| where FileName has_any ("tor.exe","firefox.exe","start-tor-browser.exe","firefox-real.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, InitiatingProcessCommandLine
| order by  Timestamp desc
```
<<img width="955" height="413" alt="image" src="https://github.com/user-attachments/assets/8ca3320d-82e0-4248-a0fb-34a3849f7866" />
>

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-06-02T21:38:31`, an employee on the "JVM" device successfully established a connection to the remote IP address `127.0.0.1` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
|where DeviceName == "jvm"
| where InitiatingProcessAccountName == "labuser"
| where InitiatingProcessAccountName != "System"
| where RemotePort  in ("9001","9030","9040","9050","9051","9150","80","443")
|project Timestamp, DeviceName, ActionType, RemoteIP,RemotePort,RemoteUrl,InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
| where Timestamp == datetime(2026-06-03T04:58:11.9983593Z)
```
<<img width="950" height="454" alt="image" src="https://github.com/user-attachments/assets/db29612c-2f00-4602-93ee-7818e4b8df0f" />
>

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-06-02T21:38:31`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-06-02T21:38:31`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** ``2026-06-02T21:38:31`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-06-02T21:38:31`
- **Event:** A network connection to IP `127.0.0.1` on port `9150` by user "labuser" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2026-06-02T21:38:31` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "labuser" through the TOR browser.
- **Action:** One successful connection detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-06-02T21:38:31`
- **Event:** The user "labuser" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The investigation confirmed that user **labuser** on endpoint **jvm** downloaded, installed, and actively used the Tor Browser. Evidence showed that the Tor Browser installer was downloaded to the user's **Downloads** directory and executed multiple times. Telemetry also revealed a silent installation and extraction process using the **/S** switch. Following installation, numerous Tor Browser-related files, including **tor.exe**, were created on the user's **Desktop**. Process execution logs identified multiple instances of **firefox.exe** associated with Tor Browser activity, indicating active browser usage. Additionally, network telemetry captured communications over **port 9150**, a port commonly used by the Tor Browser's local proxy service, further confirming Tor-related network activity. The investigation also identified the creation and subsequent access of a Tor-related text file named **tor-shopping-list.txt**. Based on the collected file, process, and network telemetry, the investigation successfully verified Tor Browser usage on endpoint **jvm** by user **labuser**. No unrelated activity was included in the scope of this report.


---

## Response Taken

TOR usage was confirmed on the endpoint `jvm` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
