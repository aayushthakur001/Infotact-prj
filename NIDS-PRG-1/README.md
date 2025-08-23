# 🚀 Project 1 — Network Intrusion Detection System (NIDS)

This repository contains a **complete PoC** for deploying a **Snort-based Network Intrusion Detection System (NIDS)** as part of the cybersecurity internship project.  
It demonstrates how to detect different types of network intrusions using custom Snort rules, along with full documentation and presentation.

It includes:

- Snort **custom rules** for ICMP, Nmap scans, SSH/FTP brute-force, and simulated HTTP C2 beacons.
- A **step-by-step guide** to reproduce the PoC.
- Final **report (DOCX)** and **slides (PPTX)** with placeholders for your screenshots.
- Evidence folder for storing your screenshots and logs.

> Target: Ubuntu Server (Snort) — Attacker: Kali Linux (Nmap, Hydra, curl) — Network: Bridged LAN

---

## 📌 Project Overview

- **Target Machine (Ubuntu Server 24.04 LTS):** Runs Snort IDS
- **Attacker Machine (Kali Linux):** Runs attack tools (Nmap, Hydra, Curl)
- **Network Setup:** VMware, Bridged Network mode
- **Detection Engine:** Snort 2.x (installed via apt)

The goal is to configure Snort with **custom rules** to detect:  
✔️ ICMP Pings  
✔️ Nmap Scans (SYN, FIN, Xmas)  
✔️ SSH Brute-Force Attempts  
✔️ FTP Brute-Force Attempts (Optional)  
✔️ Simulated Malware C2 Beacons (HTTP Host header + URI pattern)

---

## 📂 Repository Structure

```
nids-project/
├─ README.md
├─ rules/
│  └─ local.rules
├─ scripts/
│  ├─ run_snort_console.sh
│  └─ beacon_loop_example.sh
├─ evidence/           # put your screenshots/logs here
│  ├─ .gitkeep
│  └─ examples.txt
└─ docs/
   ├─ NIDS_Project_Report.docx
   └─ NIDS_Project_Presentation.pptx
```

---

## 🛠️ Setup Instructions

### 1️⃣ On Target (Ubuntu Server)

```bash
# Install Snort & services
sudo apt update && sudo apt install -y snort apache2 openssh-server vsftpd

# Enable required services
sudo systemctl enable --now apache2 ssh vsftpd

# Verify interface and IP
ip a
```

### 2️⃣ On Attacker (Kali Linux)

```bash
# Install attack tools
sudo apt update && sudo apt install -y nmap hydra curl

# Verify IP
ip a
```

### 3️⃣ Deploy Custom Rules

Copy `rules/local.rules` into Snort rules directory on **Ubuntu**:

```bash
sudo cp ./rules/local.rules /etc/snort/rules/local.rules
```

Restart Snort with new rules:

```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i <INTERFACE>
```

### 1) ICMP

- **Attacker:** `ping -c 5 <TARGET_IP>`
- **Expected:** Snort alert `ICMP test`

### 2) Nmap scans

- **Attacker:** `nmap -sS <TARGET_IP>`, `nmap -sF <TARGET_IP>`, `nmap -sX <TARGET_IP>`
- **Expected:** `Nmap SYN/FIN/Xmas Scan` alerts

### 3) SSH brute-force

- **Target:** ensure SSH running (`systemctl status ssh`)
- **Attacker:** `echo -e "password\nadmin\nroot\n123456\nqwerty\nletmein" > pass.txt`
  then `hydra -l testuser -P pass.txt ssh://<TARGET_IP>`
- **Expected:** `SSH Brute-Force Attempt Detected`

### 4) (Optional) FTP brute-force

- **Target:** install `vsftpd` and run
- **Attacker:** `hydra -l testuser -P pass.txt ftp://<TARGET_IP>`
- **Expected:** `FTP Brute-Force Attempt Detected`

### 5) Malware C2 beacon (HTTP)

- **Target:** Apache running
- **Attacker:** `while true; do curl -H "Host: malicious-c2-server.com" http://<TARGET_IP>/ping; sleep 10; done`
- **Expected:** `Malware C2 HTTP Host detected` and `Malware C2 Beacon URI detected`

---

## 🔍 Attack Scenarios & Detection Rules

### 📡 ICMP Ping Detection

- **Rule:**
  ```snort
  alert icmp any any -> $HOME_NET any (msg:"ICMP test"; sid:1000000; rev:1;)
  ```
- **Command (Kali):**
  ```bash
  ping -c 5 <TARGET_IP>
  ```
- **Expected Alert:**  
  `ICMP test` in Snort console

---

### 🔎 Nmap Scan Detection

- **Rules:**
  ```snort
  alert tcp any any -> $HOME_NET any (msg:"Nmap SYN Scan"; flags:S; flow:stateless; sid:1000001; rev:1;)
  alert tcp any any -> $HOME_NET any (msg:"Nmap FIN Scan"; flags:F; flow:stateless; sid:1000002; rev:1;)
  alert tcp any any -> $HOME_NET any (msg:"Nmap Xmas Scan"; flags:FPU; flow:stateless; sid:1000003; rev:1;)
  ```
- **Commands (Kali):**
  ```bash
  nmap -sS <TARGET_IP>
  nmap -sF <TARGET_IP>
  nmap -sX <TARGET_IP>
  ```
- **Expected Alerts:**  
  `Nmap SYN Scan`, `Nmap FIN Scan`, `Nmap Xmas Scan`

---

### 🔐 SSH Brute-Force Detection

- **Rule:**
  ```snort
  alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute-Force Attempt Detected";
  flow:to_server,established; detection_filter:track by_src, count 5, seconds 60;
  sid:1000004; rev:1;)
  ```
- **Commands (Kali):**
  ```bash
  echo -e "password
  admin
  root
  123456
  qwerty
  letmein" > pass.txt
  hydra -l testuser -P pass.txt ssh://<TARGET_IP>
  ```
- **Expected Alert:**  
  `SSH Brute-Force Attempt Detected`

---

### 📁 FTP Brute-Force Detection (Optional)

- **Rule:**
  ```snort
  alert tcp any any -> $HOME_NET 21 (msg:"FTP Brute-Force Attempt Detected";
  flow:to_server,established; detection_filter:track by_src, count 5, seconds 60;
  sid:1000005; rev:1;)
  ```
- **Command (Kali):**
  ```bash
  hydra -l testuser -P pass.txt ftp://<TARGET_IP>
  ```
- **Expected Alert:**  
  `FTP Brute-Force Attempt Detected`

---

### ☠️ Malware C2 Beacon Detection

- **Rules:**

  ```snort
  alert tcp any any -> $HOME_NET 80 (msg:"Malware C2 HTTP Host detected";
  flow:to_server,established; content:"Host|3a 20|malicious-c2-server.com"; http_header;
  sid:1000006; rev:1;)

  alert tcp any any -> $HOME_NET 80 (msg:"Malware C2 Beacon URI detected";
  flow:to_server,established; content:"/ping"; http_uri;
  sid:1000007; rev:1;)
  ```

- **Command (Kali):**
  ```bash
  ./scripts/beacon_loop_example.sh <TARGET_IP>
  ```
- **Expected Alerts:**  
  `Malware C2 HTTP Host detected`, `Malware C2 Beacon URI detected`

---

## 📝 Logging & PCAP Evidence

Enable logging:

```bash
sudo snort -A fast -q -c /etc/snort/snort.conf -i <INTERFACE> -l /var/log/snort
tail -f /var/log/snort/alert
```

Optional: Capture traffic in PCAP for Wireshark analysis:

```bash
sudo tcpdump -i <INTERFACE> -w /tmp/nids_test.pcap
```

---

## 📸 Proof of Concept (PoC) — What to Capture

- Ubuntu Snort console showing alerts for each test (ICMP, Nmap, SSH, FTP, C2)
- Attacker commands (Kali terminal) proving attack launched
- Snort logs in `/var/log/snort/alert`
- (Optional) PCAP file from tcpdump

---

## 📑 Deliverables

✔️ **Report (DOCX)** → `/docs/NIDS_Project_Report.docx`  
✔️ **Presentation (PPTX)** → `/docs/NIDS_Project_Presentation.pptx`  
✔️ **GitHub Repo** → contains rules, scripts, docs, and placeholders for screenshots/logs

---

## Notes

- Replace `<INTERFACE>` with your NIC (e.g., `enp0s3` / `eth0`). Check with `ip a`.
- Replace `<TARGET_IP>` with the Ubuntu VM IP.
- All rules use SIDs in the 1000000+ local range.
- This repo includes minimal helper scripts in `scripts/`.

---

## ⚖️ License

This project is licensed under the **MIT License**.  
Feel free to use, modify, and share with attribution.

---

## 🙌 Acknowledgements

- Snort IDS (Cisco/Talos)
- Kali Linux tools (Nmap, Hydra, Curl)
- Ubuntu Server
- Internship project guidelines
