# Security Systems Course Projects

[cite_start]**Authors:** * Alexandra Gkaragkani (AM: 2019030020) [cite: 25]
* [cite_start]Eva Pantazi (AM: 2019030021) [cite: 26]

> [cite_start]This repository contains a collection of projects developed for the "Security Systems" course[cite: 24]. The projects cover a wide range of cybersecurity topics including cryptography, network security, web vulnerabilities, access control, and system exploitation.

---

## 📚 Table of Contents

- [Assignment 1: Cryptography Tools](#1-cryptography-tools)
- [Assignment 2: Access Control Logging](#2-access-control-logging-system)
- [Assignment 3: Web Vulnerabilities](#3-web-vulnerabilities-exploitation)
- [Assignment 4: Network Traffic Analyzer](#4-network-traffic-analyzer)
- [Assignment 5: Simple Adblocker](#5-simple-adblocker)
- [Assignment 6: Intrusion Detection (Snort)](#6-intrusion-detection-with-snort)
- [Assignment 7: Buffer Overflow Exploitation](#7-buffer-overflow-exploitation)

---

## 1. Cryptography Tools
**Focus:** Diffie-Hellman & RSA Implementation  
**Language:** C (requires GMP library)

This project implements two fundamental cryptographic algorithms from scratch:
* [cite_start]**Diffie-Hellman Key Exchange:** A command-line tool that generates public/private keys and calculates the shared secret between two parties[cite: 22].
* [cite_start]**RSA Encryption/Decryption:** A tool to generate RSA key pairs (of specified bit length), encrypt plain text files, and decrypt cipher text files[cite: 22].

---

## 2. Access Control Logging System
**Focus:** File System Monitoring & Access Control  
**Language:** C, OpenSSL

A custom access control system consisting of two main components:
1.  **Logging Tool (`logger.so`):** Intercepts file operations (creation, opening, writing) using `LD_PRELOAD`. [cite_start]It logs the User ID, file path, timestamp, access type, and the file's MD5 fingerprint[cite: 22].
2.  **Monitoring Tool (`acmonitor`):** Parses the logs to detect suspicious behavior, such as:
    * [cite_start]**Unauthorized Access:** Users with more than 7 failed attempts[cite: 22].
    * [cite_start]**File Modifications:** Tracking how many times specific users modified a file[cite: 22].

---

## 3. Web Vulnerabilities Exploitation
**Focus:** SQL Injection & XSS  
**Context:** Web Application Security

This project involves identifying and exploiting vulnerabilities in a vulnerable web application:
* [cite_start]**SQL Injection (SQLi):** Bypassing login screens and using `UNION SELECT` attacks to retrieve the administrator's password from the database[cite: 46, 85].
* [cite_start]**DOM-Based XSS:** Manipulating client-side JavaScript via the URL fragment to execute malicious scripts[cite: 52].
* [cite_start]**Reflected XSS:** Injecting scripts into search bars that are reflected back in the server response[cite: 65].

---

## 4. Network Traffic Analyzer
**Focus:** Packet Sniffing & Analysis  
**Language:** C, Libpcap

A network analysis tool capable of capturing live traffic or reading offline PCAP files.
* [cite_start]**Protocol Analysis:** Parses TCP and UDP packets to extract IP addresses, ports, and payload sizes[cite: 22].
* [cite_start]**Flow & Retransmission:** Counts network flows and detects TCP packet retransmissions by analyzing sequence numbers and flags[cite: 22].
* [cite_start]**Filtering:** Supports BPF filter expressions (e.g., specific ports)[cite: 22].

---

## 5. Simple Adblocker
**Focus:** Firewall Configuration  
**Language:** Bash, iptables

A command-line adblocker script built on Linux `iptables`.
* [cite_start]**Blocking:** Configure rules to block traffic based on a list of domain names or IP addresses[cite: 22].
* [cite_start]**Management:** Includes commands to save rules, load rules, list current configurations, and reset the firewall[cite: 22].

---

## 6. Intrusion Detection with Snort
**Focus:** Network Intrusion Detection System (NIDS)  
**Tool:** Snort

Configuration of Snort IDS to detect malicious network patterns, including:
* [cite_start]**ICMP Alerts:** Detecting connection attempts[cite: 22].
* [cite_start]**Content Filtering:** Flagging packets containing specific strings (e.g., "hello")[cite: 22].
* [cite_start]**Port Monitoring:** Alerting on traffic occurring on non-root ports (>1024)[cite: 22].
* [cite_start]**Attack Detection:** Identifying SSH brute force attacks[cite: 22].

---

## 7. Buffer Overflow Exploitation
**Focus:** Stack Smashing & Shellcode  
**Language:** C, Python, Assembly

An exploitation project targeting a vulnerable "Greeter" program.
* [cite_start]**Vulnerability:** The program uses `gets`, allowing a stack buffer overflow[cite: 130].
* **Exploit:** A Python script generates a payload containing NOP slides and shellcode. [cite_start]It overwrites the return address (EIP) to jump to the stack and execute arbitrary code, spawning a root shell[cite: 157, 158].
* [cite_start]**Advanced:** Includes discussion on bypassing protections like ASLR and DEP using Return-to-libc attacks[cite: 172].

---

## 📜 License
These projects are licensed under the [MIT License](https://choosealicense.com/licenses/mit/).