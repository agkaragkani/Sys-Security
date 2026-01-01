# Security Systems Course Projects

**Authors:** Alexandra Gkaragkani (AM: 2019030020) 
Eva Pantazi (AM: 2019030021) 

> This repository contains a collection of projects developed for the "Security Systems" course. The projects cover a wide range of cybersecurity topics including cryptography, network security, web vulnerabilities, access control, and system exploitation.

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
**Diffie-Hellman Key Exchange:** A command-line tool that generates public/private keys and calculates the shared secret between two parties.
**RSA Encryption/Decryption:** A tool to generate RSA key pairs (of specified bit length), encrypt plain text files, and decrypt cipher text files.

---

## 2. Access Control Logging System
**Focus:** File System Monitoring & Access Control  
**Language:** C, OpenSSL

A custom access control system consisting of two main components:
1.  **Logging Tool (`logger.so`):** Intercepts file operations (creation, opening, writing) using `LD_PRELOAD`. It logs the User ID, file path, timestamp, access type, and the file's MD5 fingerprint.
2.  **Monitoring Tool (`acmonitor`):** Parses the logs to detect suspicious behavior, such as:
    **Unauthorized Access:** Users with more than 7 failed attempts.
    **File Modifications:** Tracking how many times specific users modified a file.

---

## 3. Web Vulnerabilities Exploitation
**Focus:** SQL Injection & XSS  
**Context:** Web Application Security

This project involves identifying and exploiting vulnerabilities in a vulnerable web application:
**SQL Injection (SQLi):** Bypassing login screens and using `UNION SELECT` attacks to retrieve the administrator's password from the database.
**DOM-Based XSS:** Manipulating client-side JavaScript via the URL fragment to execute malicious scripts.
**Reflected XSS:** Injecting scripts into search bars that are reflected back in the server response.

---

## 4. Network Traffic Analyzer
**Focus:** Packet Sniffing & Analysis  
**Language:** C, Libpcap

A network analysis tool capable of capturing live traffic or reading offline PCAP files.
**Protocol Analysis:** Parses TCP and UDP packets to extract IP addresses, ports, and payload sizes.
**Flow & Retransmission:** Counts network flows and detects TCP packet retransmissions by analyzing sequence numbers and flags.
**Filtering:** Supports BPF filter expressions (e.g., specific ports).

---

## 5. Simple Adblocker
**Focus:** Firewall Configuration  
**Language:** Bash, iptables

A command-line adblocker script built on Linux `iptables`.
**Blocking:** Configure rules to block traffic based on a list of domain names or IP addresses.
**Management:** Includes commands to save rules, load rules, list current configurations, and reset the firewall.

---

## 6. Intrusion Detection with Snort
**Focus:** Network Intrusion Detection System (NIDS)  
**Tool:** Snort

Configuration of Snort IDS to detect malicious network patterns, including:
**ICMP Alerts:** Detecting connection attempts.
**Content Filtering:** Flagging packets containing specific strings (e.g., "hello").
**Port Monitoring:** Alerting on traffic occurring on non-root ports (>1024).
**Attack Detection:** Identifying SSH brute force attacks.

---

## 7. Buffer Overflow Exploitation
**Focus:** Stack Smashing & Shellcode  
**Language:** C, Python, Assembly

An exploitation project targeting a vulnerable "Greeter" program.
**Vulnerability:** The program uses `gets`, allowing a stack buffer overflow.
**Exploit:** A Python script generates a payload containing NOP slides and shellcode. It overwrites the return address (EIP) to jump to the stack and execute arbitrary code, spawning a root shell.
**Advanced:** Includes discussion on bypassing protections like ASLR and DEP using Return-to-libc attacks.

---

## 📜 License

These projects are licensed under the [MIT License](https://choosealicense.com/licenses/mit/).
