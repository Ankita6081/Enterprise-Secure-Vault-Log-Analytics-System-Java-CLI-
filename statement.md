Project Statement: Enterprise Secure Vault & Log Analytics System

Problem Statement:
In contemporary software operations and DevOps workflows,
managing sensitive credentials (such as API keys and database passwords)
alongside high-volume system logs presents significant security and performance challenges:

Insecure Secret Storage: 
Developers frequently store plaintext credentials in configuration files, scripts, or unsecured environments, exposing critical assets to leak vulnerabilities.
Audit Record Vulnerability: Standard system log files are vulnerable to post-intrusion modification or deletion, leaving system administrators without a trustworthy record of events.
Stream Processing Bottlenecks: Processing multi-megabyte log files sequentially in command-line environments often leads to memory overhead and delayed insights.

The Enterprise Secure Vault & Log Analytics System solves these issues by providing a single, pure-Java CLI engine that unifies AES-encrypted secret management, concurrent log analytics, and tamper-evident audit logging.  

Scope of the Project:
This project is scoped as a pure Core Java (JDK 17+) command-line application built without external third-party dependencies.  
In-Scope Capabilities:
	
	Cryptographic Vault: Encrypting, storing, and decrypting key-value pairs locally using AES-256-GCM encryption with PBKDF2 key derivation.
	Concurrent Log Aggregation: Parsing log files via multi-threaded Producer-Consumer streams to generate real-time metrics and error counts.
	Tamper Detection Ledger: Generating an append-only SHA-256 hash-linked audit chain that detects modified or deleted log entries instantly.
	Terminal Native Workflow: Full execution support via command-line arguments, options, and exit codes.

Out-of-Scope:
	
	Graphical User Interfaces (GUI or Web dashboards).   
	Cloud-hosted remote key management systems (e.g., AWS KMS or HashiCorp Vault integrations).
	Distributed multi-node consensus algorithms.

Target Users:
	
	System & Security Administrators: Professionals who need a quick, terminal-native utility to manage environment secrets and verify system integrity without installing heavy third-party software packages.
	DevOps Engineers: Automation specialists looking for lightweight CLI engines capable of parsing local build logs and tracking deployment events securely.
	Compliance & Security Auditors: Investigators who require cryptographic proof that log files and operational histories have not been altered or tampered with post-incident.

High-Level Features:
	
	Authenticated AES-256-GCM Encryption: Secures stored secrets using strong cipher algorithms paired with salted PBKDF2 password derivation.
	Multi-Threaded Stream Processing: Utilizes ExecutorService and concurrent queues to parse large log streams rapidly without blocking system memory.
	Cryptographic Hash Chaining: Implements a blockchain-inspired SHA-256 hash ledger where each event block validates the cryptographic integrity of the previous block.
	POS-Compliant CLI Flags: Supports standard terminal commands (e.g., --set, --get, --analyze-logs, --verify-chain) for straightforward pipeline integration.
