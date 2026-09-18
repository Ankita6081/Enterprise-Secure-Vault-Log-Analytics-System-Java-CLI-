# PROJECT TITLE: Enterprise-Secure-Vault-Log-Analytics-System-Java-CLI-

OVERVIEW OF THE PROJECT: A lightweight, zero-dependency Java command-line interface (CLI) application built to securely store credentials, parse high-volume log streams, and track file changes. Built entirely using Core Java, this tool runs directly in terminal environments to provide enterprise-grade encryption, fast multi-threaded processing, and digital tamper detection.

FEATURES: 
1. Safe Password Vault: Encrypts and locks secret keys and passwords using enterprise-grade AES-256-GCM encryption.
2. Fast Log Analytics: Reads and analyzes large log files using multi-threaded execution to summarize errors and traffic metrics quickly.
3. Tamper-Proof Audit Chain: Links system records together using SHA-256 hash chains so you can instantly spot if a file was altered or deleted.
4. Native CLI Execution: Runs directly from standard terminal environments using command flags and standard input/output pipes.

TECHNOLOGIES/TOOLS USED: 
1. Language: Java 17+ (Core Java APIs)
2. Build Tool: Apache Maven
3. Cryptographic Frameworks: javax.crypto (AES/GCM/NoPadding, PBKDF2 Key Derivation)
4. Concurrency: java.util.concurrent (ExecutorService, BlockingQueue)
5. Testing: JUnit 5

STEPS TO INSTALL & RUN THE PROJECT
1. Prerequisites
2. Java Development Kit (JDK): Version 17 or higher
3. Apache Maven: Version 3.8 or higher

INSTALLATION:- 
1. Clone the repository
2. Build the project executable using Maven

HOW TO RUN (CLI EXAMPLES):-
1. Store a Secret in the Vault
2. Retrieve a Secret
3. Analyze a Log File
4. Verify Log Integrity (Tamper Detection)

INSTRUCTIONS FOR TESTING: 
Run the automated JUnit test suite using Maven:
Manual CLI Testing - 
1. Bad Passcode Test: Run a --get command with an incorrect --master-key. Verify that access is denied with a clear error message.
2. File Tamper Test: Manually open the generated log chain file, edit a single character, and execute --verify-chain. Confirm that the system flags the tampered record.

SCREENSHOTS: 

1. Vault Secret Encryption & Retrieval
   
   <img width="681" height="403" alt="image" src="https://github.com/user-attachments/assets/3f4bf6e2-f557-43a1-b1d3-40d56f308fea" />
   
3. Multi-Threaded Log Analysis
   
   <img width="490" height="290" alt="image" src="https://github.com/user-attachments/assets/597860fb-31a1-4e6c-a0b6-5dedcc425348" />
   
5. Tamper-Evident Audit Chain Verification
   
   <img width="524" height="281" alt="image" src="https://github.com/user-attachments/assets/f494b993-a14a-4f72-81b0-84fd639c289c" />

