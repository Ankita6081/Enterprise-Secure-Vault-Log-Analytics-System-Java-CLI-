package com.vault;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

public class App {

    private static final String VAULT_FILE = "secrets.bin";
    private static final String AUDIT_FILE = "audit_ledger.txt";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            System.exit(0);
        }

        try {
            Map<String, String> params = parseArgs(args);

            if (params.containsKey("--set")) {
                handleSetSecret(params.get("--set"), params.get("--value"), params.get("--master-key"));
            } else if (params.containsKey("--get")) {
                handleGetSecret(params.get("--get"), params.get("--master-key"));
            } else if (params.containsKey("--analyze-logs")) {
                handleLogAnalysis(params.get("--analyze-logs"));
            } else if (params.containsKey("--verify-chain")) {
                handleVerifyChain();
            } else {
                printUsage();
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Execution failed: " + e.getMessage());
            System.exit(1);
        }
    }

    // =========================================================================
    // MODULE 1: SECURE CREDENTIAL VAULT (AES-256-GCM + PBKDF2)
    // =========================================================================

    private static void handleSetSecret(String key, String value, String masterKey) throws Exception {
        if (key == null || value == null || masterKey == null) {
            System.out.println("[ERROR] Missing arguments for --set. Usage: --set <key> --value <val> --master-key <pass>");
            return;
        }

        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        SecretKey secretKey = deriveKey(masterKey, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

        byte[] ciphertext = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));

        // Save salt + iv + key_name + ciphertext length + ciphertext to disk
        Properties props = loadVaultData();
        String record = Base64.getEncoder().encodeToString(salt) + ":" +
                        Base64.getEncoder().encodeToString(iv) + ":" +
                        Base64.getEncoder().encodeToString(ciphertext);
        props.setProperty(key, record);
        saveVaultData(props);

        System.out.println("[SUCCESS] Secret '" + key + "' encrypted with AES-256-GCM and stored.");
        appendAuditRecord("SET_SECRET", "Key=" + key);
    }

    private static void handleGetSecret(String key, String masterKey) throws Exception {
        if (key == null || masterKey == null) {
            System.out.println("[ERROR] Missing arguments for --get. Usage: --get <key> --master-key <pass>");
            return;
        }

        Properties props = loadVaultData();
        String record = props.getProperty(key);

        if (record == null) {
            System.out.println("[ERROR] Secret key '" + key + "' not found in vault.");
            return;
        }

        String[] parts = record.split(":");
        byte[] salt = Base64.getDecoder().decode(parts[0]);
        byte[] iv = Base64.getDecoder().decode(parts[1]);
        byte[] ciphertext = Base64.getDecoder().decode(parts[2]);

        SecretKey secretKey = deriveKey(masterKey, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

        byte[] decrypted = cipher.doFinal(ciphertext);
        System.out.println("[SUCCESS] Secret Decrypted: " + new String(decrypted, StandardCharsets.UTF_8));
        appendAuditRecord("GET_SECRET", "Key=" + key);
    }

    private static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    // =========================================================================
    // MODULE 2: CONCURRENT LOG ANALYTICS STREAM
    // =========================================================================

    private static void handleLogAnalysis(String filePath) throws Exception {
        File logFile = new File(filePath);
        if (!logFile.exists()) {
            System.out.println("[ERROR] Log file not found: " + filePath);
            return;
        }

        System.out.println("======================================================================");
        System.out.println("                  LOG ANALYTICS STREAM SUMMARY                        ");
        System.out.println("======================================================================");
        System.out.println("[STREAM] Parsing log stream: " + filePath);

        long startTime = System.currentTimeMillis();
        ExecutorService executor = Executors.newFixedThreadPool(4);
        BlockingQueue<String> queue = new LinkedBlockingQueue<>(1000);

        Map<String, Integer> severityCounts = new ConcurrentHashMap<>();
        severityCounts.put("INFO", 0);
        severityCounts.put("WARNING", 0);
        severityCounts.put("ERROR", 0);

        // Producer: Read file lines
        CompletableFuture<Void> producer = CompletableFuture.runAsync(() -> {
            try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    queue.put(line);
                }
                queue.put("EOF"); // Poison pill
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        // Consumer: Parse metrics
        CompletableFuture<Void> consumer = CompletableFuture.runAsync(() -> {
            try {
                while (true) {
                    String line = queue.take();
                    if ("EOF".equals(line)) break;

                    if (line.contains("ERROR")) {
                        severityCounts.compute("ERROR", (k, v) -> v + 1);
                    } else if (line.contains("WARN")) {
                        severityCounts.compute("WARNING", (k, v) -> v + 1);
                    } else {
                        severityCounts.compute("INFO", (k, v) -> v + 1);
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        CompletableFuture.allOf(producer, consumer).join();
        executor.shutdown();

        long duration = System.currentTimeMillis() - startTime;
        int totalLogs = severityCounts.values().stream().mapToInt(Integer::intValue).sum();

        System.out.println("Execution Duration : " + (duration / 1000.0) + " seconds");
        System.out.println("Total Logs Parsed  : " + totalLogs);
        System.out.println("\nSeverity Breakdown:");
        System.out.println("  - INFO    : " + severityCounts.get("INFO"));
        System.out.println("  - WARNING : " + severityCounts.get("WARNING"));
        System.out.println("  - ERROR   : " + severityCounts.get("ERROR"));
        System.out.println("======================================================================");

        appendAuditRecord("ANALYZE_LOGS", "File=" + filePath + ", Total=" + totalLogs);
    }

    // =========================================================================
    // MODULE 3: TAMPER-EVIDENT AUDIT HASH CHAINING
    // =========================================================================

    private static void appendAuditRecord(String action, String details) {
        try {
            File file = new File(AUDIT_FILE);
            String prevHash = "0000000000000000000000000000000000000000000000000000000000000000";

            if (file.exists() && file.length() > 0) {
                try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                    String lastLine = null, currentLine;
                    while ((currentLine = reader.readLine()) != null) {
                        lastLine = currentLine;
                    }
                    if (lastLine != null) {
                        String[] parts = lastLine.split(" \\| ");
                        if (parts.length >= 4) {
                            prevHash = parts[3];
                        }
                    }
                }
            }

            long timestamp = System.currentTimeMillis();
            String rawData = timestamp + " | " + action + " | " + details + " | " + prevHash;
            String currentHash = calculateSHA256(rawData);

            try (FileWriter writer = new FileWriter(file, true)) {
                writer.write(rawData + " | " + currentHash + "\n");
            }
        } catch (Exception e) {
            System.err.println("[AUDIT ERROR] Could not record entry: " + e.getMessage());
        }
    }

    private static void handleVerifyChain() throws Exception {
        File file = new File(AUDIT_FILE);
        if (!file.exists()) {
            System.out.println("[AUDIT] No ledger records found to verify.");
            return;
        }

        System.out.println("[AUDIT] Starting cryptographic integrity scan on " + AUDIT_FILE + "...");
        
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            String expectedPrevHash = "0000000000000000000000000000000000000000000000000000000000000000";
            int count = 0;
            boolean valid = true;

            while ((line = reader.readLine()) != null) {
                count++;
                String[] parts = line.split(" \\| ");
                if (parts.length < 5) {
                    System.out.println("[TAMPER DETECTED] Malformed row at line " + count);
                    valid = false;
                    break;
                }

                String timestamp = parts[0];
                String action = parts[1];
                String details = parts[2];
                String prevHash = parts[3];
                String currentHash = parts[4];

                if (!prevHash.equals(expectedPrevHash)) {
                    System.out.println("[TAMPER DETECTED] Block #" + count + " previous hash mismatch!");
                    valid = false;
                    break;
                }

                String rawData = timestamp + " | " + action + " | " + details + " | " + prevHash;
                String recalculatedHash = calculateSHA256(rawData);

                if (!recalculatedHash.equals(currentHash)) {
                    System.out.println("[TAMPER DETECTED] Block #" + count + " data hash signature modified!");
                    valid = false;
                    break;
                }

                expectedPrevHash = currentHash;
            }

            if (valid) {
                System.out.println("----------------------------------------------------------------------");
                System.out.println("[STATUS] Hash Chain Verification Passed (" + count + " records checked)");
                System.out.println("[RESULT] Zero tampered or deleted records detected in system ledger.");
                System.out.println("----------------------------------------------------------------------");
            }
        }
    }

    private static String calculateSHA256(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // =========================================================================
    // UTILITIES
    // =========================================================================

    private static Properties loadVaultData() {
        Properties props = new Properties();
        File file = new File(VAULT_FILE);
        if (file.exists()) {
            try (FileInputStream in = new FileInputStream(file)) {
                props.load(in);
            } catch (IOException ignored) {}
        }
        return props;
    }

    private static void saveVaultData(Properties props) {
        try (FileOutputStream out = new FileOutputStream(VAULT_FILE)) {
            props.store(out, "Vault Storage Encrypted Data");
        } catch (IOException e) {
            System.err.println("[ERROR] Storage failed: " + e.getMessage());
        }
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> map = new HashMap<>();
        for (int i = 0; i < args.length; i++) {
            if (args[i].startsWith("--")) {
                if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                    map.put(args[i], args[i + 1]);
                    i++;
                } else {
                    map.put(args[i], "true");
                }
            }
        }
        return map;
    }

    private static void printUsage() {
        System.out.println("======================================================================");
        System.out.println("     Enterprise Secure Vault & Log Analytics System (Java CLI)        ");
        System.out.println("======================================================================");
        System.out.println("Usage Commands:");
        System.out.println("  1. Store Secret : --set <KEY_NAME> --value <VALUE> --master-key <PASSWORD>");
        System.out.println("  2. Get Secret   : --get <KEY_NAME> --master-key <PASSWORD>");
        System.out.println("  3. Parse Logs   : --analyze-logs <LOG_FILE_PATH>");
        System.out.println("  4. Verify Audit : --verify-chain");
        System.out.println("======================================================================");
    }
}
