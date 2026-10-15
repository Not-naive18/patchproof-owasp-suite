package com.patchproof.benchmark;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * PatchProof AI Benchmark - Java (Patched Implementation)
 * Demonstrates proven patches that fix OWASP Top 10 vulnerabilities without regression.
 */
public class PatchedEndpoints {

    private Connection conn;

    public PatchedEndpoints() {
        try {
            conn = DriverManager.getConnection("jdbc:sqlite::memory:");
            Statement stmt = conn.createStatement();
            stmt.executeUpdate("CREATE TABLE accounts (id INTEGER PRIMARY KEY, username TEXT, balance REAL)");
            stmt.executeUpdate("INSERT INTO accounts VALUES (1, 'john', 500.00)");
            stmt.executeUpdate("INSERT INTO accounts VALUES (2, 'sarah', 1250.50)");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // PATCH A02: Strong Cryptographic Hash (SHA-256)
    public String hashUserPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    // PATCH A03: PreparedStatement Prevents SQL Injection
    public List<String> findAccountByUser(String userInput) throws Exception {
        List<String> results = new ArrayList<>();
        // SECURE: Parameterized query eliminates SQL injection
        String query = "SELECT username, balance FROM accounts WHERE username = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, userInput);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    results.add(rs.getString("username") + ":" + rs.getDouble("balance"));
                }
            }
        }
        return results;
    }

    // PATCH A08: Safe Data Parsing (Plain text / JSON structure instead of Java Serialization)
    public String parseSafeSessionToken(String tokenData) {
        if (tokenData == null || tokenData.trim().isEmpty()) {
            throw new IllegalArgumentException("Token cannot be empty");
        }
        // SECURE: Whitelist validation and deterministic string parsing
        return tokenData.replaceAll("[^a-zA-Z0-9_-]", "");
    }

    // PATCH A10: SSRF Defense with Host and IP Validation
    private boolean isSafeUrl(URL url) throws Exception {
        if (!"https".equalsIgnoreCase(url.getProtocol())) {
            return false;
        }
        InetAddress address = InetAddress.getByName(url.getHost());
        if (address.isLoopbackAddress() || address.isSiteLocalAddress() || address.isAnyLocalAddress()) {
            return false;
        }
        return true;
    }

    public String fetchRemoteStatus(String targetUrl) throws Exception {
        URL url = new URL(targetUrl);
        if (!isSafeUrl(url)) {
            throw new SecurityException("SSRF blocked: Disallowed URL or private address target");
        }
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(2000);
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            return reader.readLine();
        }
    }
}
