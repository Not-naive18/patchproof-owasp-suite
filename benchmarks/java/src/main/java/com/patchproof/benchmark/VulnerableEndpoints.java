package com.patchproof.benchmark;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * PatchProof AI Benchmark - Java (Vulnerable Implementations)
 * Demonstrates OWASP Top 10 vulnerabilities in Java enterprise applications.
 */
public class VulnerableEndpoints {

    private Connection conn;

    public VulnerableEndpoints() {
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

    // OWASP A02:2021 - Cryptographic Failures: Insecure Hash (MD5)
    public String hashUserPassword(String password) throws Exception {
        // VULNERABLE: MD5 is cryptographically broken and prone to collision attacks
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    // OWASP A03:2021 - Injection: SQL Injection via dynamic Statement
    public List<String> findAccountByUser(String userInput) throws Exception {
        List<String> results = new ArrayList<>();
        Statement stmt = conn.createStatement();
        // VULNERABLE: Direct string concatenation into query
        String query = "SELECT username, balance FROM accounts WHERE username = '" + userInput + "'";
        ResultSet rs = stmt.executeQuery(query);
        while (rs.next()) {
            results.add(rs.getString("username") + ":" + rs.getDouble("balance"));
        }
        return results;
    }

    // OWASP A08:2021 - Software and Data Integrity Failures: Deserialization of untrusted input
    public Object deserializeSession(byte[] rawData) throws Exception {
        // VULNERABLE: Reading untrusted object stream enables Remote Code Execution (RCE)
        try (ByteArrayInputStream bais = new ByteArrayInputStream(rawData);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            return ois.readObject();
        }
    }

    // OWASP A10:2021 - Server-Side Request Forgery (SSRF)
    public String fetchRemoteStatus(String targetUrl) throws Exception {
        // VULNERABLE: Opening connection directly to user-supplied URL
        URL url = new URL(targetUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(2000);
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            return reader.readLine();
        }
    }
}
