<?php
/**
 * PatchProof AI Benchmark - PHP (Vulnerable Implementation)
 * Demonstrates OWASP Top 10 vulnerabilities in PHP web services.
 */

class VulnerableService {
    private PDO $pdo;

    public function __construct() {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->exec("CREATE TABLE members (id INTEGER PRIMARY KEY, username TEXT, role TEXT, password TEXT)");
        $this->pdo->exec("INSERT INTO members VALUES (1, 'alice', 'admin', '5f4dcc3b5aa765d61d8327deb882cf99')"); // md5('password')
        $this->pdo->exec("INSERT INTO members VALUES (2, 'bob', 'user', '5f4dcc3b5aa765d61d8327deb882cf99')");
    }

    // OWASP A03:2021 - SQL Injection
    public function searchMember(string $username): array {
        // VULNERABLE: Direct string interpolation into query
        $sql = "SELECT id, username, role FROM members WHERE username = '" . $username . "'";
        $stmt = $this->pdo->query($sql);
        return $stmt ? $stmt->fetchAll(PDO::FETCH_ASSOC) : [];
    }

    // OWASP A07:2021 - Weak Cryptographic Hash (MD5)
    public function verifyPassword(string $inputPassword, string $storedHash): bool {
        // VULNERABLE: md5 is unsafe for password verification
        return md5($inputPassword) === $storedHash;
    }

    // OWASP A08:2021 - Software and Data Integrity Failures (PHP Object Injection)
    public function restoreSession(string $serializedData) {
        // VULNERABLE: unserialize allows arbitrary gadget chains and RCE
        return unserialize($serializedData);
    }
}
