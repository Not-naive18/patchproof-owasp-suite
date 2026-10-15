<?php
/**
 * PatchProof AI Benchmark - PHP (Patched Implementation)
 * Demonstrates secure fixes with verified regression safety.
 */

class PatchedService {
    private PDO $pdo;

    public function __construct() {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->exec("CREATE TABLE members (id INTEGER PRIMARY KEY, username TEXT, role TEXT, password TEXT)");
        $hashed = password_hash('password', PASSWORD_BCRYPT);
        $stmt = $this->pdo->prepare("INSERT INTO members (id, username, role, password) VALUES (?, ?, ?, ?)");
        $stmt->execute([1, 'alice', 'admin', $hashed]);
        $stmt->execute([2, 'bob', 'user', $hashed]);
    }

    // PATCH A03: SQL Injection Neutralized with Parameterized PDO Statement
    public function searchMember(string $username): array {
        // SECURE: Parameterized prepared statement
        $stmt = $this->pdo->prepare("SELECT id, username, role FROM members WHERE username = :username");
        $stmt->execute([':username' => $username]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // PATCH A07: Secure Password Hashing (bcrypt)
    public function verifyPassword(string $inputPassword, string $storedHash): bool {
        // SECURE: Native constant-time password verification
        return password_verify($inputPassword, $storedHash);
    }

    // PATCH A08: Safe Deserialization using JSON
    public function restoreSession(string $jsonData): ?array {
        // SECURE: Safe JSON parsing without object instantiation
        $decoded = json_decode($jsonData, true);
        return is_array($decoded) ? $decoded : null;
    }
}
