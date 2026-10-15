<?php
/**
 * PatchProof AI Regression Test Suite - PHP
 * Verifies vulnerability neutralization while preserving legitimate member lookups.
 */

require_once __DIR__ . '/vulnerable.php';
require_once __DIR__ . '/patched.php';

use PHPUnit\Framework\TestCase;

class RegressionTest extends TestCase {

    public function testMemberSearchFunctionalityPreserved() {
        $service = new PatchedService();
        $results = $service->searchMember('alice');

        $this->assertCount(1, $results);
        $this->assertEquals('alice', $results[0]['username']);
        $this->assertEquals('admin', $results[0]['role']);
    }

    public function testSqlInjectionMitigated() {
        $vuln = new VulnerableService();
        $patched = new PatchedService();

        $sqliPayload = "' OR '1'='1";

        // Vulnerable service leaks all records (2)
        $vulnResults = $vuln->searchMember($sqliPayload);
        $this->assertCount(2, $vulnResults);

        // Patched service returns empty array (0)
        $patchedResults = $patched->searchMember($sqliPayload);
        $this->assertCount(0, $patchedResults);
    }
}
