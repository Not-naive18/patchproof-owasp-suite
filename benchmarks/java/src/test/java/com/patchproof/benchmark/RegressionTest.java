package com.patchproof.benchmark;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

public class RegressionTest {

    @Test
    public void testAccountLookupPreservesBusinessFunctionality() throws Exception {
        PatchedEndpoints patched = new PatchedEndpoints();
        List<String> results = patched.findAccountByUser("john");
        assertEquals(1, results.size());
        assertEquals("john:500.0", results.get(0));
    }

    @Test
    public void testSqlInjectionMitigatedInPatchedVersion() throws Exception {
        VulnerableEndpoints vulnerable = new VulnerableEndpoints();
        PatchedEndpoints patched = new PatchedEndpoints();

        String payload = "' OR '1'='1";

        // Vulnerable implementation returns all records (2)
        List<String> vulnResults = vulnerable.findAccountByUser(payload);
        assertEquals(2, vulnResults.size());

        // Patched implementation neutralizes injection and returns empty list
        List<String> patchedResults = patched.findAccountByUser(payload);
        assertEquals(0, patchedResults.size());
    }

    @Test
    public void testHashAlgorithmProducesValidHash() throws Exception {
        PatchedEndpoints patched = new PatchedEndpoints();
        String hash = patched.hashUserPassword("mySecretPassword");
        assertNotNull(hash);
        // SHA-256 produces 64 hex characters
        assertEquals(64, hash.length());
    }
}
