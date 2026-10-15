using System.Collections.Generic;
using Xunit;

namespace PatchProof.Benchmark
{
    public class RegressionTests
    {
        [Fact]
        public void TestCustomerQueryPreservesFunctionality()
        {
            var patched = new PatchedEndpoints();
            List<string> results = patched.QueryCustomers("client1@corp.com");

            Assert.Single(results);
            Assert.Equal("client1@corp.com:50000", results[0]);
        }

        [Fact]
        public void TestSqlInjectionMitigated()
        {
            var vuln = new VulnerableEndpoints();
            var patched = new PatchedEndpoints();

            string attackPayload = "' OR '1'='1";

            // Vulnerable endpoint returns all customers (2)
            List<string> vulnResults = vuln.QueryCustomers(attackPayload);
            Assert.Equal(2, vulnResults.Count);

            // Patched endpoint treats input as literal string and returns 0 records
            List<string> patchedResults = patched.QueryCustomers(attackPayload);
            Assert.Empty(patchedResults);
        }
    }
}
