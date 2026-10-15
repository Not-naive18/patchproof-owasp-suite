using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace PatchProof.Benchmark
{
    public class VulnerableEndpoints
    {
        private readonly SqliteConnection _connection;

        public VulnerableEndpoints()
        {
            _connection = new SqliteConnection("Data Source=:memory:");
            _connection.Open();

            using var cmd = _connection.CreateCommand();
            cmd.CommandText = @"
                CREATE TABLE Customers (Id INTEGER PRIMARY KEY, Email TEXT, CreditLimit REAL);
                INSERT INTO Customers VALUES (1, 'client1@corp.com', 50000);
                INSERT INTO Customers VALUES (2, 'client2@corp.com', 75000);
            ";
            cmd.ExecuteNonQuery();
        }

        // OWASP A02:2021 - Weak Cryptography (MD5)
        public string ComputeChecksum(string input)
        {
            // VULNERABLE: MD5 is insecure
            using var md5 = MD5.Create();
            byte[] bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToHexString(bytes);
        }

        // OWASP A03:2021 - SQL Injection
        public List<string> QueryCustomers(string emailFilter)
        {
            var results = new List<string>();
            using var cmd = _connection.CreateCommand();
            // VULNERABLE: Dynamic SQL string concatenation
            cmd.CommandText = "SELECT Email, CreditLimit FROM Customers WHERE Email = '" + emailFilter + "'";
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                results.Add(reader.GetString(0) + ":" + reader.GetDouble(1));
            }
            return results;
        }
    }
}
