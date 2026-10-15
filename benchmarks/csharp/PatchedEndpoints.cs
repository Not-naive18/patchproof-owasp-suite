using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace PatchProof.Benchmark
{
    public class PatchedEndpoints
    {
        private readonly SqliteConnection _connection;

        public PatchedEndpoints()
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

        // PATCH A02: Strong Cryptography (SHA-256)
        public string ComputeChecksum(string input)
        {
            // SECURE: SHA-256 cryptographic hash
            using var sha256 = SHA256.Create();
            byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToHexString(bytes);
        }

        // PATCH A03: Parameterized SQL Command
        public List<string> QueryCustomers(string emailFilter)
        {
            var results = new List<string>();
            using var cmd = _connection.CreateCommand();
            // SECURE: Parameterized query prevents SQL injection
            cmd.CommandText = "SELECT Email, CreditLimit FROM Customers WHERE Email = @email";
            cmd.Parameters.AddWithValue("@email", emailFilter);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                results.Add(reader.GetString(0) + ":" + reader.GetDouble(1));
            }
            return results;
        }
    }
}
