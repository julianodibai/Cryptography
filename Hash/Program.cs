using System.Text;
using System.Security.Cryptography;
using Isopoh.Cryptography.Argon2;
using static System.Console;
using Isopoh.Cryptography.SecureArray;

class Program
{
    static void Main(string[] args)
    {
        WriteLine("Enter a password:");
        string password = ReadLine();

        WriteLine("Hashed Sha256 password: " + Getsha256Hash(password));
        WriteLine("Hashed Md5 password: " + GetMd5Hash(password));
        WriteLine("Hashed password using package BCrypt: " + HashPasswordBCrypt(password));
        WriteLine("Hashed password using package Argon2 simple: " + HashPasswordArgon2Simple(password));
        WriteLine("Hashed password using package Argon2 complex: " + HashPasswordArgon2Complex(password));
    }

    static string Getsha256Hash(string input)
    {
        using (SHA256 sha256Hash = SHA256.Create())
        {
            // ComputeHash - returns byte array  
            byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

            // Convert byte array to a string   
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            return builder.ToString();
        }
    }

    static string GetMd5Hash(string input)
    {
        using (MD5 md5Hash = MD5.Create())
        {
            // ComputeHash - returns byte array  
            byte[] bytes = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));
            // Convert byte array to a string   
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            return builder.ToString();
        }
    }
    static string HashPasswordBCrypt(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password);
    }
    static string HashPasswordArgon2Simple(string password)
    {
        var salt = new byte[16];
        byte[] passwordBytes2 = Encoding.UTF8.GetBytes(password);
        var hash = Argon2.Hash(passwordBytes2, salt);

        var passwordVerified = Argon2.Verify(hash, passwordBytes2, salt);

        return hash;
    }
    static string HashPasswordArgon2Complex(string password)
    {
        string hashString;
        var salt = new byte[16];      
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

        var config = new Argon2Config
        {
            Type = Argon2Type.DataIndependentAddressing,
            Version = Argon2Version.Nineteen,
            TimeCost = 10,
            MemoryCost = 32768,
            Lanes = 5,
            Threads = Environment.ProcessorCount, // higher than "Lanes" doesn't help (or hurt)
            Password = passwordBytes,
            Salt = salt, // >= 8 bytes if not null
            Secret = Encoding.UTF8.GetBytes("teste"), // from somewhere
            AssociatedData = Encoding.UTF8.GetBytes("teste"), // from somewhere
            HashLength = 20 // >= 4
        };

        var argon2A = new Argon2(config);

        using(SecureArray<byte> hashA = argon2A.Hash())
        {
            hashString = config.EncodeString(hashA.Buffer);
        }

        return hashString;
    }
}
