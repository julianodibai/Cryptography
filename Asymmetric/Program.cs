using System;
using System.Security.Cryptography;

namespace AsymmetricEncryptionExample
{
    class Program
    {
        static void Main(string[] args)
        {
            string password = "myPassword";
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                byte[] encryptedPassword = Encrypt(passwordBytes, rsa.ExportParameters(false), false);

                Console.WriteLine("Encrypted Password: " + BitConverter.ToString(encryptedPassword).Replace("-", "").ToLower());

                byte[] decryptedPassword = Decrypt(encryptedPassword, rsa.ExportParameters(true), false);

                Console.WriteLine("Decrypted Password: " + System.Text.Encoding.UTF8.GetString(decryptedPassword));
            }
        }

        static byte[] Encrypt(byte[] data, RSAParameters RSAKey, bool doOAEPPadding)
        {
            byte[] encryptedData;

            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.ImportParameters(RSAKey);
                encryptedData = RSA.Encrypt(data, doOAEPPadding);
            }

            return encryptedData;
        }

        static byte[] Decrypt(byte[] data, RSAParameters RSAKey, bool doOAEPPadding)
        {
            byte[] decryptedData;

            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                RSA.ImportParameters(RSAKey);
                decryptedData = RSA.Decrypt(data, doOAEPPadding);
            }

            return decryptedData;
        }
    }
}
