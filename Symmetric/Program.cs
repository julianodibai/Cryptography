﻿using System.Security.Cryptography;
using System.Text;
using static System.Console;

class Program
{
    static void Main(string[] args)
    {
        string original = "Mensagem original";
        WriteLine(original);

        // Cria uma instância de Aes para a criptografia
        using (Aes aes = Aes.Create())
        {
            // Gera a chave e o vetor de inicialização
            aes.GenerateKey();
            aes.GenerateIV();

            // Armazena a chave e o vetor de inicialização em arrays de bytes
            byte[] key = aes.Key;
            byte[] iv = aes.IV;

            // Criptografa a mensagem original
            byte[] encrypted = Encrypt(original, key, iv);

            // Exibe a mensagem criptografada
            WriteLine("Mensagem criptografada: " + Convert.ToBase64String(encrypted));

            // Decriptografa a mensagem criptografada
            string decrypted = Decrypt(encrypted, key, iv);

            // Exibe a mensagem decriptografada
            WriteLine("Mensagem decriptografada: " + decrypted);
        }
    }

    static byte[] Encrypt(string plainText, byte[] key, byte[] iv)
    {
        byte[] encrypted;

        var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        // Cria um encriptador para realizar a criptografia
        ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

        // Cria um fluxo de memória para armazenar o texto claro
        using (MemoryStream msEncrypt = new MemoryStream())
        {
            // Cria um fluxo de criptografia para escrever os dados criptografados no fluxo de memória
            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                {
                    // Escreve o texto claro no fluxo de criptografia
                    swEncrypt.Write(plainText);
                }

                encrypted = msEncrypt.ToArray();
            }
        }
        
        return encrypted;
    }
    static string Decrypt(byte[] cipherText, byte[] key, byte[] iv)
    {
        string plaintext = null;

        var aes = Aes.Create();
        
        aes.Key = key;
        aes.IV = iv;

        // Cria um decriptador para realizar a decriptografia
        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

        // Cria um fluxo de memória para armazenar o texto cifrado
        using (MemoryStream msDecrypt = new MemoryStream(cipherText))
        {
            // Cria um fluxo de decriptografia para ler os dados decifrados do fluxo de memória
            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            {
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    // Lê o texto decifrado do fluxo de decriptografia
                    plaintext = srDecrypt.ReadToEnd();
                }
            }
        }
            
        return plaintext;
    }
}
