using SecurityLibrary;
using System;

class Program
{
    static void Main()
    {
        CryptographicTechnique cryptographicTechnique = new SecurityLibrary.DES.DES();
        Console.WriteLine("Enter the plain text:");
        string plainText = "Hello World!";
        Console.WriteLine(22);
        string key = "12345678";
        Console.WriteLine("Enter the key:");
        string cipherText = cryptographicTechnique.Encrypt(plainText, key);
        Console.WriteLine("Cipher text:");
        Console.WriteLine(cipherText);
    }
}
