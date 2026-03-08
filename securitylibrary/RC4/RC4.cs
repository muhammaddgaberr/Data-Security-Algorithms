using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            bool isHexMode = cipherText.StartsWith("0x") && key.StartsWith("0x");

            int[] keyBytes, cipherBytes;

            if (isHexMode)
            {
                string keyHex = key.Substring(2);
                string cipherHex = cipherText.Substring(2);
                keyBytes = new int[keyHex.Length / 2];
                cipherBytes = new int[cipherHex.Length / 2];
                for (int i = 0; i < keyBytes.Length; i++)
                    keyBytes[i] = Convert.ToInt32(keyHex.Substring(i * 2, 2), 16);
                for (int i = 0; i < cipherBytes.Length; i++)
                    cipherBytes[i] = Convert.ToInt32(cipherHex.Substring(i * 2, 2), 16);
            }
            else
            {
                keyBytes = new int[key.Length];
                cipherBytes = new int[cipherText.Length];
                for (int i = 0; i < keyBytes.Length; i++)
                    keyBytes[i] = key[i];
                for (int i = 0; i < cipherText.Length; i++)
                    cipherBytes[i] = cipherText[i];
            }

            int[] S = new int[256];
            for (int i = 0; i < 256; i++)
                S[i] = i;

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + keyBytes[i % keyBytes.Length]) % 256;
                int tmp = S[i]; S[i] = S[j]; S[j] = tmp;
            }

            int x = 0, y = 0;
            int[] outputBytes = new int[cipherBytes.Length];
            for (int i = 0; i < cipherBytes.Length; i++)
            {
                x = (x + 1) % 256;
                y = (y + S[x]) % 256;
                int tmp = S[x]; S[x] = S[y]; S[y] = tmp;
                int keystreamByte = S[(S[x] + S[y]) % 256];
                outputBytes[i] = cipherBytes[i] ^ keystreamByte;
            }

            if (isHexMode)
            {
                string result = "0x";
                for (int i = 0; i < outputBytes.Length; i++)
                    result += outputBytes[i].ToString("x2");
                return result;
            }
            else
            {
                string result = "";
                for (int i = 0; i < outputBytes.Length; i++)
                    result += (char)outputBytes[i];
                return result;
            }
        }

        public override  string Encrypt(string plainText, string key)
        {
            bool isHexMode = plainText.StartsWith("0x") && key.StartsWith("0x");

            int[] keyBytes, plainBytes;

            if (isHexMode)
            {
                string keyHex = key.Substring(2);
                string plainHex = plainText.Substring(2);
                keyBytes = new int[keyHex.Length / 2];
                plainBytes = new int[plainHex.Length / 2];
                for (int i = 0; i < keyBytes.Length; i++)
                    keyBytes[i] = Convert.ToInt32(keyHex.Substring(i * 2, 2), 16);
                for (int i = 0; i < plainBytes.Length; i++)
                    plainBytes[i] = Convert.ToInt32(plainHex.Substring(i * 2, 2), 16);
            }
            else
            {
                keyBytes = new int[key.Length];
                plainBytes = new int[plainText.Length];
                for (int i = 0; i < keyBytes.Length; i++)
                    keyBytes[i] = key[i];
                for (int i = 0; i < plainBytes.Length; i++)
                    plainBytes[i] = plainText[i];
            }

            int[] S = new int[256];
            for (int i = 0; i < 256; i++)
                S[i] = i;

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + keyBytes[i % keyBytes.Length]) % 256;
                int tmp = S[i]; S[i] = S[j]; S[j] = tmp;
            }

            int x = 0, y = 0;
            int[] outputBytes = new int[plainBytes.Length];
            for (int i = 0; i < plainBytes.Length; i++)
            {
                x = (x + 1) % 256;
                y = (y + S[x]) % 256;
                int tmp = S[x]; S[x] = S[y]; S[y] = tmp;
                int keystreamByte = S[(S[x] + S[y]) % 256];
                outputBytes[i] = plainBytes[i] ^ keystreamByte;
            }

            if (isHexMode)
            {
                string result = "0x";
                for (int i = 0; i < outputBytes.Length; i++)
                    result += outputBytes[i].ToString("x2");
                return result;
            }
            else
            {
                string result = "";
                for (int i = 0; i < outputBytes.Length; i++)
                    result += (char)outputBytes[i];
                return result;
            }
        }
    }
}
