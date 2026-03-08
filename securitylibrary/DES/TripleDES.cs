using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {

        DES des = new DES();
        public string Encrypt(string plainText, List<string> keys)
        {


            string cipher1 = des.Encrypt(plainText, keys[0]);
            string cipher2 = des.Decrypt(cipher1, keys[1]);
            string fc = des.Encrypt(cipher2, keys[0]);

            return fc;
        }

        public string Decrypt(string cipherText, List<string> keys)
        {

            string plain1 = des.Decrypt(cipherText, keys[0]);
            string plain2 = des.Encrypt(plain1, keys[1]);
            string fp = des.Decrypt(plain2, keys[0]);

            return fp;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}