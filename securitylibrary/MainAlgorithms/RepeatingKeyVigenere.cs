using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int len_of_cipherText = cipherText.Length;
            string key = "";
            for (int i = 0; i < len_of_cipherText; ++i)
            {
                //a=0,b=1,c=2
                //j=9 , h = 7 ==> (j-h = 2 = c)
                int diff_rkm = cipherText[i] - plainText[i];
                if (diff_rkm < 0)
                {
                    diff_rkm += 26;
                }
                char The_letter = (char)(diff_rkm + 'a');
                key = key + The_letter;
            }
            string final_key = "";
            for (int i=0;i<len_of_cipherText;++i)
            {
                final_key += key[i];
                if (cipherText.Equals(Encrypt(plainText,final_key)))
                {
                    return final_key;
                }
            }
            return final_key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            int len_of_cipherText = cipherText.Length;
            int len_of_key = key.Length;
            if (len_of_key < len_of_cipherText)
            {
                int diff_len = len_of_cipherText - len_of_key;
                for (int i = 0; i < diff_len; i++)
                {
                    key = key + key[i];
                }
            }
            string plainText = "";
            for (int i = 0; i < len_of_cipherText; ++i)
            {
                //a=0,b=1,c=2
                //j=9 , h = 7 ==> (j-h = 2 = c)
                int diff_rkm = cipherText[i] - key[i];
                if (diff_rkm < 0)
                {
                    diff_rkm += 26;
                }
                char The_letter = (char)(diff_rkm + 'a');
                plainText = plainText + The_letter;
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText= plainText.ToLower();
            key= key.ToLower();
            int len_of_plainText = plainText.Length;
            int len_of_key = key.Length;
            if (len_of_key < len_of_plainText)
            {
                int diff_len = len_of_plainText - len_of_key;
                for (int i = 0; i < diff_len; i++)
                {
                    key = key + key[i];
                }
            }
            string cipherText = "";
            for (int i = 0; i < len_of_plainText; ++i) 
            {
                cipherText = cipherText + (char)((((plainText[i] - 'a') + (key[i] - 'a')) % 26) + 'a');
            }
            return cipherText;
        }
    }
}