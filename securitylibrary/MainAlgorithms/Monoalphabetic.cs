using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            char[] key = new char[26];
            for (int i = 0; i < plainText.Length; i++)
            {
                int m = plainText[i] - 'a';
                key[m] = cipherText[i];
            }
            for (int i = 0; i < 26; i++)
            {
                if (key[i] == '\0')
                {
                    bool found = false;
                    for (int j = 0; j < 26; j++)
                    {
                        found = false;
                        char c = (char)(j + 'a');
                        for (int k = 0; k < 26; k++)
                        {
                            if (key[k] == c)
                            {
                                found = true;
                                break;
                            }
                        }
                        if (!found)
                        {
                            key[i] = c;
                            break;
                        }
                    }
                }
            }
            string Key = "";
            for (int i = 0; i < key.Length; ++i)
            {
                Key += key[i];
            }

            return Key;
        }

        public string Decrypt(string cipherText, string key)
        {

            cipherText = cipherText.ToLower();
            key = key.ToLower();
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)

            {
                int j;
                char letter = cipherText[i];
                for (j = 0; j < key.Length; j++)
                {
                    if (key[j] == letter)
                    {
                        break;

                    }



                }
                char l = (char)(j + 'a');
                plainText = plainText + l;

            }
            return plainText;


        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();
            string ciphertext = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                int index = plainText[i] - 'a';
                ciphertext = ciphertext + key[index];
            }
            return ciphertext;

        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            int[] freq = new int[26];
            char[] eng = new char[26];
            string alpha = "etaoinsrhldcumfpgwybvkxjqz";

          
            for (int i = 0; i < 26; i++)
            {
                freq[i] = 0;
            }

        
            for (int j = 0; j < cipher.Length; j++)
            {
                if (cipher[j] >= 'a' && cipher[j] <= 'z')
                    freq[cipher[j] - 'a']++;
            }

          
            for (char letter = 'a'; letter <= 'z'; letter++)
            {
                eng[letter - 'a'] = letter;
            }

          
            for (int i = 0; i < 25; i++)
            {
                int maxIndex = i;
                for (int j = i + 1; j < 26; j++)
                {
                    if (freq[j] > freq[maxIndex])
                    {
                        maxIndex = j;
                    }
                }

                int temp1 = freq[i];
                freq[i] = freq[maxIndex];
                freq[maxIndex] = temp1;

                char temp2 = eng[i];
                eng[i] = eng[maxIndex];
                eng[maxIndex] = temp2;
            }

         
            string plainText = "";
            for (int i = 0; i < cipher.Length; i++)
            {
                char letter = cipher[i];
                int j;
                for (j = 0; j < 26; j++)
                {
                    if (eng[j] == letter)
                    {
                        break;
                    }
                }
              
                char l = alpha[j];
                plainText = plainText + l;
            }

            return plainText;
        }
    }
}
