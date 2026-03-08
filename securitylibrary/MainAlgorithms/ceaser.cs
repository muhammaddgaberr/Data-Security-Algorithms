using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            string cipherTex = "";
            
           char [] charArr = plainText.ToCharArray();
           for(int i=0; i<charArr.Length; i++)
            {
                charArr[i] = (char)('a' + (charArr[i] - 'a' + key) % 26);
            }
            return new string(charArr);
            
        }

        public string Decrypt(string cipherText, int key)
        {
            // throw new NotImplementedException();
             cipherText= cipherText.ToLower();
            string plainText = "";
            char[] charArr = cipherText.ToCharArray();
            for(int i = 0; i < charArr.Length; i++)
            {
                charArr[i]=(char)('a' + (charArr[i] - 'a' - key+26) % 26);
            }
            return new string(charArr);
        }

        public int Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException
            int key=0;
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            for (int i = 0; i < plainText.Length; i++)
            {
                char plainChar = plainText[i];
                char cipherChar = cipherText[i];
                 key = (cipherChar - plainChar + 26) % 26;
                return key;
            }

            return 0;
        }
    }
}
