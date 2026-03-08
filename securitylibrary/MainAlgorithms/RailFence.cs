using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int lengthOfplaine = plainText.Length;
            for (int key=2;key<=lengthOfplaine;key++)
            {
                string result = Decrypt(cipherText, key);

                if (result.StartsWith(plainText,StringComparison.InvariantCultureIgnoreCase))
                {
                    return key;   
                    
                }
            }
            return -1;
          
        }

        public string Decrypt(string cipherText, int key)
        {
           cipherText = cipherText.Replace(" ", "").ToLower();
           int Colnumbers=(int)Math.Ceiling((float)cipherText.Length / key);
            //make array 2D key=>rows,colnumbers=>columns
            char[,] matrix = new char[key,Colnumbers];
            //make rows outer cause the columns changes faster than raws in filling
            int pos = 0;
            for(int r=0;r<key && pos < cipherText.Length; r++)
            {
                for(int c=0;c<Colnumbers && pos < cipherText.Length; c++)
                {
                    matrix[r, c] = cipherText[pos++];
                }
            }
            string plaintext = "";
            for(int c=0;c<Colnumbers;c++)
            {
                for(int r=0;r<key;r++)
                {
                    if (matrix[r,c]!='\0')
                    {
                        plaintext += matrix[r, c];
                    }
                }
            }
            return plaintext.ToUpper();
        }

        public string Encrypt(string plainText, int key)
        {
            plainText = plainText.Replace(" ", "").ToLower();
            int colnumbers = (int)Math.Ceiling((float)plainText.Length / key);
            //make array 2D key=>rows,colnumbers=>columns
            char[,] matrix = new char[key, colnumbers];
            //make columns outer cause the rows changes faster than columns in filling
            int pos = 0;
            for (int c = 0; c < colnumbers && pos<plainText.Length; c++)
            {
                for (int r = 0; r < key && pos<plainText.Length; r++)
                {
                    matrix[r, c] = plainText[pos++];
                }
            }

            String ciphertext = "";
            //make rows outer cause the columns changes faster than raws in reading
            for (int r = 0; r < key; r++)
            {
                for (int c = 0; c < colnumbers; c++)
                {
                    if (matrix[r, c]!= '\0')
                    {
                        ciphertext+=matrix[r, c];
                    }
                }
            }
            return ciphertext.ToUpper();
            //throw new NotImplementedException();
        }
    }
}
