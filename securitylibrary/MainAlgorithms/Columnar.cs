using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();    
            int plainLength = plainText.Length;
            int cipherLength = cipherText.Length;

            for (int key = 2; key <= cipherLength; key++)
            {
                // Calculate rows
                int rows = (int)Math.Ceiling((float)cipherText.Length/ key);

                // Check if the matrix size matches the ciphertext length and if not continue to the next key 
                if (rows * key != cipherLength)
                    continue;
                //key=>colunms number
                //we write the plain text in the matrix row by row so we need to make the rows outer loop
                char[,] matrix = new char[rows, key];
                int pos = 0;
                for (int r = 0; r < rows; r++)
                {
                    for (int c = 0; c < key; c++)
                    {
                        if (pos < plainLength)
                            matrix[r, c] = plainText[pos++];
                        else
                            matrix[r, c] = 'x';
                    }
                }

                // Split the ciphertext into parts.
                List<string> parts = new List<string>();
                for (int i = 0; i < key; i++)
                {
                    parts.Add(cipherText.Substring(i * rows, rows));
                }

                
                int[] allkeys = new int[key];
                bool[] used = new bool[key];
                bool isvalid = true;
                for (int c = 0; c < key; c++)
                {
                    String s = "";
                    for (int r = 0; r < rows; r++)
                    {
                        s+=(matrix[r, c]);
                    }
                    

                    // Find a matching parts that not used.
                    int f = -1;
                    for (int i = 0; i < key; i++)
                    {
                        if (!used[i] && parts[i] == s)
                        {
                            f = i;
                            used[i] = true;
                            break;
                        }
                    }
                    if (f == -1)
                    {
                        isvalid = false;
                        break;
                    }
                    // go to the next column 
                    allkeys[c] = f + 1;
                }
                // If the key is not valid continue to the next key.
                if (!isvalid)
                    continue;
                
                string testCipher = Encrypt(plainText, new List<int>(allkeys)).ToLower();
                if (testCipher == cipherText)
                {
                    return new List<int>(allkeys);
                }
            }
            return new List<int>();


        }

        public string Decrypt(string cipherText, List<int> key)
        {
            cipherText = cipherText.Replace(" ", "").ToLower();
            int colnumbers = key.Count;
            int rowsnumbers = (int)Math.Ceiling((float)cipherText.Length / colnumbers);
            char[,] matrix = new char[rowsnumbers, colnumbers];
            List<int> skey = new List<int>(key);
            skey.Sort();
            int pos = 0;
            //make colmuns outer cause the rows changes faster than columns in filling
            for (int c = 0; c < colnumbers; c++)
            {
                int carranged = key.IndexOf(skey[c]);
                if (carranged == -1)
                {
                    throw new ArgumentException("Invalid key");
                }
                for (int r = 0; r < rowsnumbers; r++)
                {
                    if (pos < cipherText.Length)
                    {
                        matrix[r, carranged] = cipherText[pos++];
                    }
                    else
                    {
                        matrix[r, carranged] = 'x';
                    }
                }
            }
            string plaineext = "";
            for (int r = 0; r < rowsnumbers; r++)
            {
                for (int c = 0; c < colnumbers; c++)
                {
                    if (matrix[r, c] != '\0')
                    {
                        plaineext += matrix[r, c];
                    }
                }
            }
            return plaineext.ToUpper();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            plainText = plainText.Replace(" ", "").ToLower();
            int colnumbers = key.Count;
            int rowsnumbers = (int)Math.Ceiling((float)plainText.Length / colnumbers);
            char[,] matrix = new char[rowsnumbers, colnumbers];
            List<int> skey = new List<int>(key);
            skey.Sort();
            int pos = 0;
            //make rows outer cause the columns changes faster than rows in filling
            for (int r = 0; r < rowsnumbers; r++)
            {
                for (int c = 0; c < colnumbers; c++)
                {
                    if (pos < plainText.Length)
                    {
                        matrix[r, c] = plainText[pos++];
                    }
                    else
                    {
                        matrix[r, c] = 'x';
                    }
                }
            }
            string ciphertext = "";
            for (int c = 0; c < colnumbers; c++)
            {
                int carranged = key.IndexOf(skey[c]);
                for (int r = 0; r < rowsnumbers; r++)
                {
                    ciphertext += matrix[r, carranged];

                }

            }
            return ciphertext.ToUpper();
        }
    }
}
