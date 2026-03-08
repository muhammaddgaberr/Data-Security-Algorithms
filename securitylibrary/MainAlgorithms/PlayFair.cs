using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Analyse(string largeCipher)
        {
            string cipher = new string(largeCipher.ToLower().Replace("j", "i")
                                                  .Where(char.IsLetter).ToArray());
            string[] wordlist = {
        "password", "pasword", "qwerty", "letmein", "monkey", "dragon",
        "master", "sunshine", "princess", "welcome", "shadow", "superman",
        "playfair", "cipher", "secret", "keyword", "crypto", "security",
        "monarchy", "example", "zebras", "charles", "wheatstone",
        "test", "hello", "abc", "key"
    };
            string bestResult = "";
            double bestScore = double.MinValue;

            foreach (string candidateKey in wordlist)
            {
                HashSet<char> used = new HashSet<char>();
                char[,] matrix = new char[5, 5];
                int mr = 0, mc = 0;

                foreach (char ch in new string(candidateKey.ToLower().Replace("j", "i")
                                                            .Where(char.IsLetter).ToArray())
                                    .Concat("abcdefghiklmnopqrstuvwxyz"))
                {
                    if (!used.Contains(ch))
                    {
                        used.Add(ch);
                        matrix[mr, mc] = ch;
                        mc++;
                        if (mc == 5) { mc = 0; mr++; }
                        if (mr == 5) break;
                    }
                }

                string candidate = "";
                for (int i = 0; i < cipher.Length; i += 2)
                {
                    char a = cipher[i], b = cipher[i + 1];
                    int r1 = 0, c1 = 0, r2 = 0, c2 = 0;
                    for (int row = 0; row < 5; row++)
                        for (int col = 0; col < 5; col++)
                        {
                            if (matrix[row, col] == a) { r1 = row; c1 = col; }
                            if (matrix[row, col] == b) { r2 = row; c2 = col; }
                        }

                    if (r1 == r2)
                    {
                        candidate += matrix[r1, (c1 + 4) % 5];
                        candidate += matrix[r2, (c2 + 4) % 5];
                    }
                    else if (c1 == c2)
                    {
                        candidate += matrix[(r1 + 4) % 5, c1];
                        candidate += matrix[(r2 + 4) % 5, c2];
                    }
                    else
                    {
                        candidate += matrix[r1, c2];
                        candidate += matrix[r2, c1];
                    }
                }
                int n = candidate.Length;
                Dictionary<char, int> freq = new Dictionary<char, int>();
                foreach (char ch in candidate)
                    freq[ch] = freq.ContainsKey(ch) ? freq[ch] + 1 : 1;

                double ic = 0;
                foreach (var kv in freq)
                    ic += (double)kv.Value * (kv.Value - 1);
                ic /= (double)n * (n - 1);

                if (ic > bestScore)
                {
                    bestScore = ic;
                    bestResult = candidate;
                }
            }
            return bestResult;
        }

        public string Decrypt(string cipherText, string key)
        {
            // 1. Normalize — identical to Encrypt
            key = new string(key.ToLower().Replace("j", "i").Where(char.IsLetter).ToArray());
            cipherText = new string(cipherText.ToLower().Replace("j", "i").Where(char.IsLetter).ToArray());

            // 2. Build matrix — identical to Encrypt
            HashSet<char> used = new HashSet<char>();
            char[,] matrix = new char[5, 5];
            int r = 0, c = 0;

            foreach (char ch in key.Concat("abcdefghiklmnopqrstuvwxyz"))
            {
                if (!used.Contains(ch))
                {
                    used.Add(ch);
                    matrix[r, c] = ch;
                    c++;
                    if (c == 5) { c = 0; r++; }
                    if (r == 5) break;
                }
            }

            // 3. Reverse transformation → produces raw text (still contains padding x's)
            string raw = "";
            for (int i = 0; i < cipherText.Length; i += 2)
            {
                char a = cipherText[i], b = cipherText[i + 1];
                int r1 = 0, c1 = 0, r2 = 0, c2 = 0;

                for (int row = 0; row < 5; row++)
                    for (int col = 0; col < 5; col++)
                    {
                        if (matrix[row, col] == a) { r1 = row; c1 = col; }
                        if (matrix[row, col] == b) { r2 = row; c2 = col; }
                    }

                if (r1 == r2) { raw += matrix[r1, (c1 + 4) % 5]; raw += matrix[r2, (c2 + 4) % 5]; }
                else if (c1 == c2) { raw += matrix[(r1 + 4) % 5, c1]; raw += matrix[(r2 + 4) % 5, c2]; }
                else { raw += matrix[r1, c2]; raw += matrix[r2, c1]; }
            }

            // 4. Remove ONLY the padding x's Encrypt inserted, preserving natural x's
            //    Process digraph pairs: skip second char if it is a padding 'x'
            //    Padding 'x' rule:  second == 'x'  AND
            //      (a) first == next-pair's-first  →  x was inserted between double letters
            //      (b) this is the last pair        →  x was appended to complete odd-length input
            string plainText = "";
            int totalPairs = raw.Length / 2;
            for (int i = 0; i < raw.Length; i += 2)
            {
                char a = raw[i];
                char b = raw[i + 1];
                int pairIndex = i / 2;
                bool isLastPair = (pairIndex == totalPairs - 1);
                char nextFirst = isLastPair ? '\0' : raw[i + 2];

                plainText += a;

                // b is padding if it is 'x' AND matches either padding condition
                bool isPaddingX = b == 'x' && (isLastPair || a == nextFirst);
                if (!isPaddingX)
                    plainText += b;
            }

            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            key = new string(key.ToLower().Replace("j", "i").Where(char.IsLetter).ToArray());
            plainText = new string(plainText.ToLower().Replace("j", "i").Where(char.IsLetter).ToArray());

            HashSet<char> used = new HashSet<char>();
            char[,] matrix = new char[5, 5];
            int r = 0, c = 0;

            foreach (char ch in key.Concat("abcdefghiklmnopqrstuvwxyz"))
            {
                if (!used.Contains(ch))
                {
                    used.Add(ch);
                    matrix[r, c] = ch;
                    c++;
                    if (c == 5) { c = 0; r++; }
                    if (r == 5) break;
                }
            }

            List<string> digraphs = new List<string>();
            for (int i = 0; i < plainText.Length; i++)
            {
                char first = plainText[i];
                char second;

                if (i + 1 < plainText.Length)
                {
                    if (plainText[i] == plainText[i + 1])
                    {
                        second = 'x';
                    }
                    else
                    {
                        second = plainText[i + 1];
                        i++; 
                    }
                }
                else
                {
                    second = 'x'; 
                }
                digraphs.Add($"{first}{second}");
            }

            string cipherText = "";
            foreach (string pair in digraphs)
            {
                int r1 = 0, c1 = 0, r2 = 0, c2 = 0;
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (matrix[i, j] == pair[0]) { r1 = i; c1 = j; }
                        if (matrix[i, j] == pair[1]) { r2 = i; c2 = j; }
                    }
                }

                if (r1 == r2)
                {
                    cipherText += matrix[r1, (c1 + 1) % 5];
                    cipherText += matrix[r2, (c2 + 1) % 5];
                }
                else if (c1 == c2) 
                {
                    cipherText += matrix[(r1 + 1) % 5, c1];
                    cipherText += matrix[(r2 + 1) % 5, c2];
                }
                else 
                {
                    cipherText += matrix[r1, c2];
                    cipherText += matrix[r2, c1];
                }
            }

            return cipherText;
        }
    }
}
