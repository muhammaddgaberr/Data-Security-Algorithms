using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        private int FindMatrixSize(int count)
        {
            for (int i = 1; i * i <= count; i++)
            {
                if (i * i == count)
                    return i;
            }
            return -1;
        }
        private int Mod26(int num)
        {
            while (num < 0)
                num += 26;
            return num % 26;
        }
        private int ComputeDeterminant(List<int> matrix, int n)
        {
            if (n == 2)
            {
                int determinant = matrix[0] * matrix[3] - matrix[1] * matrix[2];
                return Mod26(determinant);
            }
            else if (n == 3)
            {
                int determinant =
                    matrix[0] * (matrix[4] * matrix[8] - matrix[5] * matrix[7])
                  - matrix[1] * (matrix[3] * matrix[8] - matrix[5] * matrix[6])
                  + matrix[2] * (matrix[3] * matrix[7] - matrix[4] * matrix[6]);
                return Mod26(determinant);
            }

            throw new InvalidAnlysisException();
        }
        private int GCD(int a, int b)
        {
            while (b != 0)
            {
                int temp = b;
                b = a % b;
                a = temp;
            }
            return a;
        }
        private int ModularInverse(int num, int mod)
        {
            if (GCD(num, mod) != 1) // Ensures num is coprime with mod
                return -1;

            for (int i = 1; i < mod; i++)
            {
                if ((num * i) % mod == 1)
                    return i;
            }
            return -1;
        }
        private List<int> ComputeAdjugate(List<int> matrix, int n)
        {
            List<int> adjugate = new List<int>(new int[matrix.Count]);

            if (n == 2)
            {
                adjugate[0] = matrix[3];
                adjugate[1] = -matrix[1];
                adjugate[2] = -matrix[2];
                adjugate[3] = matrix[0];
                for(int i=0; i<adjugate.Count; i++)
                {
                    if (adjugate[i] < 0)
                    {
                        adjugate[i] = Mod26(adjugate[i]);
                    }
                }
            }
            else if (n == 3)
            {
                adjugate[0] = matrix[4] * matrix[8] - matrix[5] * matrix[7];
                adjugate[1] = -(matrix[3] * matrix[8] - matrix[5] * matrix[6]);
                adjugate[2] = matrix[3] * matrix[7] - matrix[4] * matrix[6];

                adjugate[3] = -(matrix[1] * matrix[8] - matrix[2] * matrix[7]);
                adjugate[4] = matrix[0] * matrix[8] - matrix[2] * matrix[6];
                adjugate[5] = -(matrix[0] * matrix[7] - matrix[1] * matrix[6]);

                adjugate[6] = matrix[1] * matrix[5] - matrix[2] * matrix[4];
                adjugate[7] = -(matrix[0] * matrix[5] - matrix[2] * matrix[3]);
                adjugate[8] = matrix[0] * matrix[4] - matrix[1] * matrix[3];
            }

            return adjugate;
        }

        private List<int> InvertMatrix(List<int> matrix, int n)
        {
            int det = ComputeDeterminant(matrix, n);
            int detInverse = ModularInverse(det, 26);

            if (detInverse == -1) // If determinant has no inverse, throw the expected exception
                throw new InvalidAnlysisException();
            List<int> adjugate = ComputeAdjugate(matrix, n);
            // Transpose the adjugate matrix
            List<int> transposedAdjugate = new List<int>(new int[adjugate.Count]);
            if (n == 3)
            {
                for (int i = 0; i < n; i++)
                {
                    for (int j = 0; j < n; j++)
                    {
                        transposedAdjugate[j * n + i] = adjugate[i * n + j]; // Swap rows and columns
                    }
                }
            }
            List<int> inverseMatrix = new List<int>();
            if (n == 2)
            {
                for (int i = 0; i < adjugate.Count; i++)
                {
                    inverseMatrix.Add(Mod26(adjugate[i] * detInverse));
                }
            }
            else if (n == 3)
            {
                for (int i = 0; i < transposedAdjugate.Count; i++)
                {
                    inverseMatrix.Add(Mod26(transposedAdjugate[i] * detInverse));
                }
            }
            return inverseMatrix;
        }

        private List<int> MultiplyMatricesMod26(List<int> A, List<int> B, int n)
        {
            List<int> result = new List<int>(new int[n * n]);

            for (int row = 0; row < n; row++)
            {
                for (int col = 0; col < n; col++)
                {
                    int sum = 0;
                    for (int k = 0; k < n; k++)
                    {
                        sum += A[row * n + k] * B[k * n + col];
                    }
                    result[row * n + col] = Mod26(sum);
                }
            }

            return result;
        }


        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int n = 2;

            // Verify enough data
            if (plainText.Count < 4 || cipherText.Count < 4)
                throw new InvalidAnlysisException();

            // Try combinations to find an invertible plaintext matrix
            for (int i = 0; i <= plainText.Count - 4; i += 2)
            {
                for (int j = i + 2; j <= plainText.Count - 2; j += 2)
                {
                    List<int> plaintextMatrix = new List<int>
            {
                plainText[i], plainText[j],
                plainText[i + 1], plainText[j + 1]
            };

                    int det = ComputeDeterminant(plaintextMatrix, n);
                    if (GCD(det, 26) == 1) // invertible matrix found
                    {
                        List<int> ciphertextMatrix = new List<int>
                {
                    cipherText[i], cipherText[j],
                    cipherText[i + 1], cipherText[j + 1]
                };

                        List<int> plaintextMatrixInverse = InvertMatrix(plaintextMatrix, n);
                        return MultiplyMatricesMod26(ciphertextMatrix, plaintextMatrixInverse, n);
                    }
                }
            }

            throw new InvalidAnlysisException();
        }



        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int n = FindMatrixSize(key.Count);
            if (n == -1)
                throw new InvalidAnlysisException();
            List<int> inverseKey = InvertMatrix(key, n);
            List<int> plainText = new List<int>();
            for (int i = 0; i < cipherText.Count; i += n)
            {
                for (int row = 0; row < n; row++)
                {
                    int sum = 0;
                    for (int col = 0; col < n; col++)
                    {
                        sum += inverseKey[row * n + col] * cipherText[i + col];
                    }
                    plainText.Add(Mod26(sum));
                }
            }

            return plainText;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int n = FindMatrixSize(key.Count);
            if (n == -1)
                throw new InvalidAnlysisException();

            while (plainText.Count % n != 0)
                plainText.Add(23); // 'X' = 23

            List<int> cipherText = new List<int>();

            for (int i = 0; i < plainText.Count; i += n)
            {
                for (int row = 0; row < n; row++)
                {
                    int sum = 0;
                    for (int col = 0; col < n; col++)
                    {
                        sum += key[row * n + col] * plainText[i + col]; // Matrix multiplication
                    }
                    cipherText.Add(Mod26(sum));
                }
            }

            return cipherText;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int n = 3;

            if (plainText.Count < 9 || cipherText.Count < 9)
                throw new InvalidAnlysisException();

            int totalBlocks = plainText.Count / n;

            // Try all combinations of three different blocks to form an invertible plaintext matrix.
            for (int i = 0; i < totalBlocks; i++)
            {
                for (int j = i + 1; j < totalBlocks; j++)
                {
                    for (int k = j + 1; k < totalBlocks; k++)
                    {
                        List<int> plaintextMatrix = new List<int>()
                {
                    plainText[i * n], plainText[j * n], plainText[k * n],
                    plainText[i * n + 1], plainText[j * n + 1], plainText[k * n + 1],
                    plainText[i * n + 2], plainText[j * n + 2], plainText[k * n + 2]
                };

                        // Check if the plaintext matrix is invertible
                        int det = ComputeDeterminant(plaintextMatrix, n);
                        if (GCD(det, 26) == 1)
                        {
                            // If invertible, construct the corresponding ciphertext matrix
                            List<int> ciphertextMatrix = new List<int>()
                    {
                        cipherText[i * n], cipherText[j * n], cipherText[k * n],
                        cipherText[i * n + 1], cipherText[j * n + 1], cipherText[k * n + 1],
                        cipherText[i * n + 2], cipherText[j * n + 2], cipherText[k * n + 2]
                    };

                            // Compute the inverse of the plaintext matrix
                            List<int> plaintextMatrixInverse = InvertMatrix(plaintextMatrix, n);

                            // key = ciphertextMatrix * plaintextMatrixInverse (mod 26)
                            return MultiplyMatricesMod26(ciphertextMatrix, plaintextMatrixInverse, n);
                        }
                    }
                }
            }

            throw new InvalidAnlysisException();
        }

    }
}
