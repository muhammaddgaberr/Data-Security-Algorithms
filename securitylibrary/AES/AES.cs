using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        private const int Nb = 4, Nk = 4, Nr = 10;

        private static readonly byte[] SBox = new byte[256] {
            0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
            0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
            0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
            0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
            0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
            0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
            0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
            0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
            0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
            0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
            0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
            0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
            0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
            0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
            0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
            0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
        };

        private static readonly byte[] Rcon = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

        private static byte[] StringToBytes(string s)
        {
            s = s.Substring(2);
            var b = new byte[16];
            for (int i = 0; i < 16; i++)
                b[i] = Convert.ToByte(s.Substring(2 * i, 2), 16);
            return b;
        }
        private static int[] HexToIntArray(string hex)
        {
            int len = hex.Length;
            int[] result = new int[len / 2];
            for (int i = 0; i < len; i += 2)
                result[i / 2] = Convert.ToInt32(hex.Substring(i, 2), 16);
            return result;
        }

        private static string IntArrayToHex(int[] arr)
        {
            StringBuilder sb = new StringBuilder();
            foreach (var i in arr)
                sb.Append(i.ToString("X2"));
            return sb.ToString();
        }

        private static void InvShiftRows(int[,] state)
        {
            int temp = state[1, 3];
            state[1, 3] = state[1, 2];
            state[1, 2] = state[1, 1];
            state[1, 1] = state[1, 0];
            state[1, 0] = temp;

            temp = state[2, 0];
            state[2, 0] = state[2, 2];
            state[2, 2] = temp;
            temp = state[2, 1];
            state[2, 1] = state[2, 3];
            state[2, 3] = temp;

            temp = state[3, 0];
            state[3, 0] = state[3, 1];
            state[3, 1] = state[3, 2];
            state[3, 2] = state[3, 3];
            state[3, 3] = temp;
        }

        private static void InvSubBytes(int[,] state)
        {
            int[] rsbox = new int[256];
            for (int i = 0; i < 256; i++) rsbox[SBox[i]] = i;
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] = rsbox[state[i, j]];
        }

        private static void InvMixColumns(int[,] state)
        {
            for (int c = 0; c < 4; c++)
            {
                int a0 = state[0, c], a1 = state[1, c], a2 = state[2, c], a3 = state[3, c];

                state[0, c] = Multiply(0x0e, a0) ^ Multiply(0x0b, a1) ^ Multiply(0x0d, a2) ^ Multiply(0x09, a3);
                state[1, c] = Multiply(0x09, a0) ^ Multiply(0x0e, a1) ^ Multiply(0x0b, a2) ^ Multiply(0x0d, a3);
                state[2, c] = Multiply(0x0d, a0) ^ Multiply(0x09, a1) ^ Multiply(0x0e, a2) ^ Multiply(0x0b, a3);
                state[3, c] = Multiply(0x0b, a0) ^ Multiply(0x0d, a1) ^ Multiply(0x09, a2) ^ Multiply(0x0e, a3);
            }
        }

        private static int Multiply(int a, int b)
        {
            int result = 0;
            while (b > 0)
            {
                if ((b & 1) != 0)
                    result ^= a;
                a <<= 1;
                if ((a & 0x100) != 0)
                    a ^= 0x11B;
                b >>= 1;
            }   
            return result & 0xFF;
        }

        private static void AddRoundKey(int[,] state, int[] expandedKey, int round)
        {
            int startIdx = round * 16;
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[j, i] ^= expandedKey[startIdx + i * 4 + j];
        }

        private static int[] KeyExpansion(int[] key)
        {
            int[] expandedKey = new int[176];
            int temp0, temp1, temp2, temp3;
            int rconIndex = 0;
            for (int i = 0; i < 16; i++)
                expandedKey[i] = key[i];

            for (int i = 16; i < 176; i += 4)
            {
                temp0 = expandedKey[i - 4];
                temp1 = expandedKey[i - 3];
                temp2 = expandedKey[i - 2];
                temp3 = expandedKey[i - 1];

                if ((i / 4) % 4 == 0)
                {
                    int t = temp0;
                    temp0 = temp1;
                    temp1 = temp2;
                    temp2 = temp3;
                    temp3 = t;

                    temp0 = SBox[temp0];
                    temp1 = SBox[temp1];
                    temp2 = SBox[temp2];
                    temp3 = SBox[temp3];

                    temp0 ^= Rcon[++rconIndex];
                }

                expandedKey[i] = expandedKey[i - 16] ^ temp0;
                expandedKey[i + 1] = expandedKey[i - 15] ^ temp1;
                expandedKey[i + 2] = expandedKey[i - 14] ^ temp2;
                expandedKey[i + 3] = expandedKey[i - 13] ^ temp3;
            }

            return expandedKey;
        }
        private static byte[][] KeyExpansionBytes(byte[] key)
        {
            int totalWords = Nb * (Nr + 1);
            var W = new byte[totalWords][];
            for (int i = 0; i < totalWords; i++)
                W[i] = new byte[4];

            for (int i = 0; i < Nk; i++)
                Array.Copy(key, 4 * i, W[i], 0, 4);

            for (int i = Nk; i < totalWords; i++)
            {
                var temp = (byte[])W[i - 1].Clone();
                if (i % Nk == 0)
                {
                    byte t = temp[0];
                    temp[0] = temp[1]; temp[1] = temp[2];
                    temp[2] = temp[3]; temp[3] = t;

                    for (int j = 0; j < 4; j++)
                        temp[j] = SBox[temp[j]];

                    temp[0] ^= Rcon[i / Nk];
                }

                for (int j = 0; j < 4; j++)
                    W[i][j] = (byte)(W[i - Nk][j] ^ temp[j]);
            }

            var roundKeys = new byte[Nr + 1][];
            for (int r = 0; r <= Nr; r++)
            {
                roundKeys[r] = new byte[16];
                for (int c = 0; c < Nb; c++)
                    Array.Copy(W[r * Nb + c], 0, roundKeys[r], 4 * c, 4);
            }

            return roundKeys;
        }
        private static void SubBytes(byte[] s)
        {
            for (int i = 0; i < 16; i++)
                s[i] = SBox[s[i]];
        }

        private static void ShiftRows(byte[] s)
        {
            byte t;
            t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
            t = s[2]; s[2] = s[10]; s[10] = t;
            t = s[6]; s[6] = s[14]; s[14] = t;
            t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
        }

        private static void MixColumns(byte[] s)
        {
            for (int c = 0; c < 4; c++)
            {
                int i = 4 * c;
                byte a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
                byte m2a0 = Mul2(a0), m2a1 = Mul2(a1), m2a2 = Mul2(a2), m2a3 = Mul2(a3);

                s[i] = (byte)(m2a0 ^ (m2a1 ^ a1) ^ a2 ^ a3);
                s[i + 1] = (byte)(a0 ^ m2a1 ^ (m2a2 ^ a2) ^ a3);
                s[i + 2] = (byte)(a0 ^ a1 ^ m2a2 ^ (m2a3 ^ a3));
                s[i + 3] = (byte)((m2a0 ^ a0) ^ a1 ^ a2 ^ m2a3);
            }
        }

        private static void AddRoundKey(byte[] state, byte[] roundKey)
        {
            for (int i = 0; i < 16; i++)
                state[i] ^= roundKey[i];
        }

        private static string HexToString(byte[] b)
        {
            var sb = new StringBuilder(32);
            foreach (var x in b) sb.Append(x.ToString("X2"));
            return sb.ToString();
        }

        private static byte Mul2(byte x) =>
            (byte)((x & 0x80) != 0 ? ((x << 1) ^ 0x1B) : (x << 1));


        public override string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.StartsWith("0x") ? cipherText.Substring(2) : cipherText;
            key = key.StartsWith("0x") ? key.Substring(2) : key;

            int[] keyIntArray = HexToIntArray(key);
            int[] cipherIntArray = HexToIntArray(cipherText);

            int[,] state = new int[4, 4];
            for (int i = 0; i < 16; i++)
                state[i % 4, i / 4] = cipherIntArray[i];

            int[] expandedKey = KeyExpansion(keyIntArray);

            AddRoundKey(state, expandedKey, Nr);

            for (int round = Nr - 1; round > 0; round--)
            {
                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, expandedKey, round);
                InvMixColumns(state);
            }

            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, expandedKey, 0);

            int[] output = new int[16];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    output[i * 4 + j] = state[j, i];

            return "0x" + IntArrayToHex(output);
        }

        public override string Encrypt(string plainText, string key)
        {
            byte[] state = StringToBytes(plainText);
            byte[][] roundKeys = KeyExpansionBytes(StringToBytes(key));

            AddRoundKey(state, roundKeys[0]);
            for (int round = 1; round < Nr; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, roundKeys[round]);
            }
            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, roundKeys[Nr]);

            return "0x" + HexToString(state);
        }
    }
}

