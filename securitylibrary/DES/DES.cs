using Microsoft.SqlServer.Server;
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
    public class DES : CryptographicTechnique
    {
        int[,,] sBoxes = new int[8, 4, 16]
{
    {
        { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
        { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
        { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    {
        { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
        { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
        { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
        { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
    },
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
        { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
        { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
        { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    {
        { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
        { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
        { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
        { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
    },
    {
        { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
        { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
        { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
        { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
    },
    {
        { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
        { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
        { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
        { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
    },
    {
        { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
        { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
        { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
        { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
    },
    {
        { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
        { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
        { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
        { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
    }
};
        int[] ip =
            {
                58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7
            };
        int[] pc1 = {
                57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4
            };
        int[] left_shift = {
                1, 1, 2, 2, 2, 2, 2, 2,
                1, 2, 2, 2, 2, 2, 2, 1
            };
        int[] pc2 = {
                14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32
            };
        int[] p = {
                16, 7, 20, 21, 29, 12, 28, 17,
                1, 15, 23, 26, 5, 18, 31, 10,
                2, 8, 24, 14, 32, 27, 3, 9,
                19, 13, 30, 6, 22, 11, 4, 25
            };
        int[] e = {
                32, 1, 2, 3, 4, 5,
                4, 5, 6, 7, 8, 9,
                8, 9, 10, 11, 12, 13,
                12, 13, 14, 15, 16, 17,
                16, 17, 18, 19, 20, 21,
                20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29,
                28, 29, 30, 31, 32, 1
            };
        int[] ip_inverse = {
                40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25
            };

        public override string Decrypt(string cipherText, string key)
        {
            int[] CipherText_In_Binary = new int[64];
            From_Hexa_To_Binary(cipherText, CipherText_In_Binary);

            // key To Binary
            int[] Key_In_Binary = new int[64];
            From_Hexa_To_Binary(key, Key_In_Binary);

            //map the key to the first permutation
            int[] key_after_mapping = new int[56];
            int[] key_c = new int[28];
            int[] key_d = new int[28];
            Mapping_Key_With_Pc1_and_dividing_it_to_c_and_d(key_after_mapping, Key_In_Binary, key_c, key_d);

            // circular left shift in each round
            int[,] key_c_plus_d = new int[16, 56];
            Shitfing_left_for_the_16_round(key_c, key_d, key_c_plus_d);

            //mapping with pc2 in each round
            int[,] after_pc2 = new int[16, 48];
            Mapping_Key_With_pc2(after_pc2, key_c_plus_d);

            int[] before_IP_inverse = new int[64];
            for (int i = 0; i < 64; ++i)
            {
                before_IP_inverse[ip_inverse[i] - 1] = CipherText_In_Binary[i];
            }

            int[] before_32_bit_swapping = new int[64];
            _32_swapping_decrypt(before_IP_inverse, before_32_bit_swapping);


            int[] left_ip = new int[32];
            int[] right_ip = new int[32];
            int[] old_right = new int[32];
            int[] old_right_ip_after_e = new int[48];
            int[] old_right_ip_after_xor = new int[48];
            int[,] old_right_ip_after_xor_2d = new int[8, 6];
            int[] old_ints = new int[32];
            int[] old_new_right_ip = new int[32];
            int[] old_after_last_permutation = new int[32];

            for (int round = 15; round >= 0; --round)
            {
                for (int i = 0; i < 32; ++i)
                {
                    left_ip[i] = before_32_bit_swapping[i];
                    old_right[i] = before_32_bit_swapping[i];
                    right_ip[i] = before_32_bit_swapping[i + 32];
                }
                // E-table
                Exapnsion_Table(old_right_ip_after_e, old_right);

                // XOR with subkey
                XOR_Ints_and_Keys(old_right_ip_after_xor, old_right_ip_after_e, after_pc2, round);

                //convert the right ip from 1d to 2d array
                Convert_1D_to_2D(old_right_ip_after_xor_2d, old_right_ip_after_xor);

                // S-Boxes
                RETURN_OUTPUT_OF_S_BOX(old_right_ip_after_xor_2d, old_ints);

                // P-Permutation
                Mapping_The_Output_With_P(old_after_last_permutation, old_ints);

                // XOR to get the old left ip
                int[] old_left_ip = new int[32];
                for (int i = 0; i < 32; ++i)
                {
                    old_left_ip[i] = right_ip[i] ^ old_after_last_permutation[i];
                }

                for (int i = 0; i < 32; ++i)
                {
                    before_32_bit_swapping[i] = old_left_ip[i];
                    before_32_bit_swapping[i + 32] = left_ip[i];
                }

            }
            int[] before_ip = new int[64];
            for (int i = 0; i < 64; ++i)
            {
                before_ip[ip[i] - 1] = before_32_bit_swapping[i];
            }

            string plainText = "";
            From_Binary_To_Hexa(before_ip, ref plainText);

            return plainText;
        }

        public override string Encrypt(string plainText, string key)
        {
            //plainText To Binary
            int[] PlainText_In_Binary = new int[64];
            From_Hexa_To_Binary(plainText, PlainText_In_Binary);

            // key To Binary
            int[] Key_In_Binary = new int[64];
            From_Hexa_To_Binary(key, Key_In_Binary);

            // map the plain text to the first permutation
            int[] after_ip = new int[64];
            Mapping_The_PlainText_With_IP(after_ip, PlainText_In_Binary);

            //map the key to the first permutation
            int[] key_after_mapping = new int[56];
            int[] key_c = new int[28];
            int[] key_d = new int[28];
            Mapping_Key_With_Pc1_and_dividing_it_to_c_and_d(key_after_mapping, Key_In_Binary, key_c, key_d);

            // circular left shift in each round
            int[,] key_c_plus_d = new int[16, 56];
            Shitfing_left_for_the_16_round(key_c, key_d, key_c_plus_d);

            //mapping with pc2 in each round
            int[,] after_pc2 = new int[16, 48];
            Mapping_Key_With_pc2(after_pc2, key_c_plus_d);

            //all of the above is right
            int[] left_ip = new int[32];
            int[] right_ip = new int[32];
            int[] right_ip_after_e = new int[48];
            int[] right_ip_after_xor = new int[48];
            int[,] right_ip_after_xor_2d = new int[8, 6];
            int[] ints = new int[32];
            int[] new_right_ip = new int[32];
            int[] after_last_permutation = new int[32];
            // make permutaion on the result of the s-boxes
            for (int round = 0; round < 16; ++round)
            {
                // left and right 
                Split_The_Ip_Into_Left_and_Right(after_ip, left_ip, right_ip);

                // E-table
                Exapnsion_Table(right_ip_after_e, right_ip);

                // XOR with subkey
                XOR_Ints_and_Keys(right_ip_after_xor, right_ip_after_e, after_pc2, round);

                //convert the right ip from 1d to 2d array
                Convert_1D_to_2D(right_ip_after_xor_2d, right_ip_after_xor);

                // S-Boxes
                RETURN_OUTPUT_OF_S_BOX(right_ip_after_xor_2d, ints);

                // P-Permutation
                Mapping_The_Output_With_P(after_last_permutation, ints);

                // XOR to get the new right ip
                XOR_left_ip_and_after_last_permutation(new_right_ip, left_ip, after_last_permutation);

                // Swap halves
                Swap_the_halves(after_ip, right_ip, new_right_ip);
            }
            //swap the halves
            _32_bit_swap_encrypt(after_ip, right_ip, left_ip);

            //Mapping with Inverse ip
            int[] final_output = new int[64];
            Mapping_Output_With_Inverse_IP(final_output, after_ip);

            //Finally we got the cipher text
            string cipherText = "";
            From_Binary_To_Hexa(final_output, ref cipherText);

            return cipherText;
        }

        void From_Binary_To_Hexa(int[] Binary_arr, ref string Text)
        {
            Text = "0x";
            for (int i = 0; i < 64; i += 4)
            {
                int hexValue = (Binary_arr[i] << 3) | (Binary_arr[i + 1] << 2) |
                               (Binary_arr[i + 2] << 1) | Binary_arr[i + 3];
                Text += hexValue.ToString("X");
            }
        }
        void _32_bit_swap_encrypt(int[] after_ip, int[] right_ip, int[] left_ip)
        {
            for (int i = 0; i < 32; ++i)
            {
                left_ip[i] = after_ip[i];
                right_ip[i] = after_ip[i + 32];
            }
            for (int i = 0; i < 32; ++i)
            {
                after_ip[i] = right_ip[i];
                after_ip[i + 32] = left_ip[i];
            }
        }
        void Shitfing_left_for_the_16_round(int[] key_c, int[] key_d, int[,] key_c_plus_d)
        {
            for (int round = 0; round < 16; ++round)
            {
                //key_arr_c = 12345678
                //first_arr = 123
                //second_arr = 45678
                //key_arr_c_after_shifting = 45678 + 123
                LeftShift(key_c, left_shift[round]);
                LeftShift(key_d, left_shift[round]);

                for (int i = 0; i < 28; ++i)
                {
                    key_c_plus_d[round, i] = key_c[i];
                    key_c_plus_d[round, i + 28] = key_d[i];
                }
            }
        }

        void Swap_the_halves(int[] after_ip, int[] right_ip, int[] new_right_ip)
        {
            for (int i = 0; i < 32; i++)
            {
                after_ip[i] = right_ip[i];
                after_ip[i + 32] = new_right_ip[i];
            }
        }

        void Mapping_Output_With_Inverse_IP(int[] final_output, int[] after_ip)
        {
            // make the inverse permutation
            for (int i = 0; i < 64; ++i)
            {
                final_output[i] = after_ip[ip_inverse[i] - 1];
            }
        }

        void Mapping_Key_With_pc2(int[,] after_pc2, int[,] key_c_plus_d)
        {
            for (int round = 0; round < 16; ++round)
            {
                // map the key to the PC2
                for (int i = 0; i < 48; ++i)
                {
                    after_pc2[round, i] = key_c_plus_d[round, pc2[i] - 1];
                }
            }
        }

        void Mapping_Key_With_Pc1_and_dividing_it_to_c_and_d(int[] key_after_mapping, int[] Key_In_Binary, int[] key_c, int[] key_d)
        {
            for (int i = 0; i < 56; ++i)
            {
                key_after_mapping[i] = Key_In_Binary[pc1[i] - 1];
            }
            for (int i = 0; i < 28; ++i)
            {
                key_c[i] = key_after_mapping[i];
            }
            for (int i = 0; i < 28; ++i)
            {
                key_d[i] = key_after_mapping[i + 28];
            }
        }
        void Mapping_The_PlainText_With_IP(int[] after_ip, int[] PlainText_In_Binary)
        {
            for (int i = 0; i < 64; ++i)
            {
                after_ip[i] = PlainText_In_Binary[ip[i] - 1];
            }
        }

        void From_4bit_bin_to_dec(int[] four_bits_from_bin_to_dec, ref int dec_output)
        {
            dec_output = 0;
            for (int i = 0; i < 4; ++i)
                dec_output += four_bits_from_bin_to_dec[i] * (int)Math.Pow(2, 3 - i);
        }

        void From_Hexa_To_Binary(string s, int[] arr)
        {
            int index_for_arr = 0;
            s = s.Remove(0, 2);
            for (int i = 0; i < s.Length; ++i)
            {
                int hexValue = Convert.ToInt32(s[i].ToString(), 16);
                string binary = Convert.ToString(hexValue, 2).PadLeft(4, '0');

                foreach (char bit in binary)
                {
                    arr[index_for_arr++] = bit - '0';
                }
            }
        }
        void LeftShift(int[] arr, int shiftCount)
        {
            int length = arr.Length;
            int[] temp = new int[length];
            for (int i = 0; i < length; i++)
            {
                temp[i] = arr[(i + shiftCount) % length];
            }
            Array.Copy(temp, arr, length);
        }

        void Exapnsion_Table(int[] right_ip_after_e, int[] right_ip)
        {
            for (int i = 0; i < 48; ++i)
            {
                right_ip_after_e[i] = right_ip[e[i] - 1];
            }
        }

        void Split_The_Ip_Into_Left_and_Right(int[] after_ip, int[] left_ip, int[] right_ip)
        {
            for (int i = 0; i < 32; ++i)
            {
                left_ip[i] = after_ip[i];
                right_ip[i] = after_ip[i + 32];
            }
        }

        void Convert_1D_to_2D(int[,] right_ip_after_xor_2d, int[] right_ip_after_xor)
        {
            for (int i = 0; i < 8; ++i)
            {
                for (int j = 0; j < 6; ++j)
                {
                    right_ip_after_xor_2d[i, j] = right_ip_after_xor[i * 6 + j];
                }
            }
        }

        void XOR_Ints_and_Keys(int[] right_ip_after_xor, int[] right_ip_after_e, int[,] after_pc2, int round)
        {
            for (int i = 0; i < 48; ++i)
            {
                right_ip_after_xor[i] = right_ip_after_e[i] ^ after_pc2[round, i];
            }
        }

        void XOR_left_ip_and_after_last_permutation(int[] new_right_ip, int[] left_ip, int[] after_last_permutation)
        {
            for (int i = 0; i < 32; i++)
            {
                new_right_ip[i] = left_ip[i] ^ after_last_permutation[i];
            }
        }

        void From_dec_to_4_bin(int[] _4_bit_binary_col, int col_of_the_sBox)
        {
            int index = 3;
            while (col_of_the_sBox > 0)
            {
                _4_bit_binary_col[index--] = col_of_the_sBox % 2;
                col_of_the_sBox /= 2;
            }
        }

        void From_dec_to_2_bin(int[] _2_bit_binary_row, int row_of_the_sBox)
        {
            int index = 1;
            while (row_of_the_sBox > 0)
            {
                _2_bit_binary_row[index--] = row_of_the_sBox % 2;
                row_of_the_sBox /= 2;
            }
        }

        void Mapping_The_Output_With_P(int[] after_last_permutation, int[] ints)
        {
            for (int i = 0; i < 32; ++i)
            {
                after_last_permutation[i] = ints[p[i] - 1];
            }
        }

        void RETURN_OUTPUT_OF_S_BOX(int[,] right_ip_after_xor_2d, int[] ints)
        {
            for (int i = 0; i < 8; i++)
            {
                int first_bit = right_ip_after_xor_2d[i, 0];
                int last_bit = right_ip_after_xor_2d[i, 5];
                int row = 0;
                if (first_bit == 0 && last_bit == 0)
                {
                    row = 0;
                }
                else if (first_bit == 0 && last_bit == 1)
                {
                    row = 1;
                }
                else if (first_bit == 1 && last_bit == 0)
                {
                    row = 2;
                }
                else
                {
                    row = 3;
                }
                int second_bit = right_ip_after_xor_2d[i, 1];
                int third_bit = right_ip_after_xor_2d[i, 2];
                int fourth_bit = right_ip_after_xor_2d[i, 3];
                int fifth_bit = right_ip_after_xor_2d[i, 4];
                int column = 0;
                if (second_bit == 0 && third_bit == 0 && fourth_bit == 0 && fifth_bit == 0)
                {
                    column = 0;
                }
                if (second_bit == 0 && third_bit == 0 && fourth_bit == 0 && fifth_bit == 1)
                {
                    column = 1;
                }
                if (second_bit == 0 && third_bit == 0 && fourth_bit == 1 && fifth_bit == 0)
                {
                    column = 2;
                }
                if (second_bit == 0 && third_bit == 0 && fourth_bit == 1 && fifth_bit == 1)
                {
                    column = 3;
                }
                if (second_bit == 0 && third_bit == 1 && fourth_bit == 0 && fifth_bit == 0)
                {
                    column = 4;
                }
                if (second_bit == 0 && third_bit == 1 && fourth_bit == 0 && fifth_bit == 1)
                {
                    column = 5;
                }
                if (second_bit == 0 && third_bit == 1 && fourth_bit == 1 && fifth_bit == 0)
                {
                    column = 6;
                }
                if (second_bit == 0 && third_bit == 1 && fourth_bit == 1 && fifth_bit == 1)
                {
                    column = 7;
                }
                if (second_bit == 1 && third_bit == 0 && fourth_bit == 0 && fifth_bit == 0)
                {
                    column = 8;
                }
                if (second_bit == 1 && third_bit == 0 && fourth_bit == 0 && fifth_bit == 1)
                {
                    column = 9;
                }
                if (second_bit == 1 && third_bit == 0 && fourth_bit == 1 && fifth_bit == 0)
                {
                    column = 10;
                }
                if (second_bit == 1 && third_bit == 0 && fourth_bit == 1 && fifth_bit == 1)
                {
                    column = 11;
                }
                if (second_bit == 1 && third_bit == 1 && fourth_bit == 0 && fifth_bit == 0)
                {
                    column = 12;
                }
                if (second_bit == 1 && third_bit == 1 && fourth_bit == 0 && fifth_bit == 1)
                {
                    column = 13;
                }
                if (second_bit == 1 && third_bit == 1 && fourth_bit == 1 && fifth_bit == 0)
                {
                    column = 14;
                }
                if (second_bit == 1 && third_bit == 1 && fourth_bit == 1 && fifth_bit == 1)
                {
                    column = 15;
                }
                int elmakan = sBoxes[i, row, column];
                int[] convert = new int[4];
                int index = 3;
                while (elmakan > 0)
                {
                    convert[index--] = elmakan % 2;
                    elmakan /= 2;
                }
                for (int j = 0; j < 4; ++j)
                {
                    ints[i * 4 + j] = convert[j];
                }
            }
        }
        void _32_swapping_decrypt(int[] before_IP_inverse, int[] before_32_bit_swapping)
        {

            for (int i = 0; i < 32; ++i)
            {
                before_32_bit_swapping[i + 32] = before_IP_inverse[i];
                before_32_bit_swapping[i] = before_IP_inverse[i + 32];
            }

        }

    }
}