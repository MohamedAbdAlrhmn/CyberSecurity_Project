using System;
using System.Collections.Generic;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        private int[] Ip_1_arr;
        private int[] Ip_2_arr;
        private int[] Ip_arr_of_txt;
        private int[] Exp_tbl;
        private int[] Sbox_prm;
        private int[] Inv_prm;
        private Dictionary<char, string> map = new Dictionary<char, string>();
        int[] Key_shfttbl;
        private int[,,] Sbox_arr;

        public DES()
        {
            map.Add('0', "0000");
            map.Add('1', "0001");
            map.Add('2', "0010");
            map.Add('3', "0011");
            map.Add('4', "0100");
            map.Add('5', "0101");
            map.Add('6', "0110");
            map.Add('7', "0111");
            map.Add('8', "1000");
            map.Add('9', "1001");
            map.Add('A', "1010");
            map.Add('B', "1011");
            map.Add('C', "1100");
            map.Add('D', "1101");
            map.Add('E', "1110");
            map.Add('F', "1111");

            Ip_1_arr = new int[]
            {
                57,49,41,33,25,17,9,
                1,58,50,42,34,26,18,
                10,2,59,51,43,35,27,
                19,11,3,60,52,44,36,
                63,55,47,39,31,23,15,
                7,62,54,46,38,30,22,
                14,6,61,53,45,37,29,
                21,13,5,28,20,12,4
            };

            Ip_2_arr = new int[]
            {
                14,17,11,24,1,5,
                3,28,15,6,21,10,
                23,19,12,4,26,8,
                16,7,27,20,13,2,
                41,52,31,37,47,55,
                30,40,51,45,33,48,
                44,49,39,56,34,53,
                46,42,50,36,29,32
            };

            Key_shfttbl = new int[]
            {
                1, 1, 2, 2,
                2, 2, 2, 2,
                1, 2, 2, 2,
                2, 2, 2, 1
            };

            Ip_arr_of_txt = new int[]
            {
                58,50,42,34,26,18,10,2,
                60,52,44,36,28,20,12,4,
                62,54,46,38,30,22,14,6,
                64,56,48,40,32,24,16,8,
                57,49,41,33,25,17,9,1,
                59,51,43,35,27,19,11,3,
                61,53,45,37,29,21,13,5,
                63,55,47,39,31,23,15,7
            };

            Exp_tbl = new int[]
            {
                32,1,2,3,4,5,4,5,
                6,7,8,9,8,9,10,11,
                12,13,12,13,14,15,16,17,
                16,17,18,19,20,21,20,21,
                22,23,24,25,24,25,26,27,
                28,29,28,29,30,31,32,1
            };

            Sbox_prm = new int[]
            {
                16,7,20,21,29,12,28,17,
                1,15,23,26,5,18,31,10,
                2,8,24,14,32,27,3,9,
                19,13,30,6,22,11,4,25
            };

            Inv_prm = new int[]
            {
                40,8,48,16,56,24,64,32,
                39,7,47,15,55,23,63,31,
                38,6,46,14,54,22,62,30,
                37,5,45,13,53,21,61,29,
                36,4,44,12,52,20,60,28,
                35,3,43,11,51,19,59,27,
                34,2,42,10,50,18,58,26,
                33,1,41,9,49,17,57,25
            };

            Sbox_arr = new int[,,]
            {
                    {
                        { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
                        { 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
                        { 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
                        { 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }
                    },
                    {
                        { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
                        { 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
                        { 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
                        { 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
                    },
                    {
                        { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
                        { 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
                        { 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
                        { 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
                    },
                    {
                        { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
                        { 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
                        { 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
                        { 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
                    },
                    {
                        { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
                        { 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
                        { 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
                        { 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
                    },
                    {
                        { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
                        { 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
                        { 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
                        { 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
                    },
                    {
                        { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                        { 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                        { 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                        { 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
                    },
                    {
                        { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
                        { 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
                        { 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
                        { 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
                    }
            };
        }

        public override string Decrypt(string cipherText, string key)
        {
            key = key.Remove(0, 2);
            key = Conv_hxa_to_bin(key);
            key = Aply_intil_prm(key, Ip_1_arr);

            string l_key = key.Substring(0, 28);
            string r_key = key.Substring(28, 28);

            List<string> List_of_keys = PerformLeftShift(l_key, r_key);

            List_of_keys.Reverse();

            string ciphertext = cipherText.Remove(0, 2);

            ciphertext = Conv_hxa_to_bin(ciphertext);
            ciphertext = Aply_intil_prm(ciphertext, Ip_arr_of_txt);

            string l_plaintext = ciphertext.Substring(0, 32);
            string r_plaintext = ciphertext.Substring(32, 32);

            string res = Gen_ciphertext(l_plaintext, r_plaintext, List_of_keys);

            return res;
        }

        public override string Encrypt(string plainText, string key)
        {
            key = key.Remove(0, 2);
            key = Conv_hxa_to_bin(key);
            key = Aply_intil_prm(key, Ip_1_arr);

            string l_key = key.Substring(0, 28);
            string r_key = key.Substring(28, 28);

            List<string> List_of_keys = PerformLeftShift(l_key, r_key);

            string plaintext = plainText.Remove(0, 2);
            plaintext = Conv_hxa_to_bin(plaintext);
            plaintext = Aply_intil_prm(plaintext, Ip_arr_of_txt);

            string l_plain = plaintext.Substring(0, 32);
            string r_plain = plaintext.Substring(32, 32);

            string res = Gen_ciphertext(l_plain, r_plain, List_of_keys);

            return res;
        }
        private string Conv_hxa_to_bin(string hexa)
        {
            string bin = "";

            foreach (char c in hexa)
            {
                bin += map[c];
            }

            return bin;
        }
        public string Aply_intil_prm(string key, int[] ip_table)
        {
            string New_key = "";

            foreach (int pos in ip_table)
            {
                New_key += key[pos - 1];
            }

            return New_key;
        }
        private string Aply_exp_table(string shortStr)
        {
            return Aply_intil_prm(shortStr, Exp_tbl);
        }
        private string xor(string one, string two)
        {
            string res = "";

            for (int i = 0; i < one.Length; i++)
            {
                if (one[i] == two[i])
                    res += "0";
                else res += "1";
            }

            return res;
        }
        private string Aply_Sbox(string plain)
        {
            string New_plaintext = "";

            for (int i = 0, j = 0; i < plain.Length; i += 6, j++)
            {
                string subKey = plain.Substring(i, 6);
                string row_dig = subKey[0] + "" + subKey[subKey.Length - 1];
                string col_dig = subKey.Substring(1, 4);
                int row = Convert.ToInt32(row_dig, 2);
                int col = Convert.ToInt32(col_dig, 2);
                int value = Sbox_arr[j, row, col];
                string bin = Convert.ToString(value, 2);

                while (bin.Length < 4)
                {
                    bin = "0" + bin;
                }

                New_plaintext += bin;
            }

            return New_plaintext;
        }
        private string Gen_ciphertext(string l_plaintext, string r_plaintext, List<string> keys)
        {
            for (int i = 0; i < 16; i++)
            {
                string expand = Aply_exp_table(r_plaintext);
                string New_r = xor(expand, keys[i]);

                New_r = Aply_Sbox(New_r);
                New_r = Aply_intil_prm(New_r, Sbox_prm);
                New_r = xor(New_r, l_plaintext);
                l_plaintext = r_plaintext;
                r_plaintext = New_r;

            }

            string final = r_plaintext + l_plaintext;

            final = Aply_intil_prm(final, Inv_prm);

            string Hex_string = "";

            for (int i = 0; i < final.Length; i += 4)
            {
                Hex_string += Convert.ToInt64(final.Substring(i, 4), 2).ToString("X");
            }
            string res = "0x" + Hex_string;
            return res;
        }
        private List<string> PerformLeftShift(string l_key, string r_key)
        {
            List<string> List_of_keys = new List<string>();

            for (int i = 0; i < 16; i++)
            {
                string shft = l_key.Substring(0, Key_shfttbl[i]);

                string rem = l_key.Remove(0, Key_shfttbl[i]);

                l_key = rem + shft;

                shft = r_key.Substring(0, Key_shfttbl[i]);

                rem = r_key.Remove(0, Key_shfttbl[i]);

                r_key = rem + shft;

                string New_key = l_key + r_key;

                New_key = Aply_intil_prm(New_key, Ip_2_arr);

                List_of_keys.Add(New_key);
            }

            return List_of_keys;
        }

    }
}
