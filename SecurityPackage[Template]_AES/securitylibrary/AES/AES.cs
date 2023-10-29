using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>

    public class AES : CryptographicTechnique
    {
        private string invrs_box = "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd12572f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d8490d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af41fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cefa0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d";
        private string Sbox = "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16";
        private string[,] Sbox_2d = new string[16, 16];
        string[,] pl;
        string[,] key;
        int[,] mul_tbl = new int[,] { { 2, 3, 1, 1 }, { 1, 2, 3, 1 }, { 1, 1, 2, 3 }, { 3, 1, 1, 2 } };
        int[,] mul_tbl2 = new int[,] { { 14, 11, 13, 9 }, { 9, 14, 11, 13 }, { 13, 9, 14, 11 }, { 11, 13, 9, 14 } };
        string[] bin = { "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111", };
        char[] digt = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
        string[] rcon = { "00", "01", "02", "04", "08", "10", "20", "40", "80", "1b", "36" };
        bool done = false;
        string[,,] keys;

        public override string Encrypt(string plainText, string key)
        {
            if (done == false)
            {
                cnvrt_Str_to_2darr(Sbox, 16, Sbox_2d);
                done = true;
            }

            string cipherText = "0x";
            plainText = plainText.ToLower();
            key = key.ToLower();

            pl = new string[4, 4];
            this.key = new string[4, 4];
            cnvrt_Str_to_2darr2(plainText.Remove(0, 2), 4, pl);
            cnvrt_Str_to_2darr2(key.Remove(0, 2), 4, this.key);

            for (int i = 0; i <= 10; i++)
            {
                if (i == 0)
                { plin_mul_key(); }

                else if (i > 0 && i < 10)
                {
                    cnvrt_to_Subbyt(pl);
                    shft_colum(pl);
                    pl = Mix_Coloum();
                    this.key = gen_new_key(i);
                    plin_mul_key();
                }
                else if (i == 10)
                {
                    cnvrt_to_Subbyt(pl);
                    shft_colum(pl);
                    this.key = gen_new_key(i);
                    plin_mul_key();
                }
            }

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    cipherText += pl[j, i];
                }
            }

            return cipherText;
        }
        public override string Decrypt(string cipherText, string key)
        {
            string plinText = "0x";
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            pl = new string[4, 4];
            this.key = new string[4, 4];
            cnvrt_Str_to_2darr2(cipherText.Remove(0, 2), 4, pl);
            cnvrt_Str_to_2darr2(key.Remove(0, 2), 4, this.key);
            cnvrt_Str_to_2darr(Sbox, 16, Sbox_2d);
            keys = new string[11, 4, 4];
            keys = AllKeys();
            cnvrt_Str_to_2darr(invrs_box, 16, Sbox_2d);

            for (int i = 0; i <= 10; i++)
            {
                if (i == 0)
                {
                    gen_new_key2(10 - i);
                    plin_mul_key();
                }
                else if (i > 0 && i < 10)
                {
                    shft_colum2(pl);
                    cnvrt_to_Subbyt(pl);
                    gen_new_key2(10 - i);
                    plin_mul_key();
                    pl = Mix_Coloum2();
                }
                else if (i == 10)
                {
                    shft_colum2(pl);
                    cnvrt_to_Subbyt(pl);
                    gen_new_key2(10 - i);
                    plin_mul_key();
                }
            }
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    plinText += pl[j, i];
            return plinText;
        }

        private void cnvrt_Str_to_2darr(string text, int end, string[,] arr)
        {
            int count = 0;
            for (int i = 0; i < end; i++)
            {
                for (int j = 0; j < end; j++)
                {
                    arr[i, j] = text.Substring(count, 2);
                    count += 2;
                }
            }
        }
        private void cnvrt_Str_to_2darr2(string text, int end, string[,] arr)
        {
            int count = 0;
            for (int i = 0; i < end; i++)
            {
                for (int j = 0; j < end; j++)
                {
                    arr[j, i] = text.Substring(count, 2);
                    count += 2;
                }
            }
        }
        private int get_Indx(char c)
        {

            if (c >= '0' && c <= '9')
                return c - 48;
            return c - 87;
        }
        private void cnvrt_to_Subbyt(string[,] arr)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    arr[i, j] = Sbox_2d[get_Indx(arr[i, j][0]), get_Indx(arr[i, j][1])];
                }
            }
        }
        private string get_bin(string s)
        {
            string answer = "";
            answer += bin[get_Indx(s[0])] + bin[get_Indx(s[1])];
            return answer;
        }
        private string xor(string x, string y)
        {
            string answer = "";
            for (int i = 0; i < 8; i++)
                if (x[i] != y[i])
                    answer += '1';
                else
                    answer += '0';
            return answer;
        }
        private string clear(string tmp)
        {
            string new_tmp = tmp;
            if (new_tmp[0] == '0')
            {
                new_tmp = new_tmp.Remove(0, 1);
                new_tmp += '0';
            }
            else
            {
                new_tmp = new_tmp.Remove(0, 1);
                new_tmp += '0';
                new_tmp = xor(new_tmp, "00011011");
            }
            return new_tmp;
        }
        private string get_hexa(string x)
        {
            string answer = "";
            string tmp1 = x.Substring(0, 4);
            string tmp2 = x.Substring(4, 4);
            for (int i = 0; i < 16; i++)
            {
                if (tmp1 == bin[i])
                {
                    answer += digt[i];
                }
            }
            for (int i = 0; i < 16; i++)
            {
                if (tmp2 == bin[i])
                {
                    answer += digt[i];
                }
            }
            return answer;
        }
        private string Mix(int i, int j)
        {
            string answer;
            string tmp;
            string[] data = new string[4];

            for (int k = 0; k < 4; k++)
            {
                tmp = get_bin(pl[k, j]);
                if (mul_tbl[i, k] == 1)
                    data[k] = tmp;
                else if (mul_tbl[i, k] == 2)
                    data[k] = clear(tmp);
                else
                    data[k] = xor(clear(tmp), tmp);
            }
            answer = xor(xor(xor(data[0], data[1]), data[2]), data[3]);

            answer = get_hexa(answer);
            return answer;
        }
        private string Mix2(int i, int j)
        {
            string answer = "";
            string tmp;
            string tmp2;
            string[] data = new string[4];

            for (int k = 0; k < 4; k++)
            {
                tmp = "";
                tmp += get_bin(pl[k, j]);
                tmp2 = tmp;
                if (mul_tbl2[i, k] == 9)
                {
                    tmp = clear(tmp);
                    tmp = clear(tmp);
                    tmp = clear(tmp);
                    data[k] = xor(tmp, tmp2);
                }
                else if (mul_tbl2[i, k] == 11)
                {
                    tmp = clear(tmp);
                    tmp = clear(tmp);
                    tmp = xor(tmp, tmp2);
                    tmp = clear(tmp);
                    data[k] = xor(tmp, tmp2);
                }
                else if (mul_tbl2[i, k] == 13)
                {
                    tmp = clear(tmp);
                    tmp = xor(tmp, tmp2);
                    tmp = clear(tmp);
                    tmp = clear(tmp);
                    data[k] = xor(tmp, tmp2);
                }
                else if (mul_tbl2[i, k] == 14)
                {
                    tmp = clear(tmp);
                    tmp = xor(tmp, tmp2);
                    tmp = clear(tmp);
                    tmp = xor(tmp, tmp2);
                    data[k] = clear(tmp);
                }
            }
            answer = xor(xor(xor(data[0], data[1]), data[2]), data[3]);
            answer = get_hexa(answer);
            return answer;
        }
        private void plin_mul_key()
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    pl[i, j] = get_hexa(xor(get_bin(pl[i, j]), get_bin(key[i, j])));
                }
            }
        }
        private string[,] gen_new_key(int round)
        {
            string[,] tmp_key = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                tmp_key[i, 0] = Sbox_2d[get_Indx(key[(i + 1) % 4, 3][0]), get_Indx(key[(i + 1) % 4, 3][1])];
            }

            for (int i = 0; i < 4; i++)
            {
                tmp_key[i, 0] = get_hexa(xor(get_bin(tmp_key[i, 0]), get_bin(key[i, 0])));
                if (i == 0)
                    tmp_key[i, 0] = get_hexa(xor(get_bin(tmp_key[i, 0]), get_bin(rcon[round])));
            }

            for (int j = 1; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    tmp_key[i, j] = get_hexa(xor(get_bin(key[i, j]), get_bin(tmp_key[i, j - 1])));
                }
            }

            return tmp_key;
        }
        private string[,,] AllKeys()
        {
            string[,,] keys = new string[11, 4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    keys[0, i, j] = key[i, j];
                }
            }
            for (int k = 1; k <= 10; k++)
            {
                key = gen_new_key(k);
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        keys[k, i, j] = key[i, j];
                    }
                }
            }
            return keys;
        }
        private void shft_colum(string[,] arr)
        {
            string tmp;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < i; j++)
                {
                    for (int k = 0; k < 3; k++)
                    {
                        tmp = arr[i, k];
                        arr[i, k] = arr[i, k + 1];
                        arr[i, k + 1] = tmp;
                    }
                }
            }
        }
        private void shft_colum2(string[,] arr)
        {
            string tmp;
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4 - i; j++)
                {
                    for (int k = 0; k < 3; k++)
                    {
                        tmp = arr[i, k];
                        arr[i, k] = arr[i, k + 1];
                        arr[i, k + 1] = tmp;
                    }
                }
            }
        }






        private string[,] Mix_Coloum()
        {
            string[,] mixed = new string[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    mixed[i, j] = Mix(i, j);
            return mixed;
        }
        private string[,] Mix_Coloum2()
        {
            string[,] mixed = new string[4, 4];
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    mixed[i, j] = Mix2(i, j);
            return mixed;
        }



        private void gen_new_key2(int round)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    key[i, j] = keys[round, i, j];
                }
            }
        }


    }
}