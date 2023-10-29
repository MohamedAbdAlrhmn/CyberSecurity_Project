using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        static char Repl = 'x';
        static int set_max = 10;

        public List<int> Analyse(string plainText, string cipherText)
        {
            string new_cipherText = cipherText.ToLower();
            string new_plainText = plainText.ToLower();
            int min_col = 2;
            int max_col = (new_plainText.Length / min_col);
            int new_max_col = (max_col > 10) ? (set_max) : (max_col);

            for (int i = min_col; i < new_max_col; i++)
            {
                int[] key = new int[i];
                for (int j = 0; j < i; j++)
                {
                    key[j] = j + 1;
                }
                List<List<int>> possible_key;
                possible_key = Perm(key);

                if (possible_key != null)
                {
                    foreach (List<int> key0 in possible_key)
                    {
                        string C_T = Encrypt(new_plainText, key0);
                        if (new_cipherText.Equals(C_T)) return key0;
                    }
                }


            }
            throw new KeyNotFoundException();

        }

        public string Decrypt(string cipherText, List<int> key)
        {
            string new_cipherText = cipherText.ToLower();
            string PlainText = "";
            int num_of_col = key.Count;
            float temp = (float)new_cipherText.Length / num_of_col;
            int num_of_row = (temp % 1 > 0) ? ((int)temp + 1) : ((int)temp);
            int num_of_letter = 0;
            char[,] CT_matrix = new char[num_of_row, num_of_col];
            int num_of_empty_cell = (num_of_row * num_of_col) - new_cipherText.Length;

            for (int i = 0; i < num_of_col; i++)
            {
                for (int j = 0; j < num_of_row; j++)
                {
                    if (j + 1 == num_of_row && num_of_empty_cell > num_of_col - key.IndexOf(i + 1))
                    {
                        continue;
                    }

                    if (num_of_letter < new_cipherText.Length)
                    {
                        CT_matrix[j, key.IndexOf(i + 1)] = new_cipherText[num_of_letter];
                        num_of_letter++;
                    }
                    else
                        break;
                }
            }

            for (int i = 0; i < num_of_row; i++)
            {
                for (int j = 0; j < num_of_col; j++)
                {
                    if (CT_matrix[i, j] != '\0')
                        PlainText += CT_matrix[i, j];
                }
            }
            return PlainText;
        }
        public string Encrypt(string plainText, List<int> key)
        {
            plainText = plainText.ToLower();
            string CipherText = "";
            int num_of_col = key.Count;
            float x = (float)plainText.Length / num_of_col;
            int num_of_row = (x % 1 > 0) ? ((int)x + 1) : ((int)x);
            int num_of_letter = 0;
            char[,] PT = new char[num_of_row, num_of_col];

            for (int row = 0; row < num_of_row; row++)
            {
                for (int col = 0; col < num_of_col; col++)
                {
                    if (num_of_letter < plainText.Length)
                    {
                        PT[row, col] = plainText[num_of_letter];
                        num_of_letter++;
                    }

                }
            }

            for (int col = 0; col < num_of_col; col++)
            {
                for (int row = 0; row < num_of_row; row++)
                {
                    if (PT[row, key.IndexOf(col + 1)] != '\0')
                    {
                        CipherText += PT[row, key.IndexOf(col + 1)];
                    }
                }
            }

            return CipherText;
        }
        static void Swap(ref int x, ref int y)
        {
            var temp = x;
            x = y;
            y = temp;
        }
        static List<List<int>> Get_Perm(int[] nums, int start, int end, List<List<int>> L)
        {
            if (start == end)
            {

                L.Add(new List<int>(nums));
            }
            else
            {
                for (var i = start; i <= end; i++)
                {
                    Swap(ref nums[start], ref nums[i]);
                    Get_Perm(nums, start + 1, end, L);
                    Swap(ref nums[start], ref nums[i]);
                }
            }
            return L;
        }
        static List<List<int>> Perm(int[] nums)
        {
            List<List<int>> L = new List<List<int>>();
            return Get_Perm(nums, 0, nums.Length - 1, L);
        }
    }
}
