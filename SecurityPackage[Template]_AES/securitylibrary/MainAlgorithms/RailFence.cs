using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            string new_cipherText = cipherText.ToLower();
            int start = 2;
            float x = (float)plainText.Length / 2;
            int end = (x % 1 > 0) ? (((int)x) + 1) : ((int)x);

            for (int key = start; key < end; key++)
            {
                string new_ct = Encrypt(plainText, key);

                if (new_ct.Equals(new_cipherText))
                {
                    return key;
                }
            }
            return -1;
        }

        public string Decrypt(string cipherText, int key)
        {
            string new_cipherText = cipherText.ToLower();
            string PlainText = "";
            int num_of_rows = key;
            float x = (float)new_cipherText.Length / key;
            int num_of_cols = (x % 1 > 0) ? ((new_cipherText.Length / key) + 1) : (new_cipherText.Length / key);
            int zero = 0;
            int empty = (num_of_rows * num_of_cols) - new_cipherText.Length;
            char[,] CT = new char[num_of_rows, num_of_cols];

            for (int row = 0; row < num_of_rows; row++)
            {
                for (int col = 0; col < num_of_cols; col++)
                {
                    if (col + 1 == num_of_cols && empty == num_of_rows - row)
                        continue;

                    if (zero < new_cipherText.Length)
                    {
                        CT[row, col] = new_cipherText[zero];
                        zero++;
                    }

                    else
                        break;
                }
            }

            for (int col = 0; col < num_of_cols; col++)
            {
                for (int row = 0; row < num_of_rows; row++)
                {
                    if (CT[row, col] != '\0')
                        PlainText += CT[row, col];
                }
            }
            return PlainText;
        }

        public string Encrypt(string plainText, int key)
        {
            string new_plainText = plainText.ToLower();
            string CipherText = "";
            int num_of_rows = key;
            float x = (float)new_plainText.Length / key;
            int num_of_cols = (x % 1 > 0) ? ((new_plainText.Length / key) + 1) : (new_plainText.Length / key); // column wise
            char[,] new_PT = new char[num_of_rows, num_of_cols];
            int zero = 0;

            for (int col = 0; col < num_of_cols; col++)
            {
                for (int row = 0; row < num_of_rows; row++)
                {
                    if (zero < new_plainText.Length)
                    {
                        new_PT[row, col] = new_plainText[zero];
                        zero++;
                    }

                    else
                        break;
                }
            }

            for (int row = 0; row < num_of_rows; row++)
            {
                for (int col = 0; col < num_of_cols; col++)
                {
                    if (new_PT[row, col] != '\0')
                    {
                        CipherText += new_PT[row, col];
                    }
                }
            }

            return CipherText;
        }
    }
}
