using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            cipherText = handleText(cipherText);
            return Decryption(cipherText, key); ;
        }
        public string Decryption(string input, string key)
        {

            StringBuilder result = new StringBuilder(input.ToUpper());
            for (int i = 0; i < input.Length; i += 2)
            {
                int row1 = 0, row2=0,col1=0,col2=0;
                char[,] matrix = getKkeyMatrix(key);
                getIndex(matrix, input[i], ref row1, ref col1);
                getIndex(matrix, input[i + 1], ref row2, ref col2);              
                if (col1 == col2)
                {
                    result[i] = matrix[(row1 + 4) % 5, col1];
                    result[i + 1] = matrix[(row2 + 4) % 5, col2];
                }
                else if (row1 == row2)
                {
                    result[i] = matrix[row1, (col1 + 4) % 5];
                    result[i + 1] = matrix[row2, (col2 + 4) % 5];
                }
                else
                {
                    result[i] = matrix[row1, col2];
                    result[i + 1] = matrix[row2, col1]; ;
                }

            }


            string str = result.ToString();
            string val = str.Substring(0, 1);
            for (int i = 1; i < str.Length - 1; i++)
            {
                if (!(str[i] == 'X' && str[i - 1] == str[i + 1] && i % 2 != 0))
                {
                    val += str.Substring(i, 1);
                }
            }
            if (str[str.Length - 1] != 'X')
                val += str.Substring(str.Length - 1, 1);
            str = val.ToLower();

            return str;


        }
        public string Encrypt(string plainText, string key)
        {

            string plaintxt = handleText(plainText);
            
            return Encryption(plaintxt, key); 

        }
        public string handleText(string plainText)
        {                           

            for (int i = 0;i < plainText.Length; i+=2)
            {
                if (i+1<plainText.Length&& plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Insert(i + 1, "x");
                }
                
            }
            
            if (plainText.Length % 2 != 0)
                plainText += 'x';
            plainText = plainText.ToUpper();
            return plainText;
        }

        public char[,] getKkeyMatrix(string key)
        {
            bool[] check = new bool[26];
            StringBuilder x = new StringBuilder("0000000000000000000000000");

            char[,] matrix = new char[25, 25];
            int index = 0;
            for (int i = 0; i < key.Length; i++)
            {
                if (check[key[i] - 97] == false)
                {

                    x[index] = key[i];
                    check[key[i] - 97] = true;
                    index++;

                }
            }
            char c = 'a';
            for (int i = 0; i < 25; i++)
            {
                if (x[i] == '0')
                {
                    while (check[c - 97] == true)
                    {
                        c++;
                        if (c == 'i' && check['j' - 97] == true) c++;
                        if (c == 'j' && check['i' - 97] == true) c++;

                    }
                    x[i] = c;
                    check[c - 97] = true;
                }
            }
            index = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int z = 0; z < 5; z++)
                {
                    matrix[i, z] = char.ToUpper(x[index]);
                    index++;
                }
            }
            return matrix;
        }

        public void getIndex(char[,] matrix, char ch, ref int row, ref int col)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (matrix[i, j] == ch)
                    {
                        row = i;
                        col = j;
                        break;
                    }
                }
            }

        }

        public string Encryption(string input, string key)
        {

            StringBuilder result = new StringBuilder(input.ToUpper());
            for (int i = 0; i < input.Length; i += 2)
            {
                int row1 = 0,row2=0,col1=0,col2=0;
                char[,] matrix = getKkeyMatrix(key);
                getIndex(matrix, input[i], ref row1, ref col1);
                getIndex(matrix, input[i + 1], ref row2, ref col2);
                if (col1 == col2)
                {
                    result[i] = matrix[(row1 + 1) % 5, col1];
                    result[i + 1] = matrix[(row2 + 1) % 5, col2];
                }
                else if (row1 == row2)
                {
                    result[i] = matrix[row1, (col1 + 1) % 5];
                    result[i + 1] = matrix[row2, (col2 + 1) % 5];
                }               
                else
                {
                    result[i] = matrix[row1, col2];
                    result[i + 1] = matrix[row2, col1]; ;
                }

            }
            return result.ToString(); 
        }
    }
}