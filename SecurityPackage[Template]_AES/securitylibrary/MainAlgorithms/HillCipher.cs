using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //throw new NotImplementedException();
            List<int>key = new List<int>();
            int cntr = 2;
            for (int indx = 0; indx < 2; indx++)
            {
                for (int i = 0; i < 26; i++)
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (((i * plainText[0]) + (j * plainText[1])) % 26 == cipherText[indx] &&
                            ((i * plainText[2]) + (j * plainText[3])) % 26 == cipherText[indx + 2])
                        {
                            key.Add(i);
                            key.Add(j);
                            break;
                        }
                    }
                    if (key.Count == cntr)
                        break;
                }
                cntr += 2;
            }
            if (key.Count < 4)
                throw new InvalidAnlysisException();
            return key;
        }

        public string Analyse(string plainText, string cipherText)
        {
           throw new NotImplementedException();
        }
        private int Determinant(List<List<int>> keymattrix, int m)
        {
            int determinant = 0;

            if (m == 2)
            {
                determinant = keymattrix[0][0] * keymattrix[1][1] - keymattrix[1][0] * keymattrix[0][1];
                return determinant;
            }
            else
            {
                for (int i = 0; i < 3; i++)
                    determinant += (keymattrix[0][i] * (keymattrix[1][(i + 1) % 3] * keymattrix[2][(i + 2) % 3] - keymattrix[1][(i + 2) % 3] * keymattrix[2][(i + 1) % 3]));
            }
            return determinant;
        }
        private List<List<int>> EnarMatrix(List<List<int>> mat, int m)
        {
            List<List<int>> result = new List<List<int>>();
            for (int i = 0; i < m; i++)
            {
                List<int> res = new List<int>();
                for (int j = 0; j < m; j++)
                {
                    List<List<int>> tmp1 = new List<List<int>>();
                    for (int k = 0; k < m; k++)
                    {
                        List<int> tmp2 = new List<int>();
                        for (int l = 0; l < m; l++)
                        {
                            if (k != i && l != j)
                            {
                                tmp2.Add(mat[k][l]);
                            }
                        }
                        if (tmp2.Count != 0)
                        {
                            tmp1.Add(tmp2);
                        }

                    }
                    int min = Determinant(tmp1, m - 1);
                    res.Add(min);
                }
                result.Add(res);
            }

            return result;
        }
        private List<List<int>> putfactor(List<List<int>> matrix, int m)
        {
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    if ((i + j) % 2 != 0)
                    {
                        matrix[i][j] *= -1;
                    }
                }
            }
            return matrix;
        }

        private List<List<int>> Inverse(List<List<int>> keymatrix, int m)
        {
            int det = Determinant(keymatrix, m);
            while (det < 0)
                det += 26;

            //find correct B 
            int findB = 0;
            for (int i = 2; i < 26; i++)
            {
                if (((i * det) % 26) == 1)
                {
                    findB = i;
                    break;
                }
            }
            det = findB;
            if (m == 2)
            {
                int tmp = keymatrix[0][0] * det;

                keymatrix[0][0] = keymatrix[1][1] * det;
                keymatrix[1][1] = tmp;
                keymatrix[0][1] *= (-1 * det);
                keymatrix[1][0] *= (-1 * det);

                return keymatrix;
            }
            keymatrix = EnarMatrix(keymatrix, m);
            keymatrix = putfactor(keymatrix, m);

            for (int i = 0; i < m; i++)
                for (int j = 0; j < m; j++)
                    keymatrix[i][j] *= det;

            //replace the invece rew-->column column-->row
            for (int i = 0; i < m; i++)
            {
                for (int j = i + 1; j < m; j++)
                {
                    int tmp = keymatrix[i][j];
                    keymatrix[i][j] = keymatrix[j][i];
                    keymatrix[j][i] = tmp;
                }
            }

            return keymatrix;
        }

        private List<int> MultiblyMatrix(List<List<int>> key, List<int> MatRow, int m)
        {
            List<int> result = new List<int>();
            foreach (List<int> keyRow in key)
            {
                int tmp = 0;
                for (int i = 0; i < m; i++)
                {
                    tmp += keyRow[i] * MatRow[i];
                }
                tmp %= 26;
                while (tmp < 0)
                    tmp += 26;
                result.Add(tmp);
            }
            return result;
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> plainText = new List<int>();

            int m = (int)Math.Sqrt(key.Count);
            List<List<int>> keymat = matrixkey(key, m);//true if we generate a key matrix
            List<List<int>> cipher_mat = matrixplain(cipherText, m); //false if we generate a non key matrix

            foreach (List<int> keyrow in keymat)
            {
                if (keyrow.Count != keymat.Count)
                    throw new System.Exception();
            }

            keymat = Inverse(keymat, m);

            for (int i = 0; i < cipherText.Count / m; i++)
            {
                List<int> tmp = MultiblyMatrix(keymat, cipher_mat[i], m);
                for (int j = 0; j < m; j++)
                {
                    plainText.Add(tmp[j]);
                }
            }
            if (plainText.FindAll(s => s.Equals(0)).Count == plainText.Count)
                throw new System.Exception();

            return plainText;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }
        private List<List<int>> matrixkey(List<int> key, int m)
        {
            List<List<int>> ans = new List<List<int>>();
            int rows = m;
            int indx = 0;
            for (int i = 0; i < rows; i++)
            {
                List<int> row_elements = new List<int>();
                for (int j = 0; j < m; j++)
                {
                    row_elements.Add(key[indx]);
                    indx++;
                }
                ans.Add(row_elements);
            }


            return ans;
        }
        private List<List<int>> matrixplain(List<int> plain, int m)
        {
            List<List<int>> ans = new List<List<int>>();
            int rows = plain.Count / m;
            int indx = 0;
            for (int i = 0; i < rows; i++)
            {
                List<int> row_elements = new List<int>();
                for (int j = 0; j < m; j++)
                {
                    row_elements.Add(plain[indx]);
                    indx++;
                }
                ans.Add(row_elements);
            }
            return ans;
        }
        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //throw new NotImplementedException();
            List<int>cipherText = new List<int>();
            int size = (int)Math.Sqrt(key.Count);
            List<List<int>> key_matrix = matrixkey(key, size);
            List<List<int>> plain_matrix = matrixplain(plainText, size);
            int rowplan = plainText.Count / size;
            for (int i = 0; i < rowplan; i++)
            {
                List<int> result = new List<int>();
                foreach (List<int> keyRow in key_matrix)
                {
                    int tmp = 0;
                    for (int j = 0; j < size; j++)
                    {
                        tmp += keyRow[j] * plain_matrix[i][j];
                    }
                    tmp %= 26;
                    while (tmp < 0)
                        tmp += 26;
                    result.Add(tmp);
                }
                for (int j = 0; j < size; j++)
                {
                    cipherText.Add(result[j]);
                }
            }
            
            return cipherText;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //throw new NotImplementedException();
            List<int> key = new List<int>();
            int cntr = 3;
            //try all possible key until to reach correct key
            for (int indx = 0; indx < 3; indx++)
            {
                for (int i = 0; i < 26; i++)
                {
                    for (int j = 0; j < 26; j++)
                    {
                        for (int k = 0; k < 26; k++)
                        {
                            if (((i * plain3[0]) + (j * plain3[1]) + (k * plain3[2])) % 26 == cipher3[indx] &&
                                ((i * plain3[3]) + (j * plain3[4]) + (k * plain3[5])) % 26 == cipher3[indx + 3] &&
                                ((i * plain3[6]) + (j * plain3[7]) + (k * plain3[8])) % 26 == cipher3[indx + 6])
                            {
                                key.Add(i);
                                key.Add(j);
                                key.Add(k);
                                break;
                            }
                        }
                    }
                    if (key.Count == cntr)
                        break;
                }
                cntr += 3;
            }
            if (key.Count < 6)
                throw new InvalidAnlysisException();
            return key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
