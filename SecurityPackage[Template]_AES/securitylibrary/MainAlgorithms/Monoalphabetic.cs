using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
       
        public string abc = "abcdefghijklmnopqrstuvwxyz";
        public string Analyse(string plainText, string cipherText)
        {
          
            StringBuilder Plain_key = new StringBuilder("00000000000000000000000000");
            bool[] found = new bool[26];
            int length= plainText.Length;
            for (int x=0;x< length; x++)
            {
                found[cipherText[x] - 'A'] = true;
                Plain_key[plainText[x] - 97] = cipherText[x];
            }
            for (int i = 0; i < 26; i++)
            {
                if (Plain_key[i] == '0')
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (!found[j])
                        {
                            Plain_key[i] = (char)('A' + j);
                            found[j] = true;
                            break;
                        }
                    }
                }
            }
            return Plain_key.ToString().ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
           
            cipherText = cipherText.ToLower();
            char[] Plain_Text = new char[cipherText.Length];
            int index = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int x = 0; x < key.Length; x++)
                {
                    if (cipherText[i] == key[x])
                    {
                        Plain_Text[index] = abc[x];
                        index++;
                    }
                }
            }
            return new string(Plain_Text);
        }

        public string Encrypt(string plainText, string key)
        {
            // هنا هو شاف الاول ترتيب الحرف الي في الرساله فين في ترتيب الحروف الابجديه بعد كده اخد الترتيب وجاب الحرف لي قصادو في جدول كاي

           
            char[] Ciphere_Text = new char[plainText.Length];
            int index = 0;
            for(int i=0;i< plainText.Length;i++)
            {
                for(int x=0;x<abc.Length;x++)
                {
                    if(plainText[i]==abc[x])
                    {
                        Ciphere_Text[index] = key[x];
                        index++;
                    }
                }
            }
            return new string(Ciphere_Text);
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string alphabetFreq = "etaoinsrhldcumfpgwybvkxjqz";
            Dictionary<char, int> freq = new Dictionary<char, int>();
            Dictionary<char, char> table = new Dictionary<char, char>();
            cipher = cipher.ToLower();
            int CTLength = cipher.Length;
            string key = "";
            for (int i = 0; i < CTLength; i++)
            {
                if (!freq.ContainsKey(cipher[i]))
                {
                    freq.Add(cipher[i], 0);
                }
                else
                {
                    freq[cipher[i]]++;
                }
            }

            freq = freq.OrderBy(iteam => iteam.Value).Reverse().ToDictionary(iteam => iteam.Key, iteam => iteam.Value);
            int counter = 0;
            foreach (var item in freq)
            {
                table.Add(item.Key, alphabetFreq[counter]);
                counter++;
            }

            for (int i = 0; i < CTLength; i++)
            {
                key += table[cipher[i]];
            }

            return key;
        }
    }
}