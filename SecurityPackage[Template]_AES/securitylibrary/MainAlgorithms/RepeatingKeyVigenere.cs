using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            String Key_stream = "";
            int len_cipher = cipherText.Length;
            string find_ch = "abcdefghijklmnopqrstuvwxyz";
            for (int i = 0; i < len_cipher; i++)
            {
                int indx = (find_ch.IndexOf(cipherText[i]) - find_ch.IndexOf(plainText[i])) + 26;
                indx = indx % 26;
                Key_stream += find_ch[indx];
                string ret_key = Encrypt(plainText, Key_stream);
                if (cipherText.Equals(ret_key))
                {
                    return Key_stream;
                }
            }
            return Key_stream;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string P_T = "";
            int len_Key = key.Length;
            int len_cipher = cipherText.Length;
            String Key_stream = key;
            for (int i = len_Key; i < len_cipher; i++)
            {
                int indx = (i - len_Key) % len_Key;
                Key_stream += key[indx];
            }
            string find_ch = "abcdefghijklmnopqrstuvwxyz";
            for (int i = 0; i < len_cipher; i++)
            {
                int indx = (find_ch.IndexOf(cipherText[i]) - find_ch.IndexOf(Key_stream[i]))+26;
                indx = indx % 26;
                P_T += find_ch[indx];
            }
            return P_T;
        }

        public string Encrypt(string plainText, string key)
        {
            String Key_stream = key;
            int len_plan = plainText.Length;
            int len_Key =key.Length;
            String C_T = "";
            for (int i = len_Key; i < len_plan; i++)
            {
                int indx = (i - len_Key)%len_Key;
                Key_stream += key[indx];
            }
            string find_ch = "abcdefghijklmnopqrstuvwxyz";
            for (int i = 0; i < len_plan; i++)
            {
                int indx = find_ch.IndexOf(plainText[i]) + find_ch.IndexOf(Key_stream[i]);
                indx = indx % 26;
                C_T += find_ch[indx]; 
            }
            return C_T;
        }
    }
}