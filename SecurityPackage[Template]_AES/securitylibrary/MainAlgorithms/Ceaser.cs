using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        IDictionary<int, char> numberNames = new Dictionary<int, char>();
        IDictionary<char,int> NamesNumber = new Dictionary<char,int>();
        public string Encrypt(string plainText, int key)
        {
            char c = 'A';
            for (int i = 0; i < 26; i++)
            {
                numberNames.Add(i, c);
                NamesNumber.Add(c, i);
                c++;
            }
            plainText=plainText.ToUpper();
            string EncryptMessage = "";
            for (int i=0;i<plainText.Length;i++)
            {
                int result = (NamesNumber[plainText[i]] + key) % 26;
                EncryptMessage += numberNames[result];
            }
            return EncryptMessage;
        }
        
        public string Decrypt(string cipherText, int key)
        {
             
             NamesNumber = new Dictionary<char, int>();
            char c = 'A';
            for (int i = 0; i < 26; i++)
            {                
                NamesNumber.Add(c, i);
                c++;
            }
            string Encrypt = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                int result = (NamesNumber[cipherText[i]] - key) % 26;
                if (result >= 0)
                    Encrypt += Convert.ToChar(('A' + result));
                else
                    Encrypt += Convert.ToChar(('A' + result+26));
            }
            return Encrypt.ToLower();
        }

        public int Analyse(string plainText, string cipherText)
        {
            
            NamesNumber = new Dictionary<char, int>();
            char c = 'A';
            for (int i = 0; i < 26; i++)
            {
                NamesNumber.Add(c, i);
                c++;
            }
             c = cipherText[0];
            int indexOfC = NamesNumber[c];
            char p = plainText[0];
            int indexOfp = NamesNumber[char.ToUpper(p)];
            if (indexOfC - indexOfp < 0) 
                return(indexOfC - indexOfp) + 26;
            else return indexOfC%26 - indexOfp;

            

        }
    }
}