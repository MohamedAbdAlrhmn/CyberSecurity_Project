using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public int power(int x, int y, int z)
        {
            int ans = 1;
            for (int i = 1; i <= y; i++)
            {
                ans = (ans * x) % z;
            }
            return ans;
        }
        double Km =0;
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            // throw new NotImplementedException();
            double Beta = power(alpha, k, q);
            double Ke = power(alpha, m, q);
            Km = power((int)Beta, m, q);
            double Cipher_Text1 = power(alpha, k, q);
            double Cipher_Text2 = (m * power(y, k, q)) % q;
            List<long> ans = new List<long>();
            ans.Add((long)Cipher_Text1);
            ans.Add((long)Cipher_Text2);
            return ans;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            //throw new NotImplementedException();
            double ans = (c2 * power(c1, q - 1 - x, q)) % q;            
            return (int)ans;                         
        }
    }
}
