using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public int power(int x, int y, int z)
        {
            int ans = 1;
            for (int i = 1; i <= y; i++)
            {
                ans = (ans * x) % z;
            }
            return ans;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
           double Public_keyA = power(alpha,xa,q);
            double Public_keyB = power(alpha, xb, q);
            double Reverse_keyA = power((int)Public_keyB, xa, q);
            double Reverse_keyB = power((int)Public_keyA, xb, q);
            List<int> ans = new List<int>();
            ans.Add((int)Reverse_keyA);
            ans.Add((int)Reverse_keyB);
            return ans;
        } 
    }
}