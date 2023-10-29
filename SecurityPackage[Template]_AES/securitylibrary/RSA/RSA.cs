using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        DiffieHellman.DiffieHellman Hellman = new DiffieHellman.DiffieHellman();
        AES.ExtendedEuclid extendedEuclid = new AES.ExtendedEuclid();
        public int Encrypt(int p, int q, int M, int e)
        {

            return Hellman.power(M, e, p * q) % (p * q);
        }
         
        public int Decrypt(int p, int q, int C, int e)
        {

            return Hellman.power(C, extendedEuclid.GetMultiplicativeInverse(e, (p - 1) * (q - 1)), p * q); 
        }
    }
}
