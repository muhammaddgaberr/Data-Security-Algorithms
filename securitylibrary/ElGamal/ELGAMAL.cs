using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> cipher = new List<long>();
            long c1 = calcmod(alpha, k, q);
            long K = calcmod(y, k, q);
            long c2 = (K * m) % q;
            cipher.Add(c1);
            cipher.Add(c2);
            return cipher;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            //throw new NotImplementedException();
            long K = calcmod(c1, x, q);
            long inversk=calcinvmod(K, q);
            long m = (c2 * inversk) % q;
            return (int)m;
        }
        public long calcmod(long a,long b,long c)
        {
            long res = 1;
            a = a % c;
            while (b > 0)
            {
                if ((b & 1) == 1)
                    res = (res * a) % c;
                a = (a * a) % c;
                b = b >> 1;
            }
            return res;
        }
        public long calcinvmod(long a, long m)
        {
            long m0 = m;
            long y = 0;
            long x = 1;
            if (m == 1)
                return 0;
            while (a > 1)
            {
                long q = a / m;
                long t = m;
                m = a % m;
                a = t;
                t = y;
                y = x - q * y;
                x = t;
            } 
            if (x < 0)
                x += m0;
            return x;
        }
    }
}
