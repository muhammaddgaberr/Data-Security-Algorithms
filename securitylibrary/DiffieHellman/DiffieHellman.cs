using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int ya = calcmod(alpha,xa,q);
            int yb = calcmod(alpha, xb, q);
            int ka= calcmod(yb, xa, q);
            int kb = calcmod(ya, xb, q);
            return new List<int> { ka, kb };
            // throw new NotImplementedException();
        }
        public int calcmod(int a,int b ,int c)
        {
            int result = 1;
            a=a% c;
            while (b > 0)
            {
                if ((b & 1) == 1)
                {
                    result = (result * a) % c;
                }
                a = (a * a) % c;
                b >>= 1;
            }
            return result;

        }
    }
}
