using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            // throw new NotImplementedException();
            int n = p * q;
            int phi = (p - 1) * (q - 1);
            int d = 0;
            for (int i = 1; i < phi; i++){
                if ((e * i) % phi == 1)
                {
                    d = i;
                    break;
                }
            }
            int C = 1;
            M = M % n; 
            for (int i = 0; i < e; i++)
            {
                C = (C * M) % n;
            }
            return C;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            //throw new NotImplementedException();
            int n = p * q;
            int phi = (p - 1) * (q - 1);
            int d = 0;
            for (int i = 1; i < phi; i++)
            {
                if ((e * i) % phi == 1)
                {
                    d = i;
                    break;
                }
            }
            int M = 1;
            C = C % n;

            for (int i = 0; i < d; i++)
            {
                M = (M * C) % n;

            }
            return M;

        }
          
    }
}
