using SecurityLibrary.AES;
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
            long n = p * q;

            long res = FastPower(M, e, n);

            return (int)res;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            long n = p * q;
            long euler = (p - 1) * (q - 1);

            ExtendedEuclid algo = new ExtendedEuclid();
            long D = algo.GetMultiplicativeInverse(e, (int)euler);

            long res = FastPower(C, D, n);
            return (int)res;

        }
        public static long FastPower(long baseNum, long power, long mod)
        {
            //base case
            if (power == 1) return baseNum;

            //transition
            long halfPower = FastPower(baseNum, power / 2, mod);
            long ret = (halfPower * halfPower) % mod;

            //check if the power is odd
            if ((power % 2) == 1)
                ret = (ret * baseNum) % mod;
            return ret;
        }


    }
}
