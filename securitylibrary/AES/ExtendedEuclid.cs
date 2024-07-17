using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            BigInteger gcd = BigInteger.GreatestCommonDivisor(number, baseN);
            if (gcd != 1) return -1;

            int R = baseN % number;
            int B = number, A = baseN;
            int Q = A / B;
            int T1 = 0, T2 = 1, T = T1 - T2 * Q;

            while (true)
            {
                A = B; B = R; T1 = T2; T2 = T;

                if (B == 0) break;

                Q = A / B; R = A % B;
                T = T1 - T2 * Q;

            }
            if (T1 < 0) T1 += baseN;

            return T1;
        }
    }
}
