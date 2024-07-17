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
            int ktemp = FastPower(alpha, xa, q);

            int k = FastPower(ktemp, xb, q);

            List<int> list = new List<int>();
            list.Add(k); list.Add(k);
            return list;
        }

        public static int FastPower(int baseNum, int power, int mod)
        {
            //base case
            if (power == 1) return baseNum;

            //transition
            long halfPower = FastPower(baseNum, power / 2, mod);
            long ret = (halfPower * halfPower) % mod;

            //check if the power is odd
            if ((power % 2) == 1)
                ret = (ret * baseNum) % mod;
            return (int)ret;
        }

    }


}
