using SecurityLibrary.AES;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Data.Common;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Messaging;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {

            for (int i = 0; i <= 26; i++)
            {
                for (int j = 0; j <= 26; j++)
                {
                    for (int k = 0; k <= 26; k++)
                    {
                        for (int l = 0; l <= 26; l++)
                        {
                            ExtendedEuclid algo = new ExtendedEuclid();

                            int calc = algo.GetMultiplicativeInverse(i * l - j * k, 26);
                            if (calc == -1) continue;

                            List<int> lista = new List<int>();
                            lista.Add(i);
                            lista.Add(j);
                            lista.Add(k);
                            lista.Add(l);
                            List<int> tmp = Encrypt(plainText, lista);

                            if (tmp.SequenceEqual(cipherText)) return lista;
                        }
                    }
                }
            }

            throw new InvalidAnlysisException();

        }

        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            List<int> p = new List<int>();
            List<int> c = new List<int>();

            for (int i = 0; i < plainText.Length; i++) p.Add(plainText[i] - 'a');
            for (int i = 0; i < cipherText.Length; i++) c.Add(cipherText[i] - 'a');

            List<int> tmp = Analyse(p, c);
            string ans = "";

            for (int i = 0; i < tmp.Count; i++)
            {
                ans += (char)(tmp[i] + 'a');
            }

            return ans;
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int[,] k = createMatrix(key);
            int[,] kInv = InvM(k);

            List<int> ans = new List<int>();
            int i2 = 0;

            while (i2 != cipherText.Count)
            {
                List<int> tmp2 = MM(kInv, cipherText.GetRange(i2, k.GetLength(0)));
                ans.AddRange(tmp2);

                i2 += k.GetLength(0);
            }
            return ans;
        }

        public string Decrypt(string cipherText, string key)
        {
            key = key.ToLower();
            cipherText = cipherText.ToLower();

            List<int> k = new List<int>();
            List<int> c = new List<int>();

            for (int i = 0; i < key.Length; i++) k.Add(key[i] - 'a');
            for (int i = 0; i < cipherText.Length; i++) c.Add(cipherText[i] - 'a');

            List<int> tmp = Decrypt(c, k);
            string ans = "";

            for (int i = 0; i < tmp.Count; i++)
            {
                ans += (char)(tmp[i] + 'a');
            }

            return ans;
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int[,] k = createMatrix(key);
            List<int> ans = new List<int>();

            int i2 = 0;
            while (i2 != plainText.Count)
            {
                List<int> tmp2 = MM(k, plainText.GetRange(i2, k.GetLength(0)));
                ans.AddRange(tmp2);

                i2 += k.GetLength(0);
            }

            return ans;
        }

        public string Encrypt(string plainText, string key)
        {
            key = key.ToLower();
            plainText = plainText.ToLower();

            List<int> k = new List<int>();
            List<int> p = new List<int>();

            for (int i = 0; i < key.Length; i++) k.Add(key[i] - 'a');
            for (int i = 0; i < plainText.Length; i++) p.Add(plainText[i] - 'a');

            List<int> tmp = Encrypt(p, k);
            string ans = "";

            for (int i = 0; i < tmp.Count; i++)
            {
                ans += (char)(tmp[i] + 'a');
            }

            return ans;
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            int[,] p = createMatrix(plain3);
            int[,] pInv = InvM(p);

            List<int> ans = new List<int>();
            int i2 = 0;

            while (i2 + 6 < cipher3.Count)
            {
                List<int> l = new List<int>();

                l.Add(cipher3[i2]);
                l.Add(cipher3[i2 + 3]);
                l.Add(cipher3[i2 + 6]);

                List<int> tmp2 = MM(pInv, l);
                ans.AddRange(tmp2);

                i2++;
            }
            return ans;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {

            plain3 = plain3.ToLower();
            cipher3 = cipher3.ToLower();

            List<int> p = new List<int>();
            List<int> c = new List<int>();

            for (int i = 0; i < plain3.Length; i++)
            {
                p.Add(plain3[i] - 'a');
                c.Add(cipher3[i] - 'a');
            }

            List<int> tmp = Analyse3By3Key(p, c);
            string ans = "";

            for (int i = 0; i < tmp.Count; i++)
            {
                ans += (char)(tmp[i] + 'a');
            }

            return ans;

        }

        public int[,] createMatrix(List<int> tobematrix)
        {
            int[,] matrix = null;
            int j = 0;
            int siz = 3;

            if (tobematrix.Count == 4) siz = 2;

            matrix = new int[siz, siz];

            for (int i = 0; i < siz; i++)
            {
                for (int k = 0; k < siz; k++)
                {
                    matrix[i, k] = tobematrix[j];
                    j++;
                }
            }
            return matrix;
        }
        List<int> MM(int[,] k, List<int> column)
        {
            List<int> res = new List<int>();

            for (int i = 0; i < column.Count; i++)
            {
                int tmp = 0;
                for (int j = 0; j < column.Count; j++)
                {
                    tmp += (k[i, j] * column[j]);
                }
                res.Add(tmp % 26);
            }

            return res;
        }
        int dtm(int[,] mtrx)
        {
            int ret = 0;

            if (mtrx.Length == 4)
            {
                ret = mtrx[0, 0] * mtrx[1, 1] - mtrx[0, 1] * mtrx[1, 0];
            }
            else
            {
                ret = mtrx[0, 0] * (mtrx[1, 1] * mtrx[2, 2] - mtrx[1, 2] * mtrx[2, 1])
                    - mtrx[0, 1] * (mtrx[1, 0] * mtrx[2, 2] - mtrx[1, 2] * mtrx[2, 0])
                    + mtrx[0, 2] * (mtrx[1, 0] * mtrx[2, 1] - mtrx[1, 1] * mtrx[2, 0]);
            }

            ret = validate(ret);
            return ret;
        }
        int validate(int n)
        {
            if (n < 0) return -((-n) % 26) + 26;

            return n % 26;
        }
        int[,] adjK(int[,] mtrx)
        {
            int[,] tmp = new int[5, 5];

            if (mtrx.Length == 4)
            {
                int[,] tmp2 = new int[2, 2];

                tmp2[0, 0] = mtrx[1, 1];
                tmp2[1, 1] = mtrx[0, 0];
                tmp2[1, 0] = -mtrx[1, 0];
                tmp2[0, 1] = -mtrx[0, 1];

                return tmp2;
            }
            else
            {
                for (int i = 0; i < 5; i++)
                {
                    int col = i % 3;

                    for (int j = 0; j < 3; j++)
                    {
                        tmp[j, i] = mtrx[j, col];
                    }
                }

                for (int i = 0; i < 5; i++)
                {
                    tmp[3, i] = tmp[0, i];
                    tmp[4, i] = tmp[1, i];
                }

                int[,] tmp2 = new int[3, 3];
                int i2 = 0, j2 = 0;

                for (int i = 1; i < 4; i++)
                {
                    for (int j = 1; j < 4; j++)
                    {
                        tmp2[i2, j2] = tmp[i, j] * tmp[i + 1, j + 1] - tmp[i + 1, j] * tmp[i, j + 1];
                        tmp2[i2, j2] = validate(tmp2[i2, j2]) % 26;

                        i2++;
                    }
                    i2 = 0; j2++;
                }
                return tmp2;
            }
        }

        int[,] InvM(int[,] mtrx)
        {
            int[,] kAdj = adjK(mtrx);

            ExtendedEuclid algo = new ExtendedEuclid();

            int dt = dtm(mtrx);
            int multInv = algo.GetMultiplicativeInverse(dt, 26);

            if (multInv == -1) throw new InvalidAnlysisException();

            for (int i = 0; i < kAdj.GetLength(0); i++)
            {
                for (int j = 0; j < kAdj.GetLength(0); j++)
                {
                    kAdj[i, j] = validate(kAdj[i, j] * multInv) % 26;
                }
            }
            return kAdj;
        }
    }
}