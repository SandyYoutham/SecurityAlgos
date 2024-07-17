using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            for (int i = 2; i < cipherText.Length; i++)
            {
                if (Encrypt(plainText, i) == cipherText) return i;

            }

            return 0;

        }

        public string Decrypt(string cipherText, int key)
        {

            cipherText = cipherText.ToLower();

            int extras = cipherText.Length % key;
            int siz = cipherText.Length / key;
            int one = 0;
            string ans = "";

            if (extras != 0) one = 1;

            for (int i = 0; i < siz + one; i++)
            {
                int j = i;

                if (i == siz)
                {
                    while (extras != 0)
                    {
                        ans += cipherText[j];
                        j += siz + 1;
                        extras--;
                    }
                    break;
                }

                while (j < cipherText.Length)
                {
                    ans += cipherText[j];

                    if (Math.Ceiling(((decimal)j / (decimal)siz)) <= extras && extras != 0)
                    {
                        j++;
                    }

                    j += siz;

                }
            }

            return ans;


        }

        public string Encrypt(string plainText, int key)
        {
            plainText = plainText.ToLower();

            int i = 0;
            string ans = "";

            while (i < key)
            {
                int j = i;
                while (j < plainText.Length)
                {
                    ans += plainText[j];
                    j += key;
                }
                i++;
            }
            return ans;
        }
    }
}
