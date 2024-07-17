using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            string ans = "";

            plainText = plainText.ToLower();

            for (int i = 0; i < plainText.Length; i++)
            {
                int calc = ((plainText[i] - 'a') + key) % 26;
                ans += (char)('a' + calc);
            }

            return ans;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            string ans = "";

            for (int i = 0; i < cipherText.Length; i++)
            {
                int calc = (cipherText[i] - 'a') - key;
                while (calc < 0) calc += 26;
                ans += (char)(calc + 'a');
            }

            return ans;
        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            if (plainText[0] <= cipherText[0]) return cipherText[0] - plainText[0];
            else return (cipherText[0] - 'a' + 26) - (plainText[0] - 'a');
        }
    }
}
