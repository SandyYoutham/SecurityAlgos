using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            cipherText = cipherText.ToLower();
            string alpha = "abcdefghijklmnopqrstuvwxyz";

            for (int i = 0; i < plainText.Length; i++)
            {
                int ind = ((int)cipherText[i] - 'a') - ((int)plainText[i] - 'a');
                if (ind < 0)
                {
                   ind += 26;
                }
                if (alpha[ind].Equals(plainText[0]))
                {
                    break;
                }
                key += alpha[ind];    
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string plain = "";
            cipherText = cipherText.ToLower();
            string alpha = "abcdefghijklmnopqrstuvwxyz";
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (i < key.Length)
                {
                    int ind = ((int)cipherText[i] - 'a') - ((int)key[i] - 'a');
                    if (ind < 0)
                    {
                        plain += alpha[ind + 26];
                    }
                    else
                    {
                        plain += alpha[ind];

                    }
                }
                else
                {
                    int ind = ((int)cipherText[i] - 'a') - ((int)plain[i-key.Length] - 'a');
                    if (ind < 0)
                    {
                        plain += alpha[ind + 26];
                    }
                    else
                    {
                        plain += alpha[ind];

                    }
                }
            }
            
            return plain;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipher = "";
            int[,] vigenereTable = new int[26, 26];
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    vigenereTable[i, j] = (i + j) % 26;
                }
            }
            int l = plainText.Length - key.Length;
            string updatedKey = key;
            for (int k = 0; k < l; k++)
            {
                updatedKey += plainText[k % plainText.Length];
            }

            for (int i = 0; i < plainText.Length; i++)
            {
                int ind1 = (int)plainText[i] - 'a';
                int ind2 = (int)updatedKey[i] - 'a';

                cipher += (char)(vigenereTable[ind1, ind2] + 'a');
            }

            return cipher.ToUpper();
        }
    }
}
