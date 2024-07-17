using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            string tmp = "";
            string streamKey = "";
            cipherText = cipherText.ToLower();
            string alpha = "abcdefghijklmnopqrstuvwxyz";

            for (int i = 0; i < plainText.Length; i++)
            {
                int ind = (cipherText[i] - 'a') - (plainText[i] - 'a');
                if (ind < 0)
                {
                    ind += 26;
                }
                streamKey += alpha[ind];
            }
            key += streamKey[0];
            int counter = 0;
            for (int i = 1; i < streamKey.Length; i++)
            {
                if (counter == key.Length) break;
                if (streamKey[i] == key[counter])
                {
                    tmp += streamKey[i];
                    counter++;
                }
                else
                {
                    key += tmp;
                    key += streamKey[i];
                    counter = 0;
                    tmp = "";
                }
            }
            return key;
            /*int[] arr = new int[26];
            for (int i = 0; i < streamKey.Length; i++)
            {
                if (arr[streamKey[i] - 'a']++ == 0)
                {
                    key += streamKey[i];
                }
                else
                {
                    string tmp = "";
                    for (int j = i; j < streamKey.Length; j++)
                    {
                        tmp += streamKey[j];
                        if (arr[streamKey[j] - 'a']++ == 0)
                        {
                            key += tmp;
                            i = j;
                            break;
                        }

                    }
                }
            }
            if (key.Length < streamKey.Length)
            {
                while (streamKey[key.Length] != key[0])
                {
                    key += streamKey[key.Length];
                }
            }
            return key;*/
        }

        public string Decrypt(string cipherText, string key)
        {
            string plain = "";
            cipherText = cipherText.ToLower();
            string alpha = "abcdefghijklmnopqrstuvwxyz";

            int l = cipherText.Length - key.Length;
            string updatedKey = key;
            for (int k = 0; k < l; k++)
            {
                updatedKey += key[k % key.Length];
            }

            for (int i = 0; i < cipherText.Length; i++)
            {
                int ind = ((int)cipherText[i] - 'a') - ((int)updatedKey[i] - 'a');
                if(ind < 0)
                {
                    plain += alpha[ind + 26];
                }
                else
                {
                    plain += alpha[ind];

                }
            }


            return plain;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipher = "";
            int[,] vigenereTable  = new int[26, 26];
            for(int i = 0; i < 26; i++)
            {
                for(int j = 0; j < 26; j++)
                {
                    vigenereTable[i, j] = (i + j) % 26;
                }
            }
            ///can be created with chars
            ///char[,] vigenereTable = new char[26, 26];
            ///for (int i = 0; i < 26; i++)
            ///{
            ///    for (int j = 0; j < 26; j++)
            ///    {
            ///        vigenereTable[i, j] = (char)('A' + (i + j) % 26);
            ///    }
            ///}

            int l = plainText.Length - key.Length;
            string updatedKey = key;
            for(int k = 0; k < l; k++)
            {
                updatedKey += key[k % key.Length];
            }
            
            for(int i=0; i < plainText.Length; i++)
            {
                int ind1 = (int)plainText[i]-'a' ;
                int ind2 = (int)updatedKey[i] - 'a';

                cipher += (char)(vigenereTable[ind1, ind2] + 'a');
            }

            return cipher.ToUpper();
        }
    }
}