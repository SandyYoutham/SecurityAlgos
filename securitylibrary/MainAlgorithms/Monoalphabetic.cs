using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            cipherText = cipherText.ToLower();
            char[] arr = new char[26];
            bool[] taken = new bool[26];
            for(int i = 0; i < plainText.Length; i++)
            {
                arr[plainText[i]-'a'] = cipherText[i];
                taken[cipherText[i] - 'a'] = true;
            }
            Random rnd = new Random();
            for (int i = 0; i < 26; i++)
            {
                if (arr[i] == '\0')
                {
                    int ind = rnd.Next(0, 26);
                    while (taken[ind])
                    {
                        ind = rnd.Next(0, 26);
                    }
                    key +=(char)(ind + 'a');
                    taken[ind] = true;
                }
                else
                {
                    key += arr[i];
                }
            }
            return key;
        }
        
        
        public string Decrypt(string cipherText, string key)
        {
            string plain ="";
            cipherText = cipherText.ToLower();
            for(int i = 0; i < cipherText.Length; i++)
            {
                for(int j = 0; j < key.Length; j++)
                {
                    if (cipherText[i].Equals(key[j]))
                    {
                        int temp = j + 97;
                        plain += (char)temp;
                        break;
                    }
                }
            }

            return plain.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            string ciph="";

            // a->97
            for (int i = 0; i < plainText.Length; i++)
            {
                int index = (int)plainText[i] - 97;
                ciph += key[index];
            }



                return ciph.ToUpper();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string freq = "ETAOINSRHLDCUMFPGWYBVKXJQZ";

            int[] arr = new int[26];

            for (int i = 0; i < cipher.Length; i++)
            {
                arr[cipher[i] - 'A']++;
            }

            List<Tuple<int, char>> v = new List<Tuple<int, char>>();
            for (int i = 0; i < 26; i++)
            {
                if (arr[i] > 0)
                {
                    v.Add(new Tuple<int, char>(arr[i], (char)(i + 'A')));
                }
            }

            v.Sort((x, y) =>
            {
                int result = y.Item1.CompareTo(x.Item1);
                if (result == 0)
                {
                    result = y.Item2.CompareTo(x.Item2);
                }
                return result;
            });

            List<char> lista = new List<char>(cipher.Length);

            for (int j = 0; j < cipher.Length; j++)
            {
                for (int i = 0; i < freq.Length; i++)
                {
                    if (cipher[j] == v[i].Item2)
                    {
                        lista.Add(freq[i]);
                        break;
                    }
                }
            }

            string ans = "";

            for (int i = 0; i < lista.Count; i++)
            {
                ans += lista[i];
            }

            return ans.ToLower();

        }
    }
}
