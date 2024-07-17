using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            bool found = false;
            decimal keylength = 3;
            int[] key = new int[(int)keylength];
            while (!found)
            {
                int rows =(int) Math.Ceiling(plainText.Length / keylength);
                char[,] mat = new char[rows, (int)keylength];
                int ind = 0;
                for (int i = 0; i < rows; i++)
                {
                    for (int j = 0; j < keylength; j++)
                    {
                        if (ind < plainText.Length)
                        {
                            mat[i, j] = plainText[ind];
                            ind++;
                        }
                        else
                        {
                            mat[i, j] = 'x';
                        }
                    }
                }
                int ciphind = 0;
                bool wrongkey = false;
                while (ciphind < cipherText.Length && !wrongkey)
                {
                    for (int c = 0; c < keylength; c++)
                    {
                        int streak = 0;
                        if (cipherText[ciphind] == mat[0, c])
                        {
                            for (int r = 1; r < rows; r++)
                            {
                                if (cipherText[ciphind + r] != mat[r, c])
                                {
                                    wrongkey = true;
                                    break;
                                }
                                else
                                {
                                    streak++;
                                }
                            }
                            if (streak == rows - 1)
                            {
                                key[c] = (ciphind /rows) + 1;
                                wrongkey = false;
                                break;
                            }
                        }
                    }
                    if (wrongkey)
                    {
                        keylength++;
                        key = new int[(int)keylength];
                        break;
                    }
                    ciphind += rows;
                }
                if (!wrongkey) break;
            }
            return key.ToList();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            string plain = "";
            decimal cols = key.Count();
            decimal rows = Math.Ceiling(cipherText.Length / cols);
            char[,] mat = new char[(int)rows, (int)cols];
            int[] keyInd = new int[key.Count];
            for (int i = 0; i < key.Count; i++)
            {
                keyInd[key[i] - 1] = i;
            }
            int ind = 0;
            foreach(int c in keyInd)
            {
                for(int r = 0; r < rows; r++)
                {
                    if (ind < cipherText.Length)
                    {
                        mat[r, c] = cipherText[ind];
                        ind++;
                    }
                }
            }
            for(int r = 0; r < rows; r++)
            {
                for(int c = 0; c < cols; c++)
                {
                    plain += mat[r, c];
                }
            }

            return plain.ToLower();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            string cipher = "";
            decimal cols = key.Count();
            decimal rows = Math.Ceiling(plainText.Length / cols);
            char[,] mat = new char[(int)rows, (int)cols];
            int ind = 0;
            for(int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    if (ind < plainText.Length)
                    {
                        mat[i, j] = plainText[ind];
                        ind++;
                    }
                    else
                    {
                        mat[i, j] = 'x';
                    }
                }
            }
            int[] keyInd = new int[key.Count];
            for(int i = 0; i < key.Count; i++)
            {
                keyInd[key[i]-1] = i;
            }
            foreach(int c in keyInd)
            {
                for(int r = 0; r < rows; r++)
                {
                    cipher += mat[r, c];
                }
            }
            return cipher.ToUpper();
        }
    }
}
