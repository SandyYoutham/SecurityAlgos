using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES D = new DES();
            string X = D.Decrypt(cipherText, key[0]);
            string Y = D.Encrypt(X, key[1]);
            string plaintext = D.Decrypt(Y, key[0]);
            return plaintext;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES D = new DES();
            
            string X = D.Encrypt(plainText, key[0]);
            string Y = D.Decrypt(X, key[1]);
            string ciphertext = D.Encrypt(Y, key[0]);

            return ciphertext;
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
