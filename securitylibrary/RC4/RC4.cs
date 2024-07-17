using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {

        public static string hex_to_bin(string s)
        {
            Dictionary<char, string> htb = new Dictionary<char, string>
            {
                {'0', "0000"},
                {'1', "0001"},
                {'2', "0010"},
                {'3', "0011"},
                {'4', "0100"},
                {'5', "0101"},
                {'6', "0110"},
                {'7', "0111"},
                {'8', "1000"},
                {'9', "1001"},
                {'A', "1010"},
                {'B', "1011"},
                {'C', "1100"},
                {'D', "1101"},
                {'E', "1110"},
                {'F', "1111"}
            };
            s = s.ToUpper();
            string bin_s = "";
            for (int i = 0; i < s.Length; i++)
            {
                bin_s += htb[s[i]];
            }

            return bin_s;
        }
        public static string bin_to_hex(string binary)
        {
            Dictionary<string, char> bth = new Dictionary<string, char>
            {
                {"0000", '0'},
                {"0001", '1'},
                {"0010", '2'},
                {"0011", '3'},
                {"0100", '4'},
                {"0101", '5'},
                {"0110", '6'},
                {"0111", '7'},
                {"1000", '8'},
                {"1001", '9'},
                {"1010", 'A'},
                {"1011", 'B'},
                {"1100", 'C'},
                {"1101", 'D'},
                {"1110", 'E'},
                {"1111", 'F'}
            };

            string hex = "";
            for (int i = 0; i < binary.Length; i += 4)
            {
                string ch = binary.Substring(i, 4);
                hex += bth[ch];
            }
            return hex;
        }
        public static int bin_to_dec(string binary)
        {
            int decimalValue = 0;
            // Reverse the binary string
            // example: 1(^3)1(^2)0(^1)0(^0) -> 0(^0)0(^1)1(^2)1(^3) so it goes with i
            char[] rev = binary.ToCharArray();
            Array.Reverse(rev);

            for (int i = 0; i < rev.Length; i++)
            {
                // Convert char to int
                int bitValue = rev[i] - '0';
                // Calculate decimal value
                decimalValue += bitValue * (int)Math.Pow(2, i);
            }
            return decimalValue;
        }
        public static string dec_to_bin(int decimalNum)
        {
            string binary = "";
            while (decimalNum > 0)
            {
                int rem = decimalNum % 2;
                binary = rem.ToString() + binary;
                decimalNum = decimalNum / 2;
            }
            // Pad zeros to the left to make it a 4-bit string
            while (binary.Length < 8)
            {
                binary = "0" + binary;
            }
            return binary;
        }

        public static int[] init_perm(int[] s, int[] t)
        {
            int j = 0;
            for(int i = 0; i < 256; i++)
            {
                j = (j + s[i] + t[i]) % 256;
                int tmp = s[i];
                s[i] = s[j];
                s[j] = tmp;
            }
            return s;
        }
        public static int[] KeyStreamGen(int[] s,int n)
        {
            int[] keystream = new int[n];

            int i = 0, j = 0;
            for(int x = 0; x < n; x++)
            {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;
                int tmp = s[i];
                s[i] = s[j];
                s[j] = tmp;
                int t = (s[i] + s[j]) % 256;
                keystream[x] = s[t];
            }

            return keystream;
        }
        public static int xor(int p, int k)
        {
            //convert to binary
            string bin_p = dec_to_bin(p);
            string bin_k = dec_to_bin(k);
            //xor
            string res = "";
            for (int i = 0; i < bin_p.Length; i++)
            {
                res += bin_p[i] != bin_k[i] ? "1" : "0";
            }
            //convert back to decimal
            return bin_to_dec(res);
        }
        public override string Encrypt(string plainText, string key)
        {
            string temp_p = "";
            string temp_k = "";
            bool hex = false;
            if (plainText.Substring(0, 2) == "0x" && key.Substring(0, 2) == "0x")
            {
                hex = true;
                for(int i = 2; i < plainText.Length; i+=2)
                {
                    string binP = hex_to_bin(plainText.Substring(i, 2));
                    temp_p += (char)bin_to_dec(binP);
                    string bink = hex_to_bin(key.Substring(i, 2));
                    temp_k += (char)bin_to_dec(bink);
                }
                key = temp_k;
                plainText = temp_p;
            }
            // s & t initialization 
            int[] s = new int[256];
            int[] t = new int[256];
            for (int i = 0; i < 256; i++) s[i] = i;
            for (int i = 0; i < 256; i++) t[i] = key[i % key.Length];

            int[] permuted_s = init_perm(s, t);
            int[] keystream = KeyStreamGen(permuted_s, plainText.Length);
            
            string ciphertext = "";
            for(int i = 0; i < plainText.Length; i++)
            {
               int res = xor(plainText[i], keystream[i]);
               ciphertext +=(char)res;
            }
            if (hex)
            {
                string temp_C = "0x";
                for(int i = 0; i < ciphertext.Length; i++)
                {
                    string binC = dec_to_bin(ciphertext[i]);
                    temp_C += bin_to_hex(binC);
                }
                ciphertext = temp_C;
            }

            return ciphertext;
        }
        public override string Decrypt(string cipherText, string key)
        {
            string temp_c = "";
            string temp_k = "";
            bool hex = false;
            if (cipherText.Substring(0, 2) == "0x" && key.Substring(0, 2) == "0x")
            {
                hex = true;
                for (int i = 2; i < cipherText.Length; i += 2)
                {
                    string binC = hex_to_bin(cipherText.Substring(i, 2));
                    temp_c += (char)bin_to_dec(binC);
                    string bink = hex_to_bin(key.Substring(i, 2));
                    temp_k += (char)bin_to_dec(bink);
                }
                key = temp_k;
                cipherText = temp_c;
            }
            // s & t initialization 
            int[] s = new int[256];
            int[] t = new int[256];
            for (int i = 0; i < 256; i++) s[i] = i;
            for (int i = 0; i < 256; i++) t[i] = key[i % key.Length];

            int[] permuted_s = init_perm(s, t);
            int[] keystream = KeyStreamGen(permuted_s, cipherText.Length);

            string plaintext = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                int res = xor(cipherText[i], keystream[i]);
                plaintext += (char)res;
            }

            if (hex)
            {
                string temp_p = "0x";
                for (int i = 0; i < plaintext.Length; i++)
                {
                    string binP = dec_to_bin(plaintext[i]);
                    temp_p += bin_to_hex(binP);
                }
                plaintext = temp_p;
            }
            /*RC4 d = new RC4();
            string plaintext = d.Encrypt(cipherText, key);*/
            return plaintext;
        }

    }
}
