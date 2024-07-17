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
    public class DES : CryptographicTechnique
    {
        // tables used in permutation
        public static int[] initial_perm = {58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7 };

        public static int[] keyp1 = {57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4 };

        public static int[] keyp2 ={14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32 };

        public static int[] round_per = {16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25 };

        public static int[] final_perm = {40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25};
        
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
            string bin_s = "";
            for(int i = 2; i < s.Length; i++)
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

            string hex = "0x";
            for (int i = 0; i < binary.Length; i += 4)
            {
                string ch = binary.Substring(i,4);
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
            while (binary.Length < 4)
            {
                binary = "0" + binary;
            }
            return binary;
        }

        public static string permutation(string text, int[] perTable)
        {
            string res = "";
            foreach(int i in perTable)
            {
                res += text[i - 1];
            }
            return res;
        }
        public static string left_cir_shift(string key, int round_num)
        {
            int n = 0;
            if (round_num == 1 || round_num == 2 || round_num == 9 || round_num == 16)
            {
                n = 1;
            }
            else n = 2;

            char[] res = new char[key.Length];
            for(int i = 0; i < key.Length; i++)
            {
                int newind = (i - n + key.Length) % key.Length;
                res[newind] = key[i];
            }
            return new string(res);
        }
        public static string expand(string pt)
        {
            int[] exp_d = {32, 1, 2, 3, 4, 5, 4, 5,
            6, 7, 8, 9, 8, 9, 10, 11,
            12, 13, 12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21, 20, 21,
            22, 23, 24, 25, 24, 25, 26, 27,
            28, 29, 28, 29, 30, 31, 32, 1 };

            string res ="";
            foreach (int i in exp_d)
            {
                res += pt[i - 1];
            }
            return res;
        }
        public static string XOR(string x1, string x2)
        {
            string res = "";
            for(int i = 0; i < x1.Length; i++)
            {
                res += x1[i] != x2[i] ? "1" : "0";
            }
            return res;
        }
        public static string sub(string xored)
        {
            int[][][] sbox = {
                new int[][] {
                    new int[] {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                    new int[] {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                    new int[] {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                    new int[] {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
                },
                new int[][] {
                    new int[] {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                    new int[] {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                    new int[] {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                    new int[] {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
                },
                new int[][] {
                    new int[] {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                    new int[] {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                    new int[] {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                    new int[] {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
                },
                new int[][] {
                    new int[] {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                    new int[] {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                    new int[] {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                    new int[] {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
                },
                new int[][] {
                    new int[] {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                    new int[] {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                    new int[] {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                    new int[] {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
                },
                new int[][] {
                    new int[] {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                    new int[] {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                    new int[] {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                    new int[] {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
                },
                new int[][] {
                    new int[] {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                    new int[] {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                    new int[] {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                    new int[] {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
                },
                new int[][] {
                    new int[] {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                    new int[] {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                    new int[] {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                    new int[] {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
                }
            };
            string res = "";
            int sbox_num = 0;
            for (int i = 0; i < xored.Length; i += 6)
            {
                string outers = xored[i].ToString() + xored[i + 5].ToString();
                string inners = xored.Substring(i + 1, 4);
                int row = bin_to_dec(outers);
                int col = bin_to_dec(inners);
                res += dec_to_bin(sbox[sbox_num][row][col]);
                sbox_num++;
            }
            return res;
        }
        public static string[] generate_keys(string C, string D)
        {
            string[] keys = new string[16];
            for (int r = 1; r <= 16; r++)
            {
                //Generate key of the round 
                C = left_cir_shift(C, r);
                D = left_cir_shift(D, r);
                // combine and permute2
                keys[r-1] = permutation(C + D, keyp2);
            }
            return keys;
        }
        
        public override string Encrypt(string plainText, string key)
        {
            // convert from hex to bin 
            string bin_pt = hex_to_bin(plainText);
            string bin_key = hex_to_bin(key);

            // initial permutation
            string per_bin_pt = permutation(bin_pt, initial_perm);
            
            // permutaion choice 1
            string per1_bin_key = permutation(bin_key, keyp1);
            
            // split pt
            string left = per_bin_pt.Substring(0, 32);
            string right = per_bin_pt.Substring(32, 32);
            
            // split key
            string C = per1_bin_key.Substring(0, 28);
            string D = per1_bin_key.Substring(28,28);
            
            string[] keys = generate_keys(C, D);
            for(int r = 1; r <= 16; r++)
            {
                // for each Round
                // expansion of right side of pt
                string exp_r = expand(right);
                
                // XOR res with key
                string xored = XOR(exp_r, keys[r-1]);

                // Sub(S-box) 48->32
                string subted = sub(xored);
                
                // permute 
                string permuted = permutation(subted, round_per);
                // XOR res with left 32 bit
                left = XOR(permuted, left);

                // swap left and right bits in after each round except last one
                if (r != 16)
                {
                    string temp = right;
                    right = left;
                    left = temp;
                }
            }
            // swap last round and inverse initial permutation using final_perm table
            string ciphertext = permutation(left + right, final_perm);
            return bin_to_hex(ciphertext);
        }
        public override string Decrypt(string cipherText, string key)
        {
            // convert from hex to bin 
            string bin_ct = hex_to_bin(cipherText);
            string bin_key = hex_to_bin(key);
            
            // permutation
            string per_bin_ct = permutation(bin_ct, initial_perm);
            string per1_bin_key = permutation(bin_key, keyp1);

            // split pt
            string left = per_bin_ct.Substring(0, 32);
            string right = per_bin_ct.Substring(32, 32);

            // split original key
            string C = per1_bin_key.Substring(0, 28);
            string D = per1_bin_key.Substring(28, 28);
            
            // generate all keys and use them in reverse order 
            string[] keys = generate_keys(C, D);
            Array.Reverse(keys);
            
            for (int r = 1; r <= 16; r++)
            {
                // for each Round
                // expansion of right 32 bits
                string exp_r = expand(right);
                
                // XOR expanded right ct with key
                string xored = XOR(exp_r, keys[r-1]);

                // Sub(S-box) 48->32
                string subted = sub(xored);

                // permute 
                string permuted = permutation(subted, round_per);
                // XOR res with left 32 bit 
                left = XOR(permuted, left);

                // swap left and right bits in after each round except last one
                if (r != 16)
                {
                    string temp = right;
                    right = left;
                    left = temp;
                }
            }

            // swap last round and inverse initial permutation using final_perm table
            string plaintext = permutation(left + right, final_perm);
            return bin_to_hex(plaintext);
        }
    }
}
