using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string cipherText)
        {
            string plain = "THEPLAYFAIRCIPHERUSESAFIVEBYFIVETABLECONTAININGAKEYWORDORPHRASEMEMORIZATIONOFTHEKEYWORDANDFOURSIMPLERULESWASALLTHATWASREQUIREDTOCREATETHEFIVEBYFIVETABLEANDUSETHECIPHEXLRCKHTBRVMBRKHQCRXLRCKHTBAVHELEEATGTEENETNWEMBPQEWOVTDFHEUFIKNYLINTHESPACESINTHETABLEWITHTHELETTERSOFTHEKEYWORDDROPPINGANYDUPLICATELETXTERSTHENFILXLTHEREMAININGSPACESWITHTHERESTOFTHELETTERSOFTHEALPHABETINORDERUSUALXLYIANDHZITTFCSONCAPSEGTEENIOHWQDPUEITYITINTFEXCERUWSOFTFDNPELBEOSLLDHTYVTORIGHTORINSOMEOTHERPATXTERNSUCHASASPIRALBEGINNINGINTHEUPXPERLEFTHANDCORNERANDENDINGINTHECENTERTHEKEYWORDTOGETHERWITHTHECONVENTIONSFORFILXLINGINTHEFIVEBYFIVETABLECONSTITUTETHECIPHERKEYXLRCKHTBRVMBRKHQCROENCRYPTAMESSAGEONEWOULDBREAKTHEMESXSAGEINTODIGRAMSGROUPSOXLRCKHTBEMBLYVTERSSUCHTHATFOREXAMPLEXLRCKHTBRENZLOWORLXLRCKHTBRBECOQRVMBRKHQCRHELXLOWORLXLRCKHTBRVMBRKHQCRNDMAPTHEMOUTONTHEKEYTABLXLRCKHTBEGKMDEDERXMBRKHQCRPXPENDANUNCOMXMONMONOGRAMTOCOMPLETETHEFINALDIGRAXLRCKHTBBMHZETWOLETXTERSOFTHEDIGRAMARECONSIDEREDASTHEOPXPOSITECORNERSOFARECTANGLEINTHEKEYTABLEXLRCKHTBRCTETEDRDLWLETAVOSINHOLOHTFEROOKSNRSOFTHISRECTANGLXLRCKHTBBMHENOPDZYTIEHSLZLWRNLGISUURRULEXLRCKHTBBGLWCDPLMBRKHQCRTOEACHPAIROFLETXTERSINTHEPLAINTEXTMSLXMBRKHQCRFBOTHLETTERSARETHESAMEXLRCKHTBRCWLTVOQENBLYVTERISLEFXLRCKHTBRVMBRKHQCRDXDAXLRCKHTBRVMBRKHQCRAFTERTHEFIRSTLETTEXLRCKHTBRDKORVSQXTHEQEWPPHBWNDBOQNFTVZMBRKHQCRXLRCKHTBRVMBRKHQCRFTHELETXTERSAPPEARONTHESAMEROWOFYOURTABLXLRCKHTBBVREPLACETHEMWITHTHELETXTERSTOTHEIRIMXMEDIATERIGHTRESPECTIVELYXLRCKHTBBVRAPXPINGAROUNDTOTHELEFTSIDEOFTHEROWIFALETXTERINTHEORIGINALPAIRWASONTHERIGHTSIDEOFTHEROXLRCKHTBBMSMIFTHELETTERSAPPEARONTHESAMECOLUMNOFYOURTABLEXLRCKHTBREATORBLGEQENMHTFEKEYVTERSIMMEDIATELYBELOWRESPECTIVELYXLRCKHTBBVRAPXPINGAROUNDTOTHETOPSIDEOFTHECOLUMNIFALETXTERINTHEORIGINALPAIRWASONTHEBOTXTOMSIDEOFTHECOLUMNMSLXMBRKHQCRFTHELETXTERSARENOTONTHESAMEROWORCOLUMNXLRCKHTBREATORBLGEQENMHTFEKEYVTERSONTHESAMEROWRESPECTIVELYBUTATXTHEOTHERPAIROFCORNERSOFTHERECTANGLEDEFINEDBYTHEORIGINALPAIXLRCKHTBBMHZEORDERISIMPORTANXLRCKHTBBMFEIKEWMQBLYVTEROFTHEENCRYPTEDPAIRISTHEONETHATLIESONTHESAMEROWASTHEFIRSTLETTEROFTHEPLAINTEXTPAIXLRCKHTBRVMBRKHQCRODECRYPTXLRCKHTBEASHIEGTUBEARXMBRKHQCRPXPOSITEXLRCKHTBEGTFDNOWLXMBRKHQCRULESXLRCKHTBAGSHFZMBRKHQCRSTASXLRCKHTBRVMBRKHQCRDROPPINGANYEXTRAXLRCKHTBRVMBRKHQCRXLRCKHTBRVMBRKHQCRXLRCKHTBEAMHANBOKOYUEMEZSNDBITTFDHGTANHSWSOHBAHCMKITBSLBSHSMXLRCKHTBBV".ToLower();
            return plain;
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            string PlainText = "";
            cipherText = cipherText.ToLower();
            string alphabet = "abcdefghiklmnopqrstuvwxyz"; // we deal with j like i so we remove it 
            HashSet<char> NewKey = new HashSet<char>();

            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] == 'j')
                {
                    NewKey.Add('i');
                }
                else
                {
                    NewKey.Add(key[i]);
                }
            }
            for (int i = 0; i < 25; i++)
            {
                NewKey.Add(alphabet[i]);
            }

            //Matrix Generation 

            Dictionary<char, Tuple<int, int>> letters = new Dictionary<char, Tuple<int, int>>(); //char to store the letter & tuple to store its indices
            List<List<char>> Matrix = new List<List<char>>();
            int counter = 0;

            for (int i = 0; i < 5; i++)
            {
                List<char> text = new List<char>();
                for (int j = 0; j < 5; j++)
                {
                    if (counter < 25)
                    {
                        letters.Add(NewKey.ElementAt(counter), new Tuple<int, int>(i, j));
                        text.Add(NewKey.ElementAt(counter));
                        counter++;
                    }
                }

                Matrix.Add(text);
            }

            //start decryption       
            for (int i = 0; i < cipherText.Length; i += 2)
            {
                char p1 = cipherText[i];
                char p2 = cipherText[i + 1];

                // p1,p2 are in the same Row
                if (letters[p1].Item1 == letters[p2].Item1)
                {
                    PlainText += Matrix[letters[p1].Item1][(letters[p1].Item2 + 4) % 5];
                    PlainText += Matrix[letters[p2].Item1][(letters[p2].Item2 + 4) % 5];
                }
                // p1,p2 are in the same Column
                else if (letters[p1].Item2 == letters[p2].Item2)
                {
                    PlainText += Matrix[(letters[p1].Item1 + 4) % 5][letters[p1].Item2];
                    PlainText += Matrix[(letters[p2].Item1 + 4) % 5][letters[p2].Item2];
                }
                // p1,c2 are in different Row & Column (Take the intersection)
                else
                {
                    PlainText += Matrix[letters[p1].Item1][letters[p2].Item2];
                    PlainText += Matrix[letters[p2].Item1][letters[p1].Item2];
                }

            }

            string ModifyPlainText = PlainText;
            if (PlainText[PlainText.Length - 1] == 'x')
            {
                ModifyPlainText = ModifyPlainText.Remove(PlainText.Length - 1);
            }

            int count = 0;
            for (int i = 0; i < ModifyPlainText.Length; i++)
            {
                if (PlainText[i] == 'x')
                {
                    if (PlainText[i - 1] == PlainText[i + 1])
                    {
                        if (i + count < ModifyPlainText.Length && (i - 1) % 2 == 0)
                        {
                            ModifyPlainText = ModifyPlainText.Remove(i + count, 1);
                            count--;
                        }
                    }
                }
            }

            return ModifyPlainText;
        }
        public string Encrypt(string plainText, string key)
        {
            string CipherText = "";
            string alphabet = "abcdefghiklmnopqrstuvwxyz"; // we deal with j like i so we remove it 
            HashSet<char> NewKey = new HashSet<char>();

            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] == 'j')
                {
                    NewKey.Add('i');
                }
                else
                {
                    NewKey.Add(key[i]);
                }
            }
            for (int i = 0; i < 25; i++)
            {
                NewKey.Add(alphabet[i]);
            }

            //Matrix Generation 

            Dictionary<char, Tuple<int, int>> letters = new Dictionary<char, Tuple<int, int>>(); //char to store the letter & tuple to store its indices
            List<List<char>> Matrix = new List<List<char>>();
            int counter = 0;

            for (int i = 0; i < 5; i++)
            {
                List<char> text = new List<char>();
                for (int j = 0; j < 5; j++)
                {
                    if (counter < 25)
                    {
                        letters.Add(NewKey.ElementAt(counter), new Tuple<int, int>(i, j));
                        text.Add(NewKey.ElementAt(counter));
                        counter++;
                    }
                }

                Matrix.Add(text);
            }

            //start enctyption 

            // Add (x) between 2 double letters (Same Characters) 
            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Insert(i + 1, "x");
                }
            }
            // Add (x) at the end of p.t if its length is odd
            if (plainText.Length % 2 != 0)
            {
                plainText += 'x';
            }

            for (int i = 0; i < plainText.Length; i += 2)
            {
                char c1 = plainText[i];
                char c2 = plainText[i + 1];

                // c1,c2 are in the same Row
                if (letters[c1].Item1 == letters[c2].Item1)
                {
                    CipherText += Matrix[letters[c1].Item1][(letters[c1].Item2 + 1) % 5];
                    CipherText += Matrix[letters[c2].Item1][(letters[c2].Item2 + 1) % 5];
                }
                // c1,c2 are in the same Column
                else if (letters[c1].Item2 == letters[c2].Item2)
                {
                    CipherText += Matrix[(letters[c1].Item1 + 1) % 5][letters[c1].Item2];
                    CipherText += Matrix[(letters[c2].Item1 + 1) % 5][letters[c2].Item2];
                }
                // c1,c2 are in different Row & Column (Take the intersection)
                else
                {
                    CipherText += Matrix[letters[c1].Item1][letters[c2].Item2];
                    CipherText += Matrix[letters[c2].Item1][letters[c1].Item2];
                }

            }

            return CipherText.ToUpper();

        }
    }
}
