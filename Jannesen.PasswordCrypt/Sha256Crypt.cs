using System;
using System.Security.Cryptography;
using System.Text;

namespace Jannesen.PasswordCrypt
{
    public class Sha256Crypt: ShaCrypt
    {
        public  override            string          StartWith   => "$5$";

        internal override           HashAlgorithm   createHashAlgorithm()
        {
            return System.Security.Cryptography.SHA256.Create();
        }
        internal override           void            fillBytes(StringBuilder sb, byte[] bhash)
        {
            base64TripetFill(sb, bhash[00], bhash[10], bhash[20]);
            base64TripetFill(sb, bhash[21], bhash[01], bhash[11]);
            base64TripetFill(sb, bhash[12], bhash[22], bhash[02]);
            base64TripetFill(sb, bhash[03], bhash[13], bhash[23]);
            base64TripetFill(sb, bhash[24], bhash[04], bhash[14]);
            base64TripetFill(sb, bhash[15], bhash[25], bhash[05]);
            base64TripetFill(sb, bhash[06], bhash[16], bhash[26]);
            base64TripetFill(sb, bhash[27], bhash[07], bhash[17]);
            base64TripetFill(sb, bhash[18], bhash[28], bhash[08]);
            base64TripetFill(sb, bhash[09], bhash[19], bhash[29]);
            base64TripetFill(sb, bhash[31], bhash[30]);
        }
    }
}
