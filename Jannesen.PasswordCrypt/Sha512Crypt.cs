using System;
using System.Security.Cryptography;
using System.Text;

namespace Jannesen.PasswordCrypt
{
    public class Sha512Crypt: ShaCrypt
    {
        public  override            string          StartWith   => "$6$";

        internal override           HashAlgorithm   createHashAlgorithm()
        {
            return System.Security.Cryptography.SHA512.Create();
        }
        internal override           void            fillBytes(StringBuilder sb, byte[] bhash)
        {
            base64TripetFill(sb, bhash[00], bhash[21], bhash[42]);
            base64TripetFill(sb, bhash[22], bhash[43], bhash[01]);
            base64TripetFill(sb, bhash[44], bhash[02], bhash[23]);
            base64TripetFill(sb, bhash[03], bhash[24], bhash[45]);
            base64TripetFill(sb, bhash[25], bhash[46], bhash[04]);
            base64TripetFill(sb, bhash[47], bhash[05], bhash[26]);
            base64TripetFill(sb, bhash[06], bhash[27], bhash[48]);
            base64TripetFill(sb, bhash[28], bhash[49], bhash[07]);
            base64TripetFill(sb, bhash[50], bhash[08], bhash[29]);
            base64TripetFill(sb, bhash[09], bhash[30], bhash[51]);
            base64TripetFill(sb, bhash[31], bhash[52], bhash[10]);
            base64TripetFill(sb, bhash[53], bhash[11], bhash[32]);
            base64TripetFill(sb, bhash[12], bhash[33], bhash[54]);
            base64TripetFill(sb, bhash[34], bhash[55], bhash[13]);
            base64TripetFill(sb, bhash[56], bhash[14], bhash[35]);
            base64TripetFill(sb, bhash[15], bhash[36], bhash[57]);
            base64TripetFill(sb, bhash[37], bhash[58], bhash[16]);
            base64TripetFill(sb, bhash[59], bhash[17], bhash[38]);
            base64TripetFill(sb, bhash[18], bhash[39], bhash[60]);
            base64TripetFill(sb, bhash[40], bhash[61], bhash[19]);
            base64TripetFill(sb, bhash[62], bhash[20], bhash[41]);
            base64TripetFill(sb, bhash[63]);
        }
    }
}