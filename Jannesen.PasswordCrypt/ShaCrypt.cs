using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Jannesen.PasswordCrypt
{
    public abstract class ShaCrypt: IPasswordHash
    {
        private const               int             DefaultShaIterationCount = 5000;
        private static readonly     char[]          _base64Characters = new char[] { '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

        public  abstract            string          StartWith   { get; }

        public                      string          Create(string password)
        {
            return Create(password, DefaultShaIterationCount);
        }
        public                      string          Create(string password, int iterationCount)
        {
            return Create(Encoding.UTF8.GetBytes(password), iterationCount);
        }
        public                      string          Create(byte[] password, int iterationCount)
        {
            if (iterationCount == 0) iterationCount = DefaultShaIterationCount;

            var salt  = _create_salt();
            var bhash = _createHash(password, salt, iterationCount);

            var sb = new StringBuilder();
            sb.Append(StartWith);
            if (iterationCount != DefaultShaIterationCount) {
                sb.Append("rounds=");
                sb.Append(iterationCount);
                sb.Append('$');
            }
            sb.Append(Encoding.ASCII.GetString(salt));
            sb.Append('$');
        
            fillBytes(sb, bhash);

            return sb.ToString();
        }

        public                      bool            Verify(string password, string passwordHash)
        {
            return Verify(Encoding.UTF8.GetBytes(password), passwordHash);
        }
        public                      bool            Verify(byte[] password, string passwordHash)
        {
            if (passwordHash != null && passwordHash.StartsWith(StartWith)) {
                var hashparts = passwordHash.Split('$');

                var    iterationCount = 0;
                byte[] salt           = null;
                string hash           = null;

                if (hashparts.Length == 4) {
                    iterationCount = DefaultShaIterationCount;
                    salt = Encoding.ASCII.GetBytes(hashparts[2]);
                    hash = hashparts[3];
                }
                else if (hashparts.Length == 5 && hashparts[2].StartsWith("rounds=", StringComparison.Ordinal)) {
                    if (int.TryParse(hashparts[2].Substring(7), NumberStyles.Integer, CultureInfo.InvariantCulture, out iterationCount)) {
                        salt = Encoding.ASCII.GetBytes(hashparts[3]);
                        hash = hashparts[4];
                    }
                }
            
                if (iterationCount > 0 && salt != null && hash != null) {
                    var sb = new StringBuilder();
                    fillBytes(sb, _createHash(password, salt, iterationCount));
                    return sb.ToString() == hash;
                }
            }

            return false;
        }

        internal abstract           HashAlgorithm   createHashAlgorithm();
        internal abstract           void            fillBytes(StringBuilder sb, byte[] bytes);

        private static              byte[]          _create_salt()
        {
            var salt = new byte[16];
            using (var g = RandomNumberGenerator.Create()) {
                g.GetBytes(salt);
            }
            for (var i = 0; i < salt.Length; i++) {  // make it an ascii
                salt[i] = (byte)_base64Characters[salt[i] % _base64Characters.Length];
            }

            return salt;
        }
        private                     byte[]          _createHash(byte[] password, byte[] salt, int iterationCount)
        {
            byte[] hashA;

            using (var digestA = createHashAlgorithm()) {    // step 1
                _addDigest(digestA, password);  // step 2
                _addDigest(digestA, salt);      // step 3

                byte[] hashB;
                using (var digestB = createHashAlgorithm()) {  // step 4
                    _addDigest(digestB, password);   // step 5
                    _addDigest(digestB, salt);       // step 6
                    _addDigest(digestB, password);   // step 7
                    hashB = _finishDigest(digestB);  // step 8
                    _addRepeatedDigest(digestA, hashB, password.Length);  // step 9/10
                }

                var passwordLenght = password.Length;
                while (passwordLenght > 0) {                // step 11
                    if ((passwordLenght & 0x01) != 0) {     // bit 1
                        _addDigest(digestA, hashB);
                    } else {                                // bit 0
                        _addDigest(digestA, password);
                    }
                    passwordLenght >>= 1;
                }
                hashA = _finishDigest(digestA);             // step 12
            }

            byte[] hashAC;

            using (var digestDP = createHashAlgorithm()) {    // step 13
                for (var i = 0; i < password.Length; i++) {                                         // step 14
                    _addDigest(digestDP, password);
                }
            
                var hashDP = _finishDigest(digestDP);               // step 15
                var p = _produceBytes(hashDP, password.Length);     // step 16

                byte[] hashDS;
                using (var digestDS = createHashAlgorithm()) {  // step 17
                    for (var i = 0; i < (16 + hashA[0]); i++) {  // step 18
                        _addDigest(digestDS, salt);
                    }
                    hashDS = _finishDigest(digestDS);  // step 19
                }
                var s = _produceBytes(hashDS, salt.Length);  // step 20

                hashAC = hashA;
                for (var i = 0; i < iterationCount; i++) {  // step 21
                    using (var digestC = createHashAlgorithm()) {   // step 21a
                        if ((i % 2) == 1) {  // step 21b
                            _addDigest(digestC, p);
                        } else {  // step 21c
                            _addDigest(digestC, hashAC);
                        }
                        if ((i % 3) != 0) { _addDigest(digestC, s); }  // step 21d
                        if ((i % 7) != 0) { _addDigest(digestC, p); }  // step 21e
                        if ((i % 2) == 1) {  // step 21f
                            _addDigest(digestC, hashAC);
                        } else {  // step 21g
                            _addDigest(digestC, p);
                        }
                        hashAC = _finishDigest(digestC);  // step 21h
                    }
                }
            }

            return hashAC;
        }
        private static              void            _addDigest(HashAlgorithm digest, byte[] bytes)
        {
            if (bytes.Length == 0) { return; }
            var hashLen   = digest.HashSize / 8;
            var offset    = 0;
            var remaining = bytes.Length;

            while (remaining > 0) {
                digest.TransformBlock(bytes, offset, (remaining >= hashLen) ? hashLen : remaining, null, 0);
                remaining -= hashLen;
                offset += hashLen;
            }
        }
        private static              void            _addRepeatedDigest(HashAlgorithm digest, byte[] bytes, int length)
        {
            var hashLen = digest.HashSize / 8;
            while (length > 0) {
                digest.TransformBlock(bytes, 0, (length >= hashLen) ? hashLen : length, null, 0);
                length -= hashLen;
            }
        }
        private static              byte[]          _produceBytes(byte[] hash, int lenght)
        {
            var hashLen  = hash.Length;
            var produced = new byte[lenght];
            var offset   = 0;
            while (lenght > 0) {
                Buffer.BlockCopy(hash, 0, produced, offset, (lenght >= hashLen) ? hashLen : lenght);
                offset += hashLen;
                lenght -= hashLen;
            }

            return produced;
        }
        private static              byte[]          _finishDigest(HashAlgorithm digest)
        {
            digest.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return digest.Hash ?? Array.Empty<byte>();
        }

        internal static             void            base64TripetFill(StringBuilder sb, byte byte2, byte byte1, byte byte0)
        {
            sb.Append(_base64Characters[byte0 & 0x3F]);
            sb.Append(_base64Characters[((byte1 & 0x0F) << 2) | (byte0 >> 6)]);
            sb.Append(_base64Characters[((byte2 & 0x03) << 4) | (byte1 >> 4)]);
            sb.Append(_base64Characters[byte2 >> 2]);
        }
        internal static             void            base64TripetFill(StringBuilder sb, byte byte1, byte byte0)
        {
            sb.Append(_base64Characters[byte0 & 0x3F]);
            sb.Append(_base64Characters[((byte1 & 0x0F) << 2) | (byte0 >> 6)]);
            sb.Append(_base64Characters[byte1 >> 4]);
        }
        internal static             void            base64TripetFill(StringBuilder sb, byte byte0)
        {
            sb.Append(_base64Characters[byte0 & 0x3F]);
            sb.Append(_base64Characters[byte0 >> 6]);
        }
    }
}