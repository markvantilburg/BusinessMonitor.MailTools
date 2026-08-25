#if NET5_0_OR_GREATER
using System.Security.Cryptography;
#endif

namespace BusinessMonitor.MailTools.Dkim
{
    /// <summary>
    /// Minimal DER reader for RSA public keys in DKIM records
    /// </summary>
    internal static class DkimKeyReader
    {
#if NET5_0_OR_GREATER
        /// <summary>
        /// Parses a DER encoded SubjectPublicKeyInfo structure containing an RSA public key
        /// and gets the modulus size in bits, returns false when the data is not a valid RSA public key
        /// </summary>
        internal static bool TryGetRsaModulusBits(byte[] data, out int bits)
        {
            bits = 0;

            try
            {
                using var rsa = RSA.Create();

                rsa.ImportSubjectPublicKeyInfo(data, out var read);

                // The key must not contain trailing data
                if (read != data.Length)
                {
                    return false;
                }

                bits = rsa.KeySize;

                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }
#else
        /// <summary>
        /// The rsaEncryption object identifier, 1.2.840.113549.1.1.1
        /// </summary>
        private static readonly byte[] RsaEncryptionOid = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

        /// <summary>
        /// Parses a DER encoded SubjectPublicKeyInfo structure containing an RSA public key
        /// and gets the modulus size in bits, returns false when the data is not a valid RSA public key
        /// </summary>
        internal static bool TryGetRsaModulusBits(byte[] data, out int bits)
        {
            bits = 0;
            var pos = 0;

            // SubjectPublicKeyInfo sequence
            if (!TryReadTag(data, ref pos, 0x30, out _)) return false;

            // AlgorithmIdentifier sequence, must contain the rsaEncryption identifier
            if (!TryReadTag(data, ref pos, 0x30, out var algorithmEnd)) return false;
            if (!TryReadTag(data, ref pos, 0x06, out var oidEnd)) return false;
            if (!Matches(data, pos, oidEnd - pos, RsaEncryptionOid)) return false;

            pos = algorithmEnd;

            // Bit string containing the RSA public key, skip the unused bits octet
            if (!TryReadTag(data, ref pos, 0x03, out _)) return false;
            if (pos >= data.Length || data[pos] != 0x00) return false;

            pos++;

            // RSAPublicKey sequence with the modulus integer
            if (!TryReadTag(data, ref pos, 0x30, out _)) return false;
            if (!TryReadTag(data, ref pos, 0x02, out var modulusEnd)) return false;

            // Strip leading zero bytes and compute the modulus bit length
            while (pos < modulusEnd && data[pos] == 0x00) pos++;
            if (pos == modulusEnd) return false;

            var first = (int)data[pos];
            var firstBits = 0;

            while (first != 0)
            {
                firstBits++;
                first >>= 1;
            }

            bits = (modulusEnd - pos - 1) * 8 + firstBits;

            return true;
        }

        /// <summary>
        /// Reads a DER tag and its length, leaves the position at the start of the value
        /// and returns the end offset of the value
        /// </summary>
        private static bool TryReadTag(byte[] data, ref int pos, byte tag, out int end)
        {
            end = 0;

            if (pos >= data.Length || data[pos] != tag) return false;
            pos++;

            if (pos >= data.Length) return false;
            int length = data[pos++];

            // Long form length
            if (length > 0x7F)
            {
                var octets = length & 0x7F;
                if (octets == 0 || octets > 4) return false;

                length = 0;

                for (var i = 0; i < octets; i++)
                {
                    if (pos >= data.Length) return false;

                    length = (length << 8) | data[pos++];
                }
            }

            if (length < 0 || (long)pos + length > data.Length) return false;

            end = pos + length;

            return true;
        }

        private static bool Matches(byte[] data, int offset, int length, byte[] expected)
        {
            if (length != expected.Length) return false;

            for (var i = 0; i < length; i++)
            {
                if (data[offset + i] != expected[i]) return false;
            }

            return true;
        }
#endif
    }
}
