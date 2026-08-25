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

            // SubjectPublicKeyInfo sequence, must span the whole key without trailing data
            if (!TryReadTag(data, ref pos, data.Length, 0x30, out var end)) return false;
            if (end != data.Length) return false;

            // AlgorithmIdentifier sequence, must contain the rsaEncryption identifier
            if (!TryReadTag(data, ref pos, end, 0x30, out var algorithmEnd)) return false;
            if (!TryReadTag(data, ref pos, algorithmEnd, 0x06, out var oidEnd)) return false;
            if (!Matches(data, pos, oidEnd - pos, RsaEncryptionOid)) return false;

            pos = oidEnd;

            // The algorithm parameters must be absent or a single null value
            if (pos != algorithmEnd)
            {
                if (algorithmEnd - pos != 2 || data[pos] != 0x05 || data[pos + 1] != 0x00) return false;

                pos = algorithmEnd;
            }

            // Bit string containing the RSA public key, must fill the rest of the
            // structure, skip the unused bits octet
            if (!TryReadTag(data, ref pos, end, 0x03, out var bitEnd)) return false;
            if (bitEnd != end) return false;
            if (pos >= bitEnd || data[pos] != 0x00) return false;

            pos++;

            // RSAPublicKey sequence with the modulus and exponent integers
            if (!TryReadTag(data, ref pos, bitEnd, 0x30, out var keyEnd)) return false;
            if (keyEnd != bitEnd) return false;
            if (!TryReadTag(data, ref pos, keyEnd, 0x02, out var modulusEnd)) return false;

            // The modulus must be a positive integer with a minimal encoding, a single
            // leading zero byte is only allowed when the next byte has its high bit set
            if (pos == modulusEnd) return false;

            if (data[pos] == 0x00)
            {
                pos++;

                if (pos == modulusEnd || (data[pos] & 0x80) == 0) return false;
            }
            else if ((data[pos] & 0x80) != 0)
            {
                return false;
            }

            var first = (int)data[pos];
            var firstBits = 0;

            while (first != 0)
            {
                firstBits++;
                first >>= 1;
            }

            bits = (modulusEnd - pos - 1) * 8 + firstBits;

            // The exponent integer must fill the rest of the key
            pos = modulusEnd;

            if (!TryReadTag(data, ref pos, keyEnd, 0x02, out var exponentEnd)) return false;
            if (exponentEnd != keyEnd) return false;
            if (pos == exponentEnd) return false;

            return true;
        }

        /// <summary>
        /// Reads a DER tag and its length, the value must fit within the parent limit,
        /// leaves the position at the start of the value and returns the end offset of the value
        /// </summary>
        private static bool TryReadTag(byte[] data, ref int pos, int limit, byte tag, out int end)
        {
            end = 0;

            if (pos >= limit || data[pos] != tag) return false;
            pos++;

            if (pos >= limit) return false;
            int length = data[pos++];

            // Long form length, must use the minimal number of octets
            if (length > 0x7F)
            {
                var octets = length & 0x7F;
                if (octets == 0 || octets > 4) return false;

                if (pos >= limit || data[pos] == 0x00) return false;

                length = 0;

                for (var i = 0; i < octets; i++)
                {
                    if (pos >= limit) return false;

                    length = (length << 8) | data[pos++];
                }

                if (length < 0x80) return false;
            }

            if (length < 0 || (long)pos + length > limit) return false;

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
