using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;

namespace BusinessMonitor.MailTools.Mx
{
    public class MxValidator
    {
        /// <summary>
        /// The maximum number of MX records that will be resolved for a domain (normally maximum is 5)
        /// </summary>
        private const int MaxMxRecords = 10;

        private readonly IResolver _resolver;

        public MxValidator(IResolver resolver)
        {
            if (resolver == null)
            {
                throw new ArgumentNullException(nameof(resolver));
            }

            _resolver = resolver;
        }

        public class MxValidationResult
        {
            public bool HasMxRecords { get; set; }
            public List<string> InvalidMxRecords { get; set; }

            public MxValidationResult()
            {
                InvalidMxRecords = new List<string>();
            }
        }

        /// <exception cref="MxException">The domain has more than 10 MX records</exception>
        public MxValidationResult ValidateMxRecords(string domain)
        {
            var result = new MxValidationResult();
            var mxRecords = _resolver.GetMailRecords(domain);
            if (mxRecords == null || mxRecords.Length == 0)
            {
                result.HasMxRecords = false;
                return result;
            }

            if (mxRecords.Length > MaxMxRecords)
            {
                throw new MxException($"Domain exceeds max MX records of {MaxMxRecords}");
            }

            result.HasMxRecords = true;
            foreach (var mxRecord in mxRecords)
            {
                IPAddress[] ipAddresses = _resolver.GetAddressRecords(mxRecord);
                if (ipAddresses != null && ipAddresses.Any(IsNonRoutable))
                {
                    result.InvalidMxRecords.Add(mxRecord);
                }
            }

            return result;
        }

        private static bool IsNonRoutable(IPAddress ip)
        {
            // Unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d) so the IPv4 checks apply
            if (ip.IsIPv4MappedToIPv6)
            {
                ip = ip.MapToIPv4();
            }

            if (IPAddress.IsLoopback(ip)) // 127.0.0.0/8 and ::1
                return true;

            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                return IsNonRoutableV4(ip.GetAddressBytes());
            }

            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                byte[] b = ip.GetAddressBytes();

                if (ip.Equals(IPAddress.IPv6Any)               // ::
                    || ip.IsIPv6LinkLocal                         // fe80::/10
                    || ip.IsIPv6SiteLocal                         // fec0::/10 (deprecated)
                    || ip.IsIPv6Multicast                         // ff00::/8
                    || (b[0] & 0xFE) == 0xFC                      // fc00::/7 (unique local)
                    || (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) // 2001:db8::/32 (documentation)
                    || IsZero(b, 0, 12))                          // ::/96 IPv4-compatible (deprecated, never routed)
                {
                    return true;
                }

                // Transition addresses embed an IPv4 address, apply the IPv4 checks to it
                var embedded = GetEmbeddedIPv4(b);

                if (embedded != null)
                {
                    return IsNonRoutableV4(embedded);
                }

                return false;
            }

            return true; // unknown address family — treat as invalid
        }

        private static bool IsNonRoutableV4(byte[] b)
        {
            return b[0] == 0                                  // 0.0.0.0/8
                   || b[0] == 10                                 // 10.0.0.0/8
                   || b[0] == 127                                // 127.0.0.0/8 (loopback)
                   || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)  // 172.16.0.0/12
                   || (b[0] == 192 && b[1] == 168)               // 192.168.0.0/16
                   || (b[0] == 169 && b[1] == 254)               // 169.254.0.0/16 (link-local)
                   || (b[0] == 100 && b[1] >= 64 && b[1] <= 127) // 100.64.0.0/10 (CGNAT)
                   || (b[0] == 192 && b[1] == 0 && b[2] == 0)    // 192.0.0.0/24 (IETF protocol assignments)
                   || (b[0] == 192 && b[1] == 0 && b[2] == 2)    // 192.0.2.0/24 (TEST-NET-1)
                   || (b[0] == 198 && b[1] == 51 && b[2] == 100) // 198.51.100.0/24 (TEST-NET-2)
                   || (b[0] == 203 && b[1] == 0 && b[2] == 113)  // 203.0.113.0/24 (TEST-NET-3)
                   || (b[0] == 198 && (b[1] == 18 || b[1] == 19))// 198.18.0.0/15 (benchmarking)
                   || b[0] >= 224;                               // multicast/reserved
        }

        /// <summary>
        /// Gets the IPv4 address embedded in an IPv6 transition address, null when the address embeds none
        /// </summary>
        private static byte[] GetEmbeddedIPv4(byte[] b)
        {
            // 6to4 2002:a.b.c.d::/48, the IPv4 address follows the prefix (RFC 3056)
            if (b[0] == 0x20 && b[1] == 0x02)
            {
                return new[] { b[2], b[3], b[4], b[5] };
            }

            // Teredo 2001::/32, the client IPv4 address is the inverted last 32 bits (RFC 4380)
            if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00)
            {
                return new[] { (byte)~b[12], (byte)~b[13], (byte)~b[14], (byte)~b[15] };
            }

            // NAT64 64:ff9b::/96, the IPv4 address is the last 32 bits (RFC 6052)
            if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B && IsZero(b, 4, 12))
            {
                return new[] { b[12], b[13], b[14], b[15] };
            }

            return null;
        }

        private static bool IsZero(byte[] b, int start, int end)
        {
            for (var i = start; i < end; i++)
            {
                if (b[i] != 0) return false;
            }

            return true;
        }
    }
}