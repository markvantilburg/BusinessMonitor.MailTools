using System.Net;
using System.Net.Sockets;

namespace BusinessMonitor.MailTools.Util
{
    internal static class IPAddressHelper
    {
        /// <summary>
        /// Is the ip address in the range
        /// </summary>
        /// <param name="address">The address to check</param>
        /// <param name="network">The network the address should be a part of</param>
        /// <param name="length">Total range of the network</param>
        /// <returns></returns>
        internal static bool IsInRange(IPAddress address, IPAddress network, int length)
        {
            if (address.AddressFamily != network.AddressFamily)
            {
                return false;
            }

            var addressBytes = address.GetAddressBytes();
            var networkBytes = network.GetAddressBytes();

            if (length < 0 || length > addressBytes.Length * 8)
            {
                return false;
            }

            // Compare the whole bytes of the prefix, the host bits are ignored so an
            // unaligned base like 192.168.0.1/24 behaves as 192.168.0.0/24
            var bytes = length / 8;

            for (var i = 0; i < bytes; i++)
            {
                if (addressBytes[i] != networkBytes[i])
                {
                    return false;
                }
            }

            // Compare the remaining bits of the prefix
            var bits = length % 8;

            if (bits == 0)
            {
                return true;
            }

            var mask = (byte)(0xFF << (8 - bits));

            return (addressBytes[bytes] & mask) == (networkBytes[bytes] & mask);
        }

        /// <summary>
        /// Checks whether an address is not routable on the public internet, such as loopback, private,
        /// link-local, documentation and multicast ranges, IPv6 transition addresses are checked on the
        /// IPv4 address they embed
        /// </summary>
        internal static bool IsNonRoutable(IPAddress ip)
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
