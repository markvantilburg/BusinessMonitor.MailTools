using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using BusinessMonitor.MailTools.Dns;

namespace BusinessMonitor.MailTools.Mx
{
    public class MxValidator
    {
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

        public MxValidationResult ValidateMxRecords(string domain)
        {
            var result = new MxValidationResult();
            var mxRecords = _resolver.GetMailRecords(domain);
            if (mxRecords == null || mxRecords.Length == 0)
            {
                result.HasMxRecords = false;
                return result;
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
                byte[] b = ip.GetAddressBytes();

                return b[0] == 0                                  // 0.0.0.0/8
                       || b[0] == 10                                 // 10.0.0.0/8
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

            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                byte[] b = ip.GetAddressBytes();

                return ip.Equals(IPAddress.IPv6Any)               // ::
                       || ip.IsIPv6LinkLocal                         // fe80::/10
                       || ip.IsIPv6SiteLocal                         // fec0::/10 (deprecated)
                       || ip.IsIPv6Multicast                         // ff00::/8
                       || (b[0] & 0xFE) == 0xFC                      // fc00::/7 (unique local)
                       || (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8); // 2001:db8::/32 (documentation)
            }

            return true; // unknown address family — treat as invalid
        }
    }
}