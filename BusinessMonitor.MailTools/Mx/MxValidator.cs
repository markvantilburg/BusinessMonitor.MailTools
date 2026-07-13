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
                       || b[0] >= 224;                               // multicast/reserved
            }

            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                return ip.Equals(IPAddress.IPv6Any)               // ::
                       || ip.IsIPv6LinkLocal                         // fe80::/10
                       || ip.IsIPv6SiteLocal                         // fec0::/10 (deprecated)
                       || ip.IsIPv6Multicast                         // ff00::/8
                       || (ip.GetAddressBytes()[0] & 0xFE) == 0xFC;  // fc00::/7 (unique local)
            }

            return true; // unknown address family — treat as invalid
        }
    }
}