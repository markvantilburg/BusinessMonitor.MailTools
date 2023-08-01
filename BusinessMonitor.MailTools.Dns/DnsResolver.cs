using Bdev.Net.Dns;
using Bdev.Net.Dns.Records;
using System.Linq;
using System.Net;

namespace BusinessMonitor.MailTools.Dns
{
    /// <summary>
    /// DNS resolver using Bdev.Net.Dns
    /// </summary>
    public class DnsResolver : IResolver
    {
        private readonly IPAddress _address;

        /// <summary>
        /// Initializes a new DNS resolver
        /// </summary>
        /// <param name="address">The IP address of the DNS server, null will use the default</param>
        public DnsResolver(IPAddress address = null)
        {
            _address = address;
        }

        public string[] GetTextRecords(string domain)
        {
            var response = Resolver.Lookup(domain, DnsType.TXT, _address);
            var records = response.Answers.Select(record => (record.Record as TXTRecord).Value);

            return records.ToArray();
        }
    }
}
