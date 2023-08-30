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
            var records = response.Answers
                .Where(record => record.Type == DnsType.TXT)
                .Select(record => (record.Record as TXTRecord).Value);

            return records.ToArray();
        }

        public IPAddress[] GetAddressRecords(string domain)
        {
            // A for now, Bdev.Net.Dns does not seem to support AAAA
            var response = Resolver.Lookup(domain, DnsType.A, _address);
            var records = response.Answers
                .Where(record => record.Type == DnsType.A)
                .Select(record => (record.Record as ANameRecord).IPAddress);

            return records.ToArray();
        }

        public string[] GetMailRecords(string domain)
        {
            var response = Resolver.Lookup(domain, DnsType.MX, _address);
            var records = response.Answers
                .Where(record => record.Type == DnsType.MX)
                .Select(record => (record.Record as MXRecord).DomainName);

            return records.ToArray();
        }
    }
}
