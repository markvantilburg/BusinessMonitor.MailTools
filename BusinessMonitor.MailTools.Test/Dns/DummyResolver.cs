using Bdev.Net.Dns;
using BusinessMonitor.MailTools.Dns;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace BusinessMonitor.MailTools.Test.Dns
{
    internal class DummyResolver : IResolver
    {
        private List<Record> _records;

        public DummyResolver()
        {
            _records = new List<Record>();
        }

        public DummyResolver(string domain, string value) : this()
        {
            AddText(domain, value);
        }

        public DummyResolver(string domain, IPAddress address) : this()
        {
            AddAddress(domain, address);
        }

        public void AddText(string domain, string value)
        {
            _records.Add(new Record { Domain = domain, Type = DnsType.TXT, Value = value });
        }

        public void AddAddress(string domain, IPAddress address)
        {
            _records.Add(new Record { Domain = domain, Type = DnsType.A, Address = address });
        }

        public void AddMail(string domain, string value)
        {
            _records.Add(new Record { Domain = domain, Type = DnsType.MX, Value = value });
        }

        public string[] GetTextRecords(string domain)
        {
            return _records.Where(x => x.Domain == domain && x.Type == DnsType.TXT).Select(x => x.Value).ToArray();
        }

        public IPAddress[] GetAddressRecords(string domain)
        {
            return _records.Where(x => x.Domain == domain && x.Type == DnsType.A).Select(x => x.Address).ToArray();

        }

        public string[] GetMailRecords(string domain)
        {
            return _records.Where(x => x.Domain == domain && x.Type == DnsType.MX).Select(x => x.Value).ToArray();
        }

        private class Record
        {
            public string Domain { get; set; }
            public DnsType Type { get; set; }

            public string Value { get; set; }
            public IPAddress Address { get; set; }
        }
    }
}
