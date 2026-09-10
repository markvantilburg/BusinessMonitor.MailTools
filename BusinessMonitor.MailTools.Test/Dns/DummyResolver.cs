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
            TextLookups = new List<string>();
            AddressLookups = new List<string>();
            MailLookups = new List<string>();
        }

        /// <summary>
        /// The names passed to GetTextRecords, in order
        /// </summary>
        public List<string> TextLookups { get; }

        /// <summary>
        /// The names passed to GetAddressRecords, in order
        /// </summary>
        public List<string> AddressLookups { get; }

        /// <summary>
        /// The names passed to GetMailRecords, in order
        /// </summary>
        public List<string> MailLookups { get; }

        /// <summary>
        /// When set, a lookup without results returns null instead of an empty array,
        /// mimicking resolver implementations that do so
        /// </summary>
        public bool ReturnNullWhenEmpty { get; set; }

        public DummyResolver(string domain, string value) : this()
        {
            AddText(domain, value);
        }

        public DummyResolver(string domain, string[] value) : this()
        {
            foreach (string x in value)
            {
                AddText(domain, x);
            }
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
            TextLookups.Add(domain);

            return NullWhenEmpty(_records.Where(x => x.Domain == domain && x.Type == DnsType.TXT).Select(x => x.Value).ToArray());
        }

        public IPAddress[] GetAddressRecords(string domain)
        {
            AddressLookups.Add(domain);

            return NullWhenEmpty(_records.Where(x => x.Domain == domain && x.Type == DnsType.A).Select(x => x.Address).ToArray());
        }

        public string[] GetMailRecords(string domain)
        {
            MailLookups.Add(domain);

            return NullWhenEmpty(_records.Where(x => x.Domain == domain && x.Type == DnsType.MX).Select(x => x.Value).ToArray());
        }

        private T[] NullWhenEmpty<T>(T[] result)
        {
            return ReturnNullWhenEmpty && result.Length == 0 ? null : result;
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
