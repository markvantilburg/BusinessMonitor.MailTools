using BusinessMonitor.MailTools.Dns;
using System;
using System.Collections.Generic;
using System.Net;

namespace BusinessMonitor.MailTools.Test.Dns
{
    internal class DummyResolver : IResolver
    {
        // Simple dictionary of domains, only supports only record per domain
        private Dictionary<string, string> _records;

        public DummyResolver()
        {
            _records = new Dictionary<string, string>();
        }

        public DummyResolver(string domain, string value) : this()
        {
            _records[domain] = value;
        }

        public void AddDomain(string domain, string value)
        {
            _records[domain] = value;
        }

        public string[] GetTextRecords(string domain)
        {
            if (_records.TryGetValue(domain, out var value))
            {
                return new string[] { value };
            }

            return new string[0];
        }

        public IPAddress[] GetAddressRecords(string domain)
        {
            throw new NotImplementedException();
        }

        public string[] GetMailRecords(string domain)
        {
            throw new NotImplementedException();
        }
    }
}
