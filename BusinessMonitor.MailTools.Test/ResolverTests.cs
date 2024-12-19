using BusinessMonitor.MailTools.Dns;
using NUnit.Framework;
using System.Linq;
using System.Net;

namespace BusinessMonitor.MailTools.Test
{
    internal class ResolverTests
    {
        [Test]
        public void TestTextLookup()
        {
            var address = IPAddress.Parse("1.1.1.1"); // Cloudflare DNS

            var resolver = new DnsResolver(address);
            var records = resolver.GetTextRecords("businessmonitor.nl");

            Assert.That(records.Length, Is.GreaterThan(0));
            Assert.That(records.Any(x => x.StartsWith("MS=")), Is.True);
        }

        [Test]
        public void TestAddressLookup()
        {
            var address = IPAddress.Parse("1.1.1.1"); // Cloudflare DNS

            var resolver = new DnsResolver(address);
            var records = resolver.GetAddressRecords("one.one.one.one");

            Assert.That(records.Length, Is.GreaterThan(0));
            Assert.That(records.Any(x => x.Equals(IPAddress.Parse("1.1.1.1"))), Is.True);
        }

        [Test]
        public void TestMailLookup()
        {
            var address = IPAddress.Parse("1.1.1.1"); // Cloudflare DNS

            var resolver = new DnsResolver(address);
            var records = resolver.GetMailRecords("businessmonitor.nl");

            Assert.That(records.Length, Is.GreaterThan(0));
            Assert.That(records, Has.Some.Matches<string>(x => x.EndsWith("mail.protection.outlook.com") || x.EndsWith("mail.protection.outlook.com.")));
        }
    }
}
