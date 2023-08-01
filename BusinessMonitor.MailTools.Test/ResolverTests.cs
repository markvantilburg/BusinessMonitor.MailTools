using BusinessMonitor.MailTools.Dns;
using NUnit.Framework;
using System.Linq;
using System.Net;

namespace BusinessMonitor.MailTools.Test
{
    internal class ResolverTests
    {
        [Test]
        public void TestLookup()
        {
            var resolver = new DnsResolver();
            var records = resolver.GetTextRecords("businessmonitor.nl");

            Assert.Greater(records.Length, 0);
            Assert.IsTrue(records.Any(x => x.StartsWith("google-site-verification=")));
        }

        [Test]
        public void TestServerLookup()
        {
            var address = IPAddress.Parse("1.1.1.1"); // Cloudflare DNS

            var resolver = new DnsResolver(address);
            var records = resolver.GetTextRecords("businessmonitor.nl");

            Assert.Greater(records.Length, 0);
            Assert.IsTrue(records.Any(x => x.StartsWith("google-site-verification=")));
        }
    }
}
