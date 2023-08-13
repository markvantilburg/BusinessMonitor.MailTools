using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Spf;
using BusinessMonitor.MailTools.Test.Dns;
using NUnit.Framework;
using System.Linq;
using System.Net;

namespace BusinessMonitor.MailTools.Test
{
    internal class SpfTests
    {
        [Test]
        public void TestParse()
        {
            var record = SpfCheck.ParseSpfRecord("v=spf1 ip4:192.0.2.1 ip4:192.0.2.129 -all");

            Assert.IsNotNull(record);
            Assert.AreEqual(3, record.Directives.Count);

            SpfDirective directive;

            // ip4:192.0.2.1
            directive = record.Directives[0];

            Assert.AreEqual(SpfQualifier.Pass, directive.Qualifier);
            Assert.AreEqual(SpfMechanism.IP4, directive.Mechanism);
            Assert.IsNotNull(directive.IP4);
            Assert.AreEqual("192.0.2.1", directive.IP4.ToString());

            // ip4:192.0.2.129
            directive = record.Directives[1];

            Assert.AreEqual(SpfQualifier.Pass, directive.Qualifier);
            Assert.AreEqual(SpfMechanism.IP4, directive.Mechanism);
            Assert.IsNotNull(directive.IP4);
            Assert.AreEqual("192.0.2.129", directive.IP4.ToString());

            // -all
            directive = record.Directives[2];

            Assert.AreEqual(SpfQualifier.Fail, directive.Qualifier);
            Assert.AreEqual(SpfMechanism.All, directive.Mechanism);
        }

        [Test]
        public void TestAddress()
        {
            var record = SpfCheck.ParseSpfRecord("v=spf1 ip4:192.0.2.0/24 ip4:192.0.2.0 ip6:2001:db8::/32");

            Assert.IsNotNull(record);

            SpfDirective directive;

            // ip4:192.0.2.0/24
            directive = record.Directives[0];

            Assert.AreEqual("192.0.2.0/24", directive.IP4.ToString());
            Assert.AreEqual("192.0.2.0", directive.IP4.Address.ToString());
            Assert.AreEqual(24, directive.IP4.Length);

            // ip4:192.0.2.0
            directive = record.Directives[1];

            Assert.AreEqual("192.0.2.0", directive.IP4.ToString());
            Assert.AreEqual("192.0.2.0", directive.IP4.Address.ToString());
            Assert.AreEqual(null, directive.IP4.Length);

            // ip4:2001:db8::/32
            directive = record.Directives[2];

            Assert.AreEqual("2001:db8::/32", directive.IP6.ToString());
            Assert.AreEqual("2001:db8::", directive.IP6.Address.ToString());
            Assert.AreEqual(32, directive.IP6.Length);
        }

        [Test]
        public void TestModifiers()
        {
            var record = SpfCheck.ParseSpfRecord("v=spf1 redirect=_spf.example.com");

            Assert.IsNotNull(record);
            Assert.AreEqual(1, record.Modifiers.Count);

            Assert.AreEqual("redirect", record.Modifiers[0].Name);
            Assert.AreEqual("_spf.example.com", record.Modifiers[0].Value);
        }

        [Test]
        [TestCase("")]
        [TestCase("v=spf1 -boop")]
        [TestCase("v=spf1 boop:boop")]
        public void TestInvalid(string value)
        {
            Assert.Throws<InvalidSpfException>(() =>
            {
                SpfCheck.ParseSpfRecord(value);
            });
        }

        [Test]
        public void TestLookup()
        {
            var resolver = new DummyResolver();

            resolver.AddDomain("businessmonitor.nl", "v=spf1 include:survey.businessmonitor.nl -all");
            resolver.AddDomain("survey.businessmonitor.nl", "v=spf1 ip4:192.0.2.1 -all");

            var check = new SpfCheck(resolver);
            var record = check.GetSpfRecord("businessmonitor.nl");

            Assert.IsNotNull(record);
            Assert.IsNotNull(record.Directives[0].Included);

            var included = record.Directives[0].Included;

            Assert.AreEqual(2, included.Directives.Count);
            Assert.AreEqual(SpfMechanism.IP4, included.Directives[0].Mechanism);
            Assert.AreEqual("192.0.2.1", included.Directives[0].IP4.ToString());
        }

        [Test]
        public void TestMaxLookups()
        {
            var resolver = new DummyResolver("businessmonitor.nl", "v=spf1 include:businessmonitor.nl");
            var check = new SpfCheck(resolver);

            Assert.Throws<InvalidSpfException>(() =>
            {
                check.GetSpfRecord("businessmonitor.nl");
            });
        }

        [Test]
        public void TestLookups()
        {
            var resolver = new DnsResolver(IPAddress.Parse("1.1.1.1")); // Cloudflare DNS
            var check = new SpfCheck(resolver);

            var businessmonitor = check.GetSpfRecord("businessmonitor.nl");
            var google = check.GetSpfRecord("gmail.com");
            var outlook = check.GetSpfRecord("outlook.com");
            var protonmail = check.GetSpfRecord("protonmail.com");

            Assert.IsNotNull(businessmonitor);
            Assert.IsNotNull(google);
            Assert.IsNotNull(outlook);
            Assert.IsNotNull(protonmail);

            Assert.GreaterOrEqual(businessmonitor.Directives.Count, 1);
            Assert.GreaterOrEqual(outlook.Directives.Count, 1);
            Assert.GreaterOrEqual(protonmail.Directives.Count, 1);

            Assert.GreaterOrEqual(google.Modifiers.Count, 1);

            Assert.AreEqual("_spf.protonmail.ch", protonmail.Directives.First(x => x.Mechanism == SpfMechanism.Include).Include);
            Assert.IsNotNull(protonmail.Directives.First(x => x.Mechanism == SpfMechanism.Include).Included);
        }
    }
}
