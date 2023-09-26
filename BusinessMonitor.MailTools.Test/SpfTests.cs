using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Spf;
using BusinessMonitor.MailTools.Test.Dns;
using NUnit.Framework;
using System.Linq;
using System.Net;
using System.Reflection;

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
        public void TestRange()
        {
            var record = SpfCheck.ParseSpfRecord("v=spf1 ip4:192.168.0.1/24 ip4:192.168.0.13");

            Assert.IsNotNull(record);

            SpfAddress address;

            // ip4:192.168.0.1/24
            address = record.Directives[0].IP4;
            Assert.IsTrue(address.Contains(IPAddress.Parse("192.168.0.12")));

            // ip4:192.168.0.13
            address = record.Directives[1].IP4;
            Assert.IsTrue(address.Contains(IPAddress.Parse("192.168.0.13")));
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
            Assert.Throws<SpfInvalidException>(() =>
            {
                SpfCheck.ParseSpfRecord(value);
            });
        }

        [Test]
        public void TestWhitespaces()
        {
            var record = SpfCheck.ParseSpfRecord("v=spf1  ip4:192.0.2.1   -all    ");

            Assert.IsNotNull(record);
        }

        [Test]
        public void TestCaseInsensitive()
        {
            var record = SpfCheck.ParseSpfRecord("v=SPF1 Include:example.com -All");

            Assert.IsNotNull(record);
            Assert.AreEqual(SpfMechanism.Include, record.Directives[0].Mechanism);
            Assert.AreEqual(SpfMechanism.All, record.Directives[1].Mechanism);
        }

        [Test]
        public void TestLookup()
        {
            var resolver = new DummyResolver();

            resolver.AddText("businessmonitor.nl", "v=spf1 include:survey.businessmonitor.nl -all");
            resolver.AddText("survey.businessmonitor.nl", "v=spf1 ip4:192.0.2.1 -all");

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
        public void TestMX()
        {
            var resolver = new DummyResolver();

            resolver.AddText("businessmonitor.nl", "v=spf1 mx:businessmonitor.nl -all");

            resolver.AddMail("businessmonitor.nl", "mail1.businessmonitor.nl");
            resolver.AddMail("businessmonitor.nl", "mail2.businessmonitor.nl");

            resolver.AddAddress("mail1.businessmonitor.nl", IPAddress.Parse("10.10.0.1"));
            resolver.AddAddress("mail1.businessmonitor.nl", IPAddress.Parse("10.10.0.2"));
            resolver.AddAddress("mail2.businessmonitor.nl", IPAddress.Parse("10.10.0.3"));

            var check = new SpfCheck(resolver);
            var record = check.GetSpfRecord("businessmonitor.nl");

            Assert.IsNotNull(record);

            var directive = record.Directives[0];

            Assert.AreEqual(3, directive.Addresses.Length);
            Assert.AreEqual(IPAddress.Parse("10.10.0.1"), directive.Addresses[0]);
            Assert.AreEqual(IPAddress.Parse("10.10.0.2"), directive.Addresses[1]);
            Assert.AreEqual(IPAddress.Parse("10.10.0.3"), directive.Addresses[2]);

            // Check the number of lookups
            var lookups = (int)typeof(SpfCheck).GetField("_lookups", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(check);
            Assert.AreEqual(4, lookups);
        }

        [Test]
        public void TestMaxLookups()
        {
            var resolver = new DummyResolver("businessmonitor.nl", "v=spf1 include:businessmonitor.nl");
            var check = new SpfCheck(resolver);

            Assert.Throws<SpfLookupException>(() =>
            {
                check.GetSpfRecord("businessmonitor.nl");
            });
        }

        [Test]
        public void TestIncludeFail()
        {
            var resolver = new DummyResolver("businessmonitor.nl", "v=spf1 include:example.com"); // example.com does not exist
            var check = new SpfCheck(resolver);

            Assert.Throws<SpfLookupException>(() =>
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
