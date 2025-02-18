using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Spf;
using BusinessMonitor.MailTools.Test.Dns;
using NUnit.Framework;
using System;
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

            Assert.That(record, Is.Not.Null);
            Assert.That(record.Directives.Count, Is.EqualTo(3));

            SpfDirective directive;

            // ip4:192.0.2.1
            directive = record.Directives[0];

            Assert.That(directive.Qualifier, Is.EqualTo(SpfQualifier.Pass));
            Assert.That(directive.Mechanism, Is.EqualTo(SpfMechanism.IP4));
            Assert.That(directive.IP4, Is.Not.Null);
            Assert.That(directive.IP4.ToString(), Is.EqualTo("192.0.2.1"));

            // ip4:192.0.2.129
            directive = record.Directives[1];

            Assert.That(directive.Qualifier, Is.EqualTo(SpfQualifier.Pass));
            Assert.That(directive.Mechanism, Is.EqualTo(SpfMechanism.IP4));
            Assert.That(directive.IP4, Is.Not.Null);
            Assert.That(directive.IP4.ToString(), Is.EqualTo("192.0.2.129"));

            // -all
            directive = record.Directives[2];

            Assert.That(directive.Qualifier, Is.EqualTo(SpfQualifier.Fail));
            Assert.That(directive.Mechanism, Is.EqualTo(SpfMechanism.All));
        }

        [Test]
        public void TestAddress()
        {
            var record = SpfCheck.ParseSpfRecord("v=spf1 ip4:192.0.2.0/24 ip4:192.0.2.0 ip6:2001:db8::/32");

            Assert.That(record, Is.Not.Null);

            SpfDirective directive;

            // ip4:192.0.2.0/24
            directive = record.Directives[0];

            Assert.That(directive.IP4.ToString(), Is.EqualTo("192.0.2.0/24"));
            Assert.That(directive.IP4.Address.ToString(), Is.EqualTo("192.0.2.0"));
            Assert.That(directive.IP4.Length, Is.EqualTo(24));

            // ip4:192.0.2.0
            directive = record.Directives[1];

            Assert.That(directive.IP4.ToString(), Is.EqualTo("192.0.2.0"));
            Assert.That(directive.IP4.Address.ToString(), Is.EqualTo("192.0.2.0"));
            Assert.That(directive.IP4.Length, Is.Null);

            // ip4:2001:db8::/32
            directive = record.Directives[2];

            Assert.That(directive.IP6.ToString(), Is.EqualTo("2001:db8::/32"));
            Assert.That(directive.IP6.Address.ToString(), Is.EqualTo("2001:db8::"));
            Assert.That(directive.IP6.Length, Is.EqualTo(32));
        }

        [Test]
        public void TestRange()
        {
            var record = SpfCheck.ParseSpfRecord("v=spf1 ip4:192.168.0.1/24 ip4:192.168.0.13");

            Assert.That(record, Is.Not.Null);

            SpfAddress address;

            // ip4:192.168.0.1/24
            address = record.Directives[0].IP4;
            Assert.That(address.Contains(IPAddress.Parse("192.168.0.12")), Is.True);

            // ip4:192.168.0.13
            address = record.Directives[1].IP4;
            Assert.That(address.Contains(IPAddress.Parse("192.168.0.13")), Is.True);
        }

        [Test]
        public void TestModifiers()
        {
            var record = SpfCheck.ParseSpfRecord("v=spf1 redirect=_spf.example.com");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.Modifiers.Count, Is.EqualTo(1));

            Assert.That(record.Modifiers[0].Name, Is.EqualTo("redirect"));
            Assert.That(record.Modifiers[0].Value, Is.EqualTo("_spf.example.com"));
        }

        [Test]
        [TestCase("")]
        [TestCase("v=spf1 -boop")]
        [TestCase("v=spf1 boop:boop")]
        [TestCase("v=spf1 include:include:businessmonitor.nl")]
        public void TestInvalid(string value)
        {
            Assert.Throws<SpfInvalidException>(() =>
            {
                SpfCheck.ParseSpfRecord(value);
            });
        }

        [Test]
        public void TestInvalidArguments()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new SpfCheck(null);
            });

            var check = new SpfCheck(new DummyResolver());

            Assert.Throws<ArgumentNullException>(() =>
            {
                check.GetSpfRecord(null);
            });

            Assert.Throws<ArgumentException>(() =>
            {
                var domain = new string('a', 300);

                check.GetSpfRecord(domain);
            });

            Assert.Throws<ArgumentNullException>(() =>
            {
                SpfCheck.ParseSpfRecord(null);
            });
        }

        [Test]
        public void TestMultipleSPFRecords()
        {
            DummyResolver resolver = new DummyResolver();
            var check = new SpfCheck(resolver);

            resolver.AddText("x.businessmonitor.nl", "v=spf1 include:survey.businessmonitor.nl -all");
            resolver.AddText("x.businessmonitor.nl", "v=spf1 ip4:192.0.2.1 -all");

            Assert.Throws<SpfInvalidException>(() =>
            {
                check.GetSpfRecord("x.businessmonitor.nl");
            });
        }

        [Test]
        public void FailingARecordDoesNotResolve()
        {
            DummyResolver resolver = new DummyResolver();
            var check = new SpfCheck(resolver);

            resolver.AddText("nl.nl", "v=spf1 a -all");

            Assert.Throws<SpfInvalidException>(() =>
            {
                check.GetSpfRecord("nl.nl");
            });
        }

        [Test]
        public void TestWhitespaces()
        {
            var record = SpfCheck.ParseSpfRecord("v=spf1  ip4:192.0.2.1   -all    ");

            Assert.That(record, Is.Not.Null);
        }

        [Test]
        public void TestCaseInsensitive()
        {
            var record = SpfCheck.ParseSpfRecord("v=SPF1 Include:example.com -All");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.Directives[0].Mechanism, Is.EqualTo(SpfMechanism.Include));
            Assert.That(record.Directives[1].Mechanism, Is.EqualTo(SpfMechanism.All));
        }

        [Test]
        public void TestLookup()
        {
            var resolver = new DummyResolver();

            resolver.AddText("businessmonitor.nl", "v=spf1 include:survey.businessmonitor.nl -all");
            resolver.AddText("survey.businessmonitor.nl", "v=spf1 ip4:192.0.2.1 -all");

            var check = new SpfCheck(resolver);
            var record = check.GetSpfRecord("businessmonitor.nl");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.Directives[0].Included, Is.Not.Null);

            var included = record.Directives[0].Included;

            Assert.That(included.Directives.Count, Is.EqualTo(2));
            Assert.That(included.Directives[0].Mechanism, Is.EqualTo(SpfMechanism.IP4));
            Assert.That(included.Directives[0].IP4.ToString(), Is.EqualTo("192.0.2.1"));
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

            Assert.That(record, Is.Not.Null);

            var directive = record.Directives[0];

            Assert.That(directive.Addresses.Length, Is.EqualTo(3));
            Assert.That(directive.Addresses[0], Is.EqualTo(IPAddress.Parse("10.10.0.1")));
            Assert.That(directive.Addresses[1], Is.EqualTo(IPAddress.Parse("10.10.0.2")));
            Assert.That(directive.Addresses[2], Is.EqualTo(IPAddress.Parse("10.10.0.3")));

            // Check the number of lookups
            var lookups = (int)typeof(SpfCheck).GetField("_lookups", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(check);
            Assert.That(lookups, Is.EqualTo(1));
        }

        [Test]
        public void TestA()
        {
            var resolver = new DummyResolver();

            resolver.AddText("businessmonitor.nl", "v=spf1 a a:mail.businessmonitor.nl -all");

            resolver.AddAddress("businessmonitor.nl", IPAddress.Parse("10.10.0.1"));
            resolver.AddAddress("mail.businessmonitor.nl", IPAddress.Parse("10.10.0.2"));

            var check = new SpfCheck(resolver);
            var record = check.GetSpfRecord("businessmonitor.nl");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.Directives.Count, Is.EqualTo(3));

            SpfDirective directive;

            // a
            directive = record.Directives[0];

            Assert.That(directive.Domain, Is.EqualTo("businessmonitor.nl"));
            Assert.That(directive.Addresses[0], Is.EqualTo(IPAddress.Parse("10.10.0.1")));

            // a:mail.businessmonitor.nl
            directive = record.Directives[1];

            Assert.That(directive.Domain, Is.EqualTo("mail.businessmonitor.nl"));
            Assert.That(directive.Addresses[0], Is.EqualTo(IPAddress.Parse("10.10.0.2")));
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
        public void TestMaxMX()
        {
            var resolver = new DummyResolver("businessmonitor.nl", "v=spf1 mx");

            for (var i = 0; i < 11; i++)
            {
                resolver.AddMail("businessmonitor.nl", $"mx{i}.businessmonitor.nl");
            }

            var check = new SpfCheck(resolver);

            Assert.Throws<SpfException>(() =>
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

            Assert.That(businessmonitor, Is.Not.Null);
            Assert.That(google, Is.Not.Null);
            Assert.That(outlook, Is.Not.Null);
            Assert.That(protonmail, Is.Not.Null);

            Assert.That(businessmonitor.Directives.Count, Is.GreaterThanOrEqualTo(1));
            Assert.That(outlook.Directives.Count, Is.GreaterThanOrEqualTo(1));
            Assert.That(protonmail.Directives.Count, Is.GreaterThanOrEqualTo(1));

            Assert.That(google.Modifiers.Count, Is.GreaterThanOrEqualTo(1));

            Assert.That(protonmail.Directives.First(x => x.Mechanism == SpfMechanism.Include).Include, Is.EqualTo("_spf.protonmail.ch"));
            Assert.That(protonmail.Directives.First(x => x.Mechanism == SpfMechanism.Include).Included, Is.Not.Null);
        }
    }
}
