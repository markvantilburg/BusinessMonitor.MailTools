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
        [TestCase("v=spf1 a/24 -all", "", 24, null)]
        [TestCase("v=spf1 a//64 -all", "", null, 64)]
        [TestCase("v=spf1 a/24//64 -all", "", 24, 64)]
        [TestCase("v=spf1 a:example.com/24 -all", "example.com", 24, null)]
        [TestCase("v=spf1 mx:mail.example.com/24//64 -all", "mail.example.com", 24, 64)]
        [TestCase("v=spf1 MX/16 -all", "", 16, null)]              // Mechanisms are case insensitive
        [TestCase("v=spf1 a:example.com -all", "example.com", null, null)]
        [TestCase("v=spf1 a/0//0 -all", "", 0, 0)]                 // Zero is a valid CIDR length
        public void TestDualCidr(string value, string domain, int? length4, int? length6)
        {
            var record = SpfCheck.ParseSpfRecord(value);
            var directive = record.Directives[0];

            Assert.That(directive.Domain, Is.EqualTo(domain));
            Assert.That(directive.IP4Length, Is.EqualTo(length4));
            Assert.That(directive.IP6Length, Is.EqualTo(length6));
        }

        [Test]
        [TestCase("v=spf1 a/33 -all")]                             // Above the IPv4 maximum
        [TestCase("v=spf1 a//129 -all")]                           // Above the IPv6 maximum
        [TestCase("v=spf1 a/abc -all")]
        [TestCase("v=spf1 a/ -all")]
        [TestCase("v=spf1 a// -all")]
        [TestCase("v=spf1 a/+24 -all")]
        [TestCase("v=spf1 a/24/64 -all")]                          // IPv6 length needs a double slash
        [TestCase("v=spf1 a/024 -all")]                            // No leading zeros (RFC 7208 section 12)
        [TestCase("v=spf1 a//064 -all")]
        [TestCase("v=spf1 a/00 -all")]
        [TestCase("v=spf1 mx: -all")]                              // Empty value after a colon
        public void TestInvalidDualCidr(string value)
        {
            Assert.Throws<SpfInvalidException>(() =>
            {
                SpfCheck.ParseSpfRecord(value);
            });
        }

        [Test]
        [TestCase("v=spf1 exists:e.example.com -all", "e.example.com")]
        [TestCase("v=spf1 exists:%{ir}.%{v}._spf.%{d} -all", "%{ir}.%{v}._spf.%{d}")]
        [TestCase("v=spf1 exists:%{i}.%{l1r+-}._spf.%{d} -all", "%{i}.%{l1r+-}._spf.%{d}")] // RFC 7208 section 7.4 example
        [TestCase("v=spf1 exists:%%.%_.%-.example.com -all", "%%.%_.%-.example.com")]       // Literal macros
        public void TestExists(string value, string domain)
        {
            var record = SpfCheck.ParseSpfRecord(value);

            Assert.That(record.Directives[0].Mechanism, Is.EqualTo(SpfMechanism.Exists));
            Assert.That(record.Directives[0].Domain, Is.EqualTo(domain));
        }

        [Test]
        [TestCase("v=spf1 ptr -all", null)]                        // The domain is optional
        [TestCase("v=spf1 ptr:example.com -all", "example.com")]
        public void TestPtr(string value, string domain)
        {
            var record = SpfCheck.ParseSpfRecord(value);

            Assert.That(record.Directives[0].Mechanism, Is.EqualTo(SpfMechanism.Ptr));
            Assert.That(record.Directives[0].Domain, Is.EqualTo(domain));
        }

        [Test]
        [TestCase("v=spf1 exists -all")]                           // The exists mechanism requires a domain
        [TestCase("v=spf1 exists:%{x}.example.com -all")]          // Not a valid macro letter
        [TestCase("v=spf1 exists:%{c}.example.com -all")]          // Only valid in an exp text
        [TestCase("v=spf1 exists:%d.example.com -all")]            // Percent must start a macro
        [TestCase("v=spf1 exists:%{d.example.com -all")]           // Unterminated macro
        [TestCase("v=spf1 exists:%{dr2}.example.com -all")]        // Digits must come before the reverse marker
        [TestCase("v=spf1 exists:%{} -all")]                       // Empty macro
        [TestCase("v=spf1 ptr:not..a..domain -all")]
        public void TestInvalidExistsAndPtr(string value)
        {
            Assert.Throws<SpfInvalidException>(() =>
            {
                SpfCheck.ParseSpfRecord(value);
            });
        }

        [Test]
        public void TestMacroDomains()
        {
            // Macros are valid in any domain spec
            Assert.DoesNotThrow(() =>
            {
                SpfCheck.ParseSpfRecord("v=spf1 include:%{d}.spf.example.com -all");
            });

            Assert.DoesNotThrow(() =>
            {
                SpfCheck.ParseSpfRecord("v=spf1 a:%{d}.example.com/24 -all");
            });

            Assert.DoesNotThrow(() =>
            {
                SpfCheck.ParseSpfRecord("v=spf1 redirect=%{d}._spf.example.com");
            });
        }

        [Test]
        public void TestMacroIncludeNotResolved()
        {
            // A domain with macros can only be resolved during evaluation, the
            // lookup is counted but no DNS query is made
            var resolver = new DummyResolver("businessmonitor.nl", "v=spf1 include:%{d}.spf.example.com -all");
            var check = new SpfCheck(resolver);

            var record = check.GetSpfRecord("businessmonitor.nl");

            Assert.That(record.Directives[0].Included, Is.Null);
        }

        [Test]
        public void TestLookupLimitCountsPtrAndExists()
        {
            // The ptr and exists mechanisms count toward the lookup limit (RFC 7208 section 4.6.4)
            var terms = string.Join(" ", Enumerable.Repeat("exists:e.businessmonitor.nl", 10));
            var resolver = new DummyResolver("businessmonitor.nl", "v=spf1 " + terms + " ptr -all");
            var check = new SpfCheck(resolver);

            Assert.Throws<SpfLookupException>(() =>
            {
                check.GetSpfRecord("businessmonitor.nl");
            });
        }

        [Test]
        public void TestLookupLimitAtMaximum()
        {
            // Exactly 10 lookups is allowed
            var terms = string.Join(" ", Enumerable.Repeat("exists:e.businessmonitor.nl", 9));
            var resolver = new DummyResolver("businessmonitor.nl", "v=spf1 " + terms + " ptr -all");
            var check = new SpfCheck(resolver);

            Assert.DoesNotThrow(() =>
            {
                check.GetSpfRecord("businessmonitor.nl");
            });
        }

        [Test]
        public void TestDualCidrLookup()
        {
            // The CIDR lengths must not change how the a mechanism resolves
            var resolver = new DummyResolver();
            resolver.AddText("businessmonitor.nl", "v=spf1 a/24 -all");
            resolver.AddAddress("businessmonitor.nl", IPAddress.Parse("192.0.2.1"));

            var check = new SpfCheck(resolver);
            var record = check.GetSpfRecord("businessmonitor.nl");

            var directive = record.Directives[0];

            Assert.That(directive.Domain, Is.EqualTo("businessmonitor.nl"));
            Assert.That(directive.IP4Length, Is.EqualTo(24));
            Assert.That(directive.Addresses, Has.Length.EqualTo(1));
        }

        [Test]
        public void TestRedirect()
        {
            var resolver = new DummyResolver();
            resolver.AddText("businessmonitor.nl", "v=spf1 redirect=_spf.businessmonitor.nl");
            resolver.AddText("_spf.businessmonitor.nl", "v=spf1 ip4:192.0.2.1 -all");

            var check = new SpfCheck(resolver);
            var record = check.GetSpfRecord("businessmonitor.nl");

            var redirect = record.Modifiers[0];

            Assert.That(redirect.Name, Is.EqualTo("redirect"));
            Assert.That(redirect.Included, Is.Not.Null);
            Assert.That(redirect.Included.Directives[0].Mechanism, Is.EqualTo(SpfMechanism.IP4));
        }

        [Test]
        public void TestRedirectNotFound()
        {
            // A redirect to a domain without a SPF record is a permanent error (RFC 7208 section 6.1)
            var resolver = new DummyResolver("businessmonitor.nl", "v=spf1 redirect=_spf.businessmonitor.nl");
            var check = new SpfCheck(resolver);

            Assert.Throws<SpfLookupException>(() =>
            {
                check.GetSpfRecord("businessmonitor.nl");
            });
        }

        [Test]
        public void TestRedirectIgnoredWithAll()
        {
            // A redirect modifier is ignored when the record contains an all mechanism (RFC 7208 section 6.1)
            var resolver = new DummyResolver("businessmonitor.nl", "v=spf1 ip4:192.0.2.1 -all redirect=_spf.businessmonitor.nl");
            var check = new SpfCheck(resolver);

            var record = check.GetSpfRecord("businessmonitor.nl");

            Assert.That(record.Modifiers[0].Included, Is.Null);
        }

        [Test]
        public void TestRedirectLoop()
        {
            // A redirect to itself must hit the lookup limit and not recurse forever
            var resolver = new DummyResolver("businessmonitor.nl", "v=spf1 redirect=businessmonitor.nl");
            var check = new SpfCheck(resolver);

            Assert.Throws<SpfLookupException>(() =>
            {
                check.GetSpfRecord("businessmonitor.nl");
            });
        }

        [Test]
        [TestCase("v=spf1 exp=explain.example.com -all", "explain.example.com")]
        [TestCase("v=spf1 -all exp=explain._spf.%{d}", "explain._spf.%{d}")] // Modifiers may appear anywhere, macros are allowed
        public void TestExp(string value, string expected)
        {
            var record = SpfCheck.ParseSpfRecord(value);
            var exp = record.Modifiers[0];

            Assert.That(exp.Name, Is.EqualTo("exp"));
            Assert.That(exp.Value, Is.EqualTo(expected));
        }

        [Test]
        [TestCase("v=spf1 exp=a.example.com exp=b.example.com -all")] // At most one exp (RFC 7208 section 6)
        [TestCase("v=spf1 EXP=a.example.com exp=b.example.com -all")] // Modifier names are case insensitive
        [TestCase("v=spf1 exp= -all")]                                // Value must be a domain name
        [TestCase("v=spf1 exp=not..a..domain -all")]
        public void TestInvalidExp(string value)
        {
            Assert.Throws<SpfInvalidException>(() =>
            {
                SpfCheck.ParseSpfRecord(value);
            });
        }

        [Test]
        [TestCase("v=spf1 all:foo")]                                  // The all mechanism takes no value (RFC 7208 section 5.1)
        [TestCase("v=spf1 -all/24")]
        [TestCase("v=spf1 all:")]
        public void TestInvalidAll(string value)
        {
            Assert.Throws<SpfInvalidException>(() =>
            {
                SpfCheck.ParseSpfRecord(value);
            });
        }

        [Test]
        [TestCase("v=spf1 redirect=a.example.com redirect=b.example.com")] // At most one redirect (RFC 7208 section 6)
        [TestCase("v=spf1 redirect=A.example.com REDIRECT=b.example.com")] // Modifier names are case insensitive
        [TestCase("v=spf1 redirect=")]                                     // Value must be a domain name
        [TestCase("v=spf1 redirect=not..a..domain")]
        public void TestInvalidRedirect(string value)
        {
            Assert.Throws<SpfInvalidException>(() =>
            {
                SpfCheck.ParseSpfRecord(value);
            });
        }

        [Test]
        [TestCase("v=spf1")]                            // Version only
        [TestCase("V=SPF1 -all")]                       // Version is case insensitive
        public void TestVersion(string value)
        {
            Assert.DoesNotThrow(() =>
            {
                SpfCheck.ParseSpfRecord(value);
            });
        }

        [Test]
        [TestCase("v=spf1x ip4:192.0.2.1 -all")]        // Version must be the complete first term
        [TestCase("v=spf10 -all")]
        [TestCase("v=spf1-all")]
        [TestCase(" v=spf1 -all")]                      // Record must start with the version
        public void TestInvalidVersion(string value)
        {
            Assert.Throws<SpfInvalidException>(() =>
            {
                SpfCheck.ParseSpfRecord(value);
            });
        }

        [Test]
        public void TestLookupIgnoresLookalikeRecords()
        {
            // A record that does not begin with exactly v=spf1 is not a SPF record (RFC 7208 section 4.5)
            var resolver = new DummyResolver();
            resolver.AddText("businessmonitor.nl", "v=spf1x something");
            resolver.AddText("businessmonitor.nl", "v=spf1 ip4:192.0.2.1 -all");

            var check = new SpfCheck(resolver);

            Assert.DoesNotThrow(() =>
            {
                check.GetSpfRecord("businessmonitor.nl");
            });
        }

        [Test]
        [TestCase("")]
        [TestCase("v=spf1 -boop")]
        [TestCase("v=spf1 boop:boop")]
        [TestCase("v=spf1 include:include:businessmonitor.nl")]
        [TestCase("v=spf1 a ip4:192.168.1.1 ip4:192.168.1.1 ~all")]
        [TestCase("v=spf1 a ip6:::1 ip6:::1 ~all")]
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

#if INTEGRATION_TESTS
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
#endif

        [TestCase("v=spf1 ip4:192.0.2.0/33 -all")]
        [TestCase("v=spf1 ip4:192.0.2.0/-1 -all")]
        [TestCase("v=spf1 ip4:192.0.2.0/999 -all")]
        [TestCase("v=spf1 ip4:192.0.2.0/abc -all")]
        [TestCase("v=spf1 ip4:192.0.2.0/+24 -all")]
        [TestCase("v=spf1 ip4:192.0.2.0/024 -all")]  // No leading zeros (RFC 7208 section 12)
        [TestCase("v=spf1 ip6:2001:db8::/064 -all")]
        [TestCase("v=spf1 ip4:192.0.2.0/ -all")]
        [TestCase("v=spf1 ip6:2001:db8::/129 -all")]
        [TestCase("v=spf1 ip4:not-an-ip -all")]
        [TestCase("v=spf1 ip6:gggg:: -all")]
        public void TestInvalidAddress(string value)
        {
            Assert.Throws<SpfInvalidException>(() =>
            {
                SpfCheck.ParseSpfRecord(value);
            });
        }

        [Test]
        public void TestValidPrefixBounds()
        {
            Assert.DoesNotThrow(() => SpfCheck.ParseSpfRecord("v=spf1 ip4:192.0.2.0/0 -all"));
            Assert.DoesNotThrow(() => SpfCheck.ParseSpfRecord("v=spf1 ip4:192.0.2.1/32 -all"));
            Assert.DoesNotThrow(() => SpfCheck.ParseSpfRecord("v=spf1 ip6:2001:db8::1/128 -all"));
        }


        [TestCase("v=spf1 ip4:::1 -all")]                    // IPv6 in ip4
        [TestCase("v=spf1 ip4:2001:db8::1 -all")]
        [TestCase("v=spf1 ip4:2001:db8::/32 -all")]
        [TestCase("v=spf1 ip6:1.2.3.4 -all")]                // IPv4 in ip6
        [TestCase("v=spf1 ip6:192.0.2.0/24 -all")]
        [TestCase("v=spf1 ip4:1.2.3 -all")]                  // legacy shorthand, .NET parses as 1.2.0.3
        [TestCase("v=spf1 ip4:1.2 -all")]
        [TestCase("v=spf1 ip4:16909060 -all")]               // integer form of 1.2.3.4
        public void TestAddressFamilyMismatch(string value)
        {
            Assert.Throws<SpfInvalidException>(() =>
            {
                SpfCheck.ParseSpfRecord(value);
            });
        }

    }
}
