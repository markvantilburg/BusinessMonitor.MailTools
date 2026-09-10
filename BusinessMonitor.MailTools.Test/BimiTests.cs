using BusinessMonitor.MailTools.Bimi;
using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Test.Dns;
using NUnit.Framework;
using System;
using System.Net;

namespace BusinessMonitor.MailTools.Test
{
    public class BimiTests
    {
        [Test]
        public void TestParse()
        {
            var record = BimiCheck.ParseBimiRecord("v=BIMI1; l=https://example.com/logo.svg");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.Location, Is.EqualTo("https://example.com/logo.svg"));
            Assert.That(record.Evidence, Is.EqualTo(""));

            var record2 = BimiCheck.ParseBimiRecord("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/bimi.pem");

            Assert.That(record2, Is.Not.Null);
            Assert.That(record2.Location, Is.EqualTo("https://example.com/logo.svg"));
            Assert.That(record2.Evidence, Is.EqualTo("https://example.com/bimi.pem"));

            var record3 = BimiCheck.ParseBimiRecord("v=BIMI1; l=");

            Assert.That(record3, Is.Not.Null);
        }

        [Test]
        public void TestSelectors()
        {
            var record = BimiCheck.ParseBimiRecord("v=BIMI1; l=https://example.com/logo.svg; lps=hello-world");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.LocalPartSelectors, Contains.Item("hello-world"));

            var record2 = BimiCheck.ParseBimiRecord("v=BIMI1; l=https://example.com/logo.svg; lps=hello , world , yes");

            Assert.That(record2, Is.Not.Null);
            Assert.That(record2.LocalPartSelectors, Contains.Item("hello"));
            Assert.That(record2.LocalPartSelectors, Contains.Item("world"));
        }

        [Test]
        public void TestAvatar()
        {
            var record = BimiCheck.ParseBimiRecord("v=BIMI1; l=https://example.com/logo.svg; avp=personal");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.AvatarPreference, Is.EqualTo(AvatarPreference.Personal));

            var record2 = BimiCheck.ParseBimiRecord("v=BIMI1; l=https://example.com/logo.svg; avp=brand");

            Assert.That(record2, Is.Not.Null);
            Assert.That(record2.AvatarPreference, Is.EqualTo(AvatarPreference.Brand));

            var record3 = BimiCheck.ParseBimiRecord("v=BIMI1; l=https://example.com/logo.svg");

            Assert.That(record3, Is.Not.Null);
            Assert.That(record3.AvatarPreference, Is.EqualTo(AvatarPreference.Brand));
        }

        [Test]
        public void TestLookup()
        {
            var resolver = new DummyResolver("default._bimi.businessmonitor.nl", "v=BIMI1; l=https://businessmonitor.nl/logo.svg");

            var check = new BimiCheck(resolver);
            var record = check.GetBimiRecord("businessmonitor.nl");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.Location, Is.EqualTo("https://businessmonitor.nl/logo.svg"));
        }

        // Can't do new string() since const
        private const string LongSelector = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        private const string MaxSelector = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        [Test]
        public void TestSelectorValidation()
        {
            // Valid DNS labels
            var record = BimiCheck.ParseBimiRecord("v=BIMI1; l=https://example.com/logo.svg; lps=hello-world,ABC123,a,1selector,hello_world," + MaxSelector);

            Assert.That(record, Is.Not.Null);
            Assert.That(record.LocalPartSelectors, Contains.Item("hello-world"));
            Assert.That(record.LocalPartSelectors, Contains.Item("ABC123"));
            Assert.That(record.LocalPartSelectors, Contains.Item("a"));
            Assert.That(record.LocalPartSelectors, Contains.Item("1selector"));
            Assert.That(record.LocalPartSelectors, Contains.Item(MaxSelector)); // 63 characters, boundary
        }

        [Test]
        [TestCase("lps=-hello")]         // leading hyphen
        [TestCase("lps=hello-")]         // trailing hyphen
        [TestCase("lps=hello,-world")]   // invalid entry among valid ones
        [TestCase("lps=hello.world")]    // dot not allowed
        [TestCase("lps=héllo")]          // non-ASCII letter
        [TestCase("lps=日本")]           // non-ASCII letters
        [TestCase("lps=٣٤٥")]            // non-ASCII digits
        [TestCase("lps=")]               // empty value
        [TestCase("lps= ")]              // whitespace-only value
        [TestCase("lps=,,")]             // only separators
        [TestCase("lps= , , ")]          // only whitespace entries
        public void TestInvalidSelectors(string lps)
        {
            Assert.Throws<BimiInvalidException>(() =>
            {
                BimiCheck.ParseBimiRecord("v=BIMI1; l=https://example.com/logo.svg; " + lps);
            });
        }

        [Test]
        [TestCase("")]
        [TestCase("v=BIMI1")]
        [TestCase("v=BIMI1; l=invalidlink")]
        [TestCase("v=BIMI1; a=invalidlink l=https://businessmonitor.nl/logo.svg")]
        [TestCase("v=BIMI1; l=http://nothttpstransport")]
        [TestCase("v=BIMI1; l=https://example.com/logo.svg; avp=invalid")]
        [TestCase("v=BIMI1; l=https://example.com/logo.svg; lps=???")]
        [TestCase("v=BIMI1; l=https://example.com/logo.svg; lps=" + LongSelector)]
        public void TestInvalid(string value)
        {
            Assert.Throws<BimiInvalidException>(() =>
            {
                BimiCheck.ParseBimiRecord(value);
            });
        }

        // Locations a consumer would fetch must not point at the consumer itself or its network
        [TestCase("v=BIMI1; l=https://127.0.0.1/logo.svg")]
        [TestCase("v=BIMI1; l=https://127.1.2.3/logo.svg")]
        [TestCase("v=BIMI1; l=https://[::1]/logo.svg")]
        [TestCase("v=BIMI1; l=https://[::ffff:127.0.0.1]/logo.svg")]
        [TestCase("v=BIMI1; l=https://[::ffff:10.0.0.1]/logo.svg")]
        [TestCase("v=BIMI1; l=https://2130706433/logo.svg")]          // decimal form of 127.0.0.1
        [TestCase("v=BIMI1; l=https://169.254.169.254/latest/meta-data/")]
        [TestCase("v=BIMI1; l=https://10.0.0.5/logo.svg")]
        [TestCase("v=BIMI1; l=https://172.16.0.1/logo.svg")]
        [TestCase("v=BIMI1; l=https://192.168.1.1/logo.svg")]
        [TestCase("v=BIMI1; l=https://100.64.0.1/logo.svg")]
        [TestCase("v=BIMI1; l=https://0.0.0.0/logo.svg")]
        [TestCase("v=BIMI1; l=https://[fd00::1]/logo.svg")]
        [TestCase("v=BIMI1; l=https://[fe80::1]/logo.svg")]
        [TestCase("v=BIMI1; l=https://[2002:a00:1::1]/logo.svg")]       // 6to4 embedding 10.0.0.1
        [TestCase("v=BIMI1; l=https://localhost/logo.svg")]
        [TestCase("v=BIMI1; l=https://LOCALHOST/logo.svg")]
        [TestCase("v=BIMI1; l=https://foo.localhost/logo.svg")]
        [TestCase("v=BIMI1; l=https://user:password@example.com/logo.svg")]
        [TestCase("v=BIMI1; l=https://user@example.com/logo.svg")]
        [TestCase("v=BIMI1; l=https://example.com/logo.svg; a=https://127.0.0.1/vmc.pem")]
        [TestCase("v=BIMI1; l=https://example.com/logo.svg; a=https://localhost/vmc.pem")]
        [TestCase("v=BIMI1; l=https://example.com/logo.svg; a=https://user:password@example.com/vmc.pem")]
        public void TestUnsafeLocation(string value)
        {
            Assert.Throws<BimiInvalidException>(() =>
            {
                BimiCheck.ParseBimiRecord(value);
            });
        }

        [TestCase("https://example.com/logo.svg")]
        [TestCase("https://example.com:8443/logo.svg")]
        [TestCase("https://example.com/logo.svg?v=2")]
        [TestCase("https://1.1.1.1/logo.svg")]
        [TestCase("https://[2606:4700:4700::1111]/logo.svg")]
        [TestCase("https://localhost.example.com/logo.svg")]
        [TestCase("https://notlocalhost/logo.svg")]
        public void TestSafeLocation(string location)
        {
            var record = BimiCheck.ParseBimiRecord("v=BIMI1; l=" + location + "; a=" + location);

            Assert.That(record.Location, Is.EqualTo(location));
            Assert.That(record.Evidence, Is.EqualTo(location));
        }

        [Test]
        public void TestLookupIgnoresOtherTextRecords()
        {
            var resolver = new DummyResolver();
            resolver.AddText("default._bimi.businessmonitor.nl", "google-site-verification=abc");
            resolver.AddText("default._bimi.businessmonitor.nl", "v=BIMI1; l=https://businessmonitor.nl/logo.svg");
            resolver.AddText("default._bimi.businessmonitor.nl", "v=BIMI10; l=https://example.com/other.svg");

            var check = new BimiCheck(resolver);
            var record = check.GetBimiRecord("businessmonitor.nl");

            Assert.That(record.Location, Is.EqualTo("https://businessmonitor.nl/logo.svg"));
        }

        [Test]
        public void TestMultipleRecordsAreInvalid()
        {
            // Multiple records terminate discovery, receivers do not perform BIMI (BIMI draft section 7.2)
            var resolver = new DummyResolver();
            resolver.AddText("default._bimi.businessmonitor.nl", "v=BIMI1; l=https://businessmonitor.nl/a.svg");
            resolver.AddText("default._bimi.businessmonitor.nl", "v=BIMI1; l=https://businessmonitor.nl/b.svg");

            var check = new BimiCheck(resolver);

            Assert.Throws<BimiInvalidException>(() =>
            {
                check.GetBimiRecord("businessmonitor.nl");
            });
        }

        [Test]
        public void TestLookupDiscardsInvalidVersion()
        {
            var resolver = new DummyResolver("default._bimi.businessmonitor.nl", "v=BIMI10; l=https://businessmonitor.nl/logo.svg");
            var check = new BimiCheck(resolver);

            Assert.Throws<BimiNotFoundException>(() =>
            {
                check.GetBimiRecord("businessmonitor.nl");
            });
        }

        [Test]
        public void TestVersionWhitespace()
        {
            // Whitespace around the equals sign is allowed by the tag-value syntax
            var record = BimiCheck.ParseBimiRecord("v = BIMI1 ; l = https://example.com/logo.svg");

            Assert.That(record.Location, Is.EqualTo("https://example.com/logo.svg"));
        }

        [TestCase("v=BIMI10; l=https://example.com/logo.svg")]        // Not the version
        [TestCase("v=BIMI1x; l=https://example.com/logo.svg")]
        [TestCase("v=bimi1; l=https://example.com/logo.svg")]         // The version must match precisely
        [TestCase("v=BIMI2; l=https://example.com/logo.svg")]
        [TestCase("l=https://example.com/logo.svg; v=BIMI1")]         // The version must be the first tag
        [TestCase("V=BIMI1; l=https://example.com/logo.svg")]         // Tag names are case sensitive
        [TestCase("v=BIMI1; l=https://example.com/logo.svg; v=BIMI1")] // Duplicate version tag
        public void TestInvalidVersion(string value)
        {
            Assert.Throws<BimiInvalidException>(() =>
            {
                BimiCheck.ParseBimiRecord(value);
            });
        }

        [TestCase("v=BIMI1; l=https://example.com/a.svg; l=https://example.com/b.svg")] // Duplicate tag (RFC 6376 section 3.2)
        [TestCase("v=BIMI1; l=https://example.com/a.svg; a=; a=")]
        [TestCase("v=BIMI1; l=https://example.com/a.svg; garbage")]                    // Segment without a value
        [TestCase("v=BIMI1;; l=https://example.com/a.svg")]                            // Empty segment in the middle
        [TestCase("v=BIMI1; l=https://example.com/a.svg; =x")]                         // Empty tag name
        [TestCase("v=BIMI1; l=https://example.com/a.svg; 1a=x")]                       // Tag names start with a letter
        [TestCase("v=BIMI1; l=https://example.com/a.svg; a-b=x")]
        public void TestInvalidTags(string value)
        {
            Assert.Throws<BimiInvalidException>(() =>
            {
                BimiCheck.ParseBimiRecord(value);
            });
        }

        [Test]
        public void TestUnknownTagsAndTrailingSeparator()
        {
            var record = BimiCheck.ParseBimiRecord("v=BIMI1; l=https://example.com/a.svg; foo=bar; x_1=y;");

            Assert.That(record.Location, Is.EqualTo("https://example.com/a.svg"));

            var record2 = BimiCheck.ParseBimiRecord("v=BIMI1; l=https://example.com/a.svg; ");

            Assert.That(record2.Location, Is.EqualTo("https://example.com/a.svg"));
        }

        [Test]
        public void TestInvalidArguments()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new BimiCheck(null);
            });

            var check = new BimiCheck(new DummyResolver());

            Assert.Throws<ArgumentNullException>(() =>
            {
                check.GetBimiRecord(null);
            });

            Assert.Throws<ArgumentNullException>(() =>
            {
                check.GetBimiRecord("businessmonitor.nl", null);
            });

            Assert.Throws<ArgumentException>(() =>
            {
                var domain = new string('a', 300);

                check.GetBimiRecord(domain);
            });

            Assert.Throws<ArgumentNullException>(() =>
            {
                BimiCheck.ParseBimiRecord(null);
            });
        }

        [Test]
        public void TestNotFound()
        {
            var check = new BimiCheck(new DummyResolver());

            Assert.Throws<BimiNotFoundException>(() =>
            {
                check.GetBimiRecord("example.com");
            });
        }

        [Test]
        public void TestTrailingDotDomain()
        {
            var resolver = new DummyResolver("default._bimi.businessmonitor.nl", "v=BIMI1; l=https://businessmonitor.nl/logo.svg");

            var check = new BimiCheck(resolver);
            var record = check.GetBimiRecord("businessmonitor.nl.");

            Assert.That(record.Location, Is.EqualTo("https://businessmonitor.nl/logo.svg"));
        }

        [Test]
        public void TestNullResolverResult()
        {
            var resolver = new DummyResolver { ReturnNullWhenEmpty = true };
            var check = new BimiCheck(resolver);

            Assert.Throws<BimiNotFoundException>(() =>
            {
                check.GetBimiRecord("example.com");
            });
        }

        [Test]
        public void TestNullResolverEntry()
        {
            var resolver = new DummyResolver("default._bimi.businessmonitor.nl", "v=BIMI1; l=https://businessmonitor.nl/logo.svg") { ReturnNullEntry = true };
            var check = new BimiCheck(resolver);

            Assert.That(check.GetBimiRecord("businessmonitor.nl").Location, Is.EqualTo("https://businessmonitor.nl/logo.svg"));
        }

        [Test]
        public void TestLookups()
        {
            var resolver = new DnsResolver(IPAddress.Parse("1.1.1.1")); // Cloudflare DNS
            var check = new BimiCheck(resolver);

            var linkedin = check.GetBimiRecord("linkedin.com");
            var spotify = check.GetBimiRecord("spotify.com");

            Assert.That(linkedin, Is.Not.Null);
            Assert.That(spotify, Is.Not.Null);

            Assert.That(linkedin.Location, Is.Not.Empty);
            Assert.That(linkedin.Evidence, Is.Not.Empty);

            Assert.That(spotify.Location, Is.Not.Empty); // Spotify has no evidence location
        }

        [TestCase("business.nl", "sel ector")]
        [TestCase("business.nl", "sel..ector")]
        [TestCase("business.nl", "sel\u0000ector")]
        [TestCase("business..nl", "default")]
        [TestCase("busi ness.nl", "default")]
        public void TestInvalidQueryInput(string domain, string selector)
        {
            var check = new BimiCheck(new DummyResolver());

            Assert.Throws<ArgumentException>(() =>
            {
                check.GetBimiRecord(domain, selector);
            });
        }

    }
}
