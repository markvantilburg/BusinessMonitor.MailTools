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
    }
}
