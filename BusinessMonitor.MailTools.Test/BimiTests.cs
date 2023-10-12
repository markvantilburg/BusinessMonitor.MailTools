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

            Assert.IsNotNull(record);
            Assert.AreEqual("https://example.com/logo.svg", record.Location);
            Assert.AreEqual("", record.Evidence);

            var record2 = BimiCheck.ParseBimiRecord("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/bimi.pem");

            Assert.IsNotNull(record2);
            Assert.AreEqual("https://example.com/logo.svg", record2.Location);
            Assert.AreEqual("https://example.com/bimi.pem", record2.Evidence);

            var record3 = BimiCheck.ParseBimiRecord("v=BIMI1; l=");

            Assert.IsNotNull(record3);
        }

        [Test]
        public void TestLookup()
        {
            var resolver = new DummyResolver("default._bimi.businessmonitor.nl", "v=BIMI1; l=https://businessmonitor.nl/logo.svg");

            var check = new BimiCheck(resolver);
            var record = check.GetBimiRecord("businessmonitor.nl");

            Assert.IsNotNull(record);
            Assert.AreEqual("https://businessmonitor.nl/logo.svg", record.Location);
        }

        [Test]
        [TestCase("")]
        [TestCase("v=BIMI1")]
        [TestCase("v=BIMI1; l=invalidlink")]
        [TestCase("v=BIMI1; a=invalidlink l=https://businessmonitor.nl/logo.svg")]
        [TestCase("v=BIMI1; l=http://nothttpstransport")]
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
        public void TestLookups()
        {
            var resolver = new DnsResolver(IPAddress.Parse("1.1.1.1")); // Cloudflare DNS
            var check = new BimiCheck(resolver);

            var linkedin = check.GetBimiRecord("linkedin.com");
            var spotify = check.GetBimiRecord("spotify.com");

            Assert.IsNotNull(linkedin);
            Assert.IsNotNull(spotify);

            Assert.IsNotEmpty(linkedin.Location);
            Assert.IsNotEmpty(linkedin.Evidence);

            Assert.IsNotEmpty(spotify.Location); // Spotify has no evidence location
        }
    }
}
