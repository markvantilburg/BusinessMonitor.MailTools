using BusinessMonitor.MailTools.Dmarc;
using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Test.Dns;
using NUnit.Framework;
using System;
using System.Net;

namespace BusinessMonitor.MailTools.Test
{
    internal class DmarcTests
    {
        [Test]
        public void TestParse()
        {
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject; adkim=s; aspf=s");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.DkimMode, Is.EqualTo(AlignmentMode.Strict));
            Assert.That(record.SpfMode, Is.EqualTo(AlignmentMode.Strict));
            Assert.That(record.Policy, Is.EqualTo(ReceiverPolicy.Reject));

            var record2 = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject; rf=afrf; ri=604800");

            Assert.That(record2, Is.Not.Null);
            Assert.That(record2.ReportFormat, Does.Contain("afrf"));
            Assert.That(record2.ReportInterval, Is.EqualTo(604800));
        }

        [Test]
        public void TestLookup()
        {
            var resolver = new DummyResolver("_dmarc.businessmonitor.nl", "v=DMARC1; p=quarantine; adkim=s; aspf=s; pct=50; rua=reports@example.com");

            var check = new DmarcCheck(resolver);
            var record = check.GetDmarcRecord("businessmonitor.nl");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.DkimMode, Is.EqualTo(AlignmentMode.Strict));
            Assert.That(record.SpfMode, Is.EqualTo(AlignmentMode.Strict));
            Assert.That(record.Policy, Is.EqualTo(ReceiverPolicy.Quarantine));
            Assert.That(record.PercentageTag, Is.EqualTo(50));
            Assert.That(record.AggregatedReportAddresses.Length, Is.EqualTo(1));
            Assert.That(record.AggregatedReportAddresses, Does.Contain("reports@example.com"));
        }

        [Test]
        public void TestFailureOptions()
        {
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; fo=1:d");

            Assert.That(record, Is.Not.Null);
            Assert.That((record.FailureOptions & FailureOptions.Any) != 0, Is.True);
            Assert.That((record.FailureOptions & FailureOptions.DkimFailure) != 0, Is.True);

            var record2 = DmarcCheck.ParseDmarcRecord("v=DMARC1; fo=0:d:s");

            Assert.That(record2, Is.Not.Null);
            Assert.That((record2.FailureOptions & FailureOptions.All) != 0, Is.True);
            Assert.That((record2.FailureOptions & FailureOptions.DkimFailure) != 0, Is.True);
            Assert.That((record2.FailureOptions & FailureOptions.SpfFailure) != 0, Is.True);

            var record3 = DmarcCheck.ParseDmarcRecord("v=DMARC1");

            Assert.That(record3, Is.Not.Null);
            Assert.That(record3.FailureOptions, Is.EqualTo(FailureOptions.All));
        }

        [Test]
        [TestCase("")]
        [TestCase("v=DMARC1; adkim=s; aspf=x")]
        [TestCase("v=DMARC1; pct=10000")]
        [TestCase("v=DMARC1; p=aaaa")]
        [TestCase("v=DMARC1; adkim=s; p=reject")]
        public void TestInvalid(string value)
        {
            Assert.Throws<DmarcInvalidException>(() =>
            {
                DmarcCheck.ParseDmarcRecord(value);
            });
        }

        [Test]
        public void TestInvalidArguments()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new DmarcCheck(null);
            });

            var check = new DmarcCheck(new DummyResolver());

            Assert.Throws<ArgumentNullException>(() =>
            {
                check.GetDmarcRecord(null);
            });

            Assert.Throws<ArgumentException>(() =>
            {
                var domain = new string('a', 300);

                check.GetDmarcRecord(domain);
            });

            Assert.Throws<ArgumentNullException>(() =>
            {
                DmarcCheck.ParseDmarcRecord(null);
            });
        }

        [Test]
        public void TestLookups()
        {
            var resolver = new DnsResolver(IPAddress.Parse("1.1.1.1")); // Cloudflare DNS
            var check = new DmarcCheck(resolver);

            var businessmonitor = check.GetDmarcRecord("businessmonitor.nl");
            var google = check.GetDmarcRecord("gmail.com");
            var outlook = check.GetDmarcRecord("outlook.com");
            var protonmail = check.GetDmarcRecord("protonmail.com");

            Assert.That(businessmonitor, Is.Not.Null);
            Assert.That(google, Is.Not.Null);
            Assert.That(outlook, Is.Not.Null);
            Assert.That(protonmail, Is.Not.Null);

            Assert.That(google.AggregatedReportAddresses, Does.Contain("mailto:mailauth-reports@google.com"));
            Assert.That(outlook.AggregatedReportAddresses, Does.Contain("mailto:rua@dmarc.microsoft"));
        }
    }
}
