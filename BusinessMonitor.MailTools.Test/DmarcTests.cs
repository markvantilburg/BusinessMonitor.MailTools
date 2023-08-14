using BusinessMonitor.MailTools.Dmarc;
using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Test.Dns;
using NUnit.Framework;
using System.Net;

namespace BusinessMonitor.MailTools.Test
{
    internal class DmarcTests
    {
        [Test]
        public void TestParse()
        {
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject; adkim=s; aspf=s");

            Assert.IsNotNull(record);
            Assert.AreEqual(AlignmentMode.Strict, record.DkimMode);
            Assert.AreEqual(AlignmentMode.Strict, record.SpfMode);
            Assert.AreEqual(ReceiverPolicy.Reject, record.Policy);

            var record2 = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject; rf=afrf; ri=604800");

            Assert.IsNotNull(record2);
            Assert.Contains("afrf", record2.ReportFormat);
            Assert.AreEqual(604800, record2.ReportInterval);
        }

        [Test]
        public void TestLookup()
        {
            var resolver = new DummyResolver("_dmarc.businessmonitor.nl", "v=DMARC1; p=quarantine; adkim=s; aspf=s; pct=50; rua=reports@example.com");

            var check = new DmarcCheck(resolver);
            var record = check.GetDmarcRecord("businessmonitor.nl");

            Assert.IsNotNull(record);
            Assert.AreEqual(AlignmentMode.Strict, record.DkimMode);
            Assert.AreEqual(AlignmentMode.Strict, record.SpfMode);
            Assert.AreEqual(ReceiverPolicy.Quarantine, record.Policy);
            Assert.AreEqual(50, record.PercentageTag);
            Assert.AreEqual(1, record.AggregatedReportAddresses.Length);
            Assert.Contains("reports@example.com", record.AggregatedReportAddresses);
        }

        [Test]
        public void TestFailureOptions()
        {
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; fo=1:d");

            Assert.IsNotNull(record);
            Assert.IsTrue((record.FailureOptions & FailureOptions.Any) != 0);
            Assert.IsTrue((record.FailureOptions & FailureOptions.DkimFailure) != 0);

            var record2 = DmarcCheck.ParseDmarcRecord("v=DMARC1; fo=0:d:s");

            Assert.IsNotNull(record2);
            Assert.IsTrue((record2.FailureOptions & FailureOptions.All) != 0);
            Assert.IsTrue((record2.FailureOptions & FailureOptions.DkimFailure) != 0);
            Assert.IsTrue((record2.FailureOptions & FailureOptions.SpfFailure) != 0);

            var record3 = DmarcCheck.ParseDmarcRecord("v=DMARC1");

            Assert.IsNotNull(record3);
            Assert.AreEqual(FailureOptions.All, record3.FailureOptions);
        }

        [Test]
        [TestCase("")]
        [TestCase("v=DMARC1; adkim=s; aspf=x")]
        [TestCase("v=DMARC1; pct=10000")]
        [TestCase("v=DMARC1; p=aaaa")]
        [TestCase("v=DMARC1; adkim=s; p=reject")]
        public void TestInvalid(string value)
        {
            Assert.Throws<InvalidDmarcException>(() =>
            {
                DmarcCheck.ParseDmarcRecord(value);
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

            Assert.IsNotNull(businessmonitor);
            Assert.IsNotNull(google);
            Assert.IsNotNull(outlook);
            Assert.IsNotNull(protonmail);

            Assert.Contains("mailto:mailauth-reports@google.com", google.AggregatedReportAddresses);
            Assert.Contains("mailto:rua@dmarc.microsoft", outlook.AggregatedReportAddresses);
        }
    }
}
