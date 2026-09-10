using BusinessMonitor.MailTools.Dmarc;
using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Test.Dns;
using NUnit.Framework;
using System;
using System.Net;

#pragma warning disable CS0618 // The pct, rf and ri tags are obsolete but still parsed

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
            Assert.That(record.PolicySpecified, Is.True);

            var record2 = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject; rf=afrf; ri=604800");

            Assert.That(record2, Is.Not.Null);
            Assert.That(record2.ReportFormat, Does.Contain("afrf"));
            Assert.That(record2.ReportInterval, Is.EqualTo(604800));
        }

        [Test]
        public void TestDefaults()
        {
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=quarantine");

            Assert.That(record.DkimMode, Is.EqualTo(AlignmentMode.Relaxed));
            Assert.That(record.SpfMode, Is.EqualTo(AlignmentMode.Relaxed));
            Assert.That(record.FailureOptions, Is.EqualTo(FailureOptions.All));
            Assert.That(record.SubdomainPolicy, Is.EqualTo(ReceiverPolicy.Quarantine));
            Assert.That(record.NonExistentSubdomainPolicy, Is.EqualTo(ReceiverPolicy.Quarantine));
            Assert.That(record.TestMode, Is.False);
            Assert.That(record.PublicSuffixDomain, Is.EqualTo(PublicSuffixDomain.Unknown));
            Assert.That(record.PercentageTag, Is.EqualTo(100));
            Assert.That(record.ReportFormat, Is.EqualTo(new[] { "afrf" }));
            Assert.That(record.ReportInterval, Is.EqualTo(86400));
            Assert.That(record.AggregatedReportAddresses, Is.Empty);
            Assert.That(record.ForensicReportAddresses, Is.Empty);
        }

        [Test]
        public void TestLookup()
        {
            var resolver = new DummyResolver("_dmarc.businessmonitor.nl", "v=DMARC1; p=quarantine; adkim=s; aspf=s; pct=50; rua=mailto:reports@example.com");

            var check = new DmarcCheck(resolver);
            var record = check.GetDmarcRecord("businessmonitor.nl");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.DkimMode, Is.EqualTo(AlignmentMode.Strict));
            Assert.That(record.SpfMode, Is.EqualTo(AlignmentMode.Strict));
            Assert.That(record.Policy, Is.EqualTo(ReceiverPolicy.Quarantine));
            Assert.That(record.PercentageTag, Is.EqualTo(50));
            Assert.That(record.AggregatedReportAddresses.Length, Is.EqualTo(1));
            Assert.That(record.AggregatedReportAddresses, Does.Contain("mailto:reports@example.com"));
        }

        [Test]
        public void TestLookupIgnoresOtherTextRecords()
        {
            var resolver = new DummyResolver();
            resolver.AddText("_dmarc.businessmonitor.nl", "google-site-verification=abc");
            resolver.AddText("_dmarc.businessmonitor.nl", "v=DMARC1; p=reject");
            resolver.AddText("_dmarc.businessmonitor.nl", "v=spf1 -all");

            var check = new DmarcCheck(resolver);
            var record = check.GetDmarcRecord("businessmonitor.nl");

            Assert.That(record.Policy, Is.EqualTo(ReceiverPolicy.Reject));
        }

        [Test]
        public void TestMultipleRecordsAreInvalid()
        {
            // Receivers discard all records when more than one is published (RFC 9989 section 4.10.1)
            var resolver = new DummyResolver();
            resolver.AddText("_dmarc.businessmonitor.nl", "v=DMARC1; p=reject");
            resolver.AddText("_dmarc.businessmonitor.nl", "v=DMARC1; p=none");

            var check = new DmarcCheck(resolver);

            Assert.Throws<DmarcInvalidException>(() =>
            {
                check.GetDmarcRecord("businessmonitor.nl");
            });
        }

        [Test]
        public void TestFailureOptions()
        {
            // The fo tag only applies when a ruf tag is present (RFC 9989 section 4.7)
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=none; fo=1:d; ruf=mailto:failures@example.com");

            Assert.That(record, Is.Not.Null);
            Assert.That((record.FailureOptions & FailureOptions.Any) != 0, Is.True);
            Assert.That((record.FailureOptions & FailureOptions.DkimFailure) != 0, Is.True);
            Assert.That((record.FailureOptions & FailureOptions.All) != 0, Is.False);

            var record2 = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=none; ruf=mailto:failures@example.com; fo=0:d:s");

            Assert.That(record2, Is.Not.Null);
            Assert.That((record2.FailureOptions & FailureOptions.All) != 0, Is.True);
            Assert.That((record2.FailureOptions & FailureOptions.DkimFailure) != 0, Is.True);
            Assert.That((record2.FailureOptions & FailureOptions.SpfFailure) != 0, Is.True);

            var record3 = DmarcCheck.ParseDmarcRecord("v=DMARC1");

            Assert.That(record3, Is.Not.Null);
            Assert.That(record3.FailureOptions, Is.EqualTo(FailureOptions.All));
        }

        [Test]
        public void TestFailureOptionsIgnoredWithoutRuf()
        {
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=none; fo=1:d");

            Assert.That(record.FailureOptions, Is.EqualTo(FailureOptions.All));
        }

        [TestCase("fo=x")]
        [TestCase("fo=")]
        [TestCase("fo=1:")]
        [TestCase("fo=d:d")]        // Each option at most once
        [TestCase("fo=0:1")]        // 0 and 1 cannot be combined (RFC 9989 section 4.8)
        [TestCase("fo=1:d:0")]
        public void TestInvalidFailureOptions(string fo)
        {
            Assert.Throws<DmarcInvalidException>(() =>
            {
                DmarcCheck.ParseDmarcRecord("v=DMARC1; p=none; ruf=mailto:failures@example.com; " + fo);
            });
        }

        [Test]
        public void TestPolicyOptional()
        {
            // An absent p tag is treated as p=none (RFC 9989 section 4.7)
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; rua=mailto:reports@example.com");

            Assert.That(record.Policy, Is.EqualTo(ReceiverPolicy.None));
            Assert.That(record.PolicySpecified, Is.False);
            Assert.That(record.SubdomainPolicy, Is.EqualTo(ReceiverPolicy.None));
        }

        [Test]
        public void TestTagOrderIsFree()
        {
            // RFC 7489 required p directly after v, RFC 9989 allows any order (section 4.8)
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; adkim=s; p=reject");

            Assert.That(record.Policy, Is.EqualTo(ReceiverPolicy.Reject));
            Assert.That(record.DkimMode, Is.EqualTo(AlignmentMode.Strict));
        }

        [Test]
        public void TestSubdomainPolicyInheritance()
        {
            // sp inherits p, np inherits sp and then p (RFC 9989 section 4.7)
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject");

            Assert.That(record.SubdomainPolicy, Is.EqualTo(ReceiverPolicy.Reject));
            Assert.That(record.NonExistentSubdomainPolicy, Is.EqualTo(ReceiverPolicy.Reject));

            var record2 = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject; sp=none");

            Assert.That(record2.SubdomainPolicy, Is.EqualTo(ReceiverPolicy.None));
            Assert.That(record2.NonExistentSubdomainPolicy, Is.EqualTo(ReceiverPolicy.None));

            var record3 = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject; sp=none; np=quarantine");

            Assert.That(record3.SubdomainPolicy, Is.EqualTo(ReceiverPolicy.None));
            Assert.That(record3.NonExistentSubdomainPolicy, Is.EqualTo(ReceiverPolicy.Quarantine));

            var record4 = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=none; np=reject");

            Assert.That(record4.SubdomainPolicy, Is.EqualTo(ReceiverPolicy.None));
            Assert.That(record4.NonExistentSubdomainPolicy, Is.EqualTo(ReceiverPolicy.Reject));

            // Inheritance works regardless of tag order
            var record5 = DmarcCheck.ParseDmarcRecord("v=DMARC1; sp=quarantine; p=reject");

            Assert.That(record5.Policy, Is.EqualTo(ReceiverPolicy.Reject));
            Assert.That(record5.SubdomainPolicy, Is.EqualTo(ReceiverPolicy.Quarantine));
            Assert.That(record5.NonExistentSubdomainPolicy, Is.EqualTo(ReceiverPolicy.Quarantine));
        }

        [Test]
        public void TestTestModeAndPublicSuffixDomain()
        {
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject; t=y; psd=n");

            Assert.That(record.TestMode, Is.True);
            Assert.That(record.PublicSuffixDomain, Is.EqualTo(PublicSuffixDomain.No));

            var record2 = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject; t=n; psd=y");

            Assert.That(record2.TestMode, Is.False);
            Assert.That(record2.PublicSuffixDomain, Is.EqualTo(PublicSuffixDomain.Yes));

            var record3 = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject; psd=u");

            Assert.That(record3.PublicSuffixDomain, Is.EqualTo(PublicSuffixDomain.Unknown));
        }

        [Test]
        public void TestValuesAreCaseInsensitive()
        {
            // ABNF literals are case insensitive, only the version value is case sensitive (RFC 9989 section 4.8)
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=Reject; sp=QUARANTINE; np=None; adkim=S; aspf=R; t=Y; psd=N");

            Assert.That(record.Policy, Is.EqualTo(ReceiverPolicy.Reject));
            Assert.That(record.SubdomainPolicy, Is.EqualTo(ReceiverPolicy.Quarantine));
            Assert.That(record.NonExistentSubdomainPolicy, Is.EqualTo(ReceiverPolicy.None));
            Assert.That(record.DkimMode, Is.EqualTo(AlignmentMode.Strict));
            Assert.That(record.SpfMode, Is.EqualTo(AlignmentMode.Relaxed));
            Assert.That(record.TestMode, Is.True);
            Assert.That(record.PublicSuffixDomain, Is.EqualTo(PublicSuffixDomain.No));
        }

        [Test]
        public void TestVersionWhitespace()
        {
            // Whitespace around the equals sign is allowed (RFC 9989 section 4.8)
            var record = DmarcCheck.ParseDmarcRecord("v = DMARC1 ; p = reject");

            Assert.That(record.Policy, Is.EqualTo(ReceiverPolicy.Reject));
        }

        [TestCase("v=DMARC10; p=reject")]         // Not the version
        [TestCase("v=DMARC1x; p=reject")]
        [TestCase("v=dmarc1; p=reject")]          // The version value is case sensitive
        [TestCase("v=DMARC2; p=reject")]
        [TestCase("p=reject; v=DMARC1")]          // The version must be the first tag
        [TestCase("V=DMARC1; p=reject")]          // Tag names are case sensitive
        [TestCase("v=DMARC1; p=reject; v=DMARC1")] // Duplicate version tag
        public void TestInvalidVersion(string value)
        {
            Assert.Throws<DmarcInvalidException>(() =>
            {
                DmarcCheck.ParseDmarcRecord(value);
            });
        }

        [Test]
        public void TestLookupDiscardsInvalidVersion()
        {
            // A record without a valid version is not a DMARC record and is discarded (RFC 9989 section 4.10.1)
            var resolver = new DummyResolver("_dmarc.businessmonitor.nl", "v=DMARC10; p=reject");
            var check = new DmarcCheck(resolver);

            Assert.Throws<DmarcNotFoundException>(() =>
            {
                check.GetDmarcRecord("businessmonitor.nl");
            });
        }

        [Test]
        public void TestUnknownTagsAreIgnored()
        {
            // Unknown tags must be ignored (RFC 9989 section 4.8)
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject; foo=bar; xyz=1:2:3");

            Assert.That(record.Policy, Is.EqualTo(ReceiverPolicy.Reject));
        }

        [Test]
        public void TestTrailingSeparator()
        {
            // A trailing separator is allowed (RFC 9989 section 4.8)
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject;");

            Assert.That(record.Policy, Is.EqualTo(ReceiverPolicy.Reject));

            var record2 = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject; ");

            Assert.That(record2.Policy, Is.EqualTo(ReceiverPolicy.Reject));
        }

        [Test]
        public void TestReportUris()
        {
            // Whitespace around commas is allowed and the obsolete size suffix is removed (RFC 9989 section 4.8)
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=none; rua=mailto:a@example.com , mailto:b@example.com!10m,https://example.com/dmarc!50K; ruf=mailto:c@example.com!5");

            Assert.That(record.AggregatedReportAddresses, Is.EqualTo(new[] { "mailto:a@example.com", "mailto:b@example.com", "https://example.com/dmarc" }));
            Assert.That(record.ForensicReportAddresses, Is.EqualTo(new[] { "mailto:c@example.com" }));
        }

        [TestCase("rua=reports@example.com")]           // Not a URI, the mailto scheme is missing
        [TestCase("rua=mailto:")]                        // No address
        [TestCase("rua=mailto:reports")]                 // No address
        [TestCase("rua=mailto:a@example.com,")]          // Empty entry
        [TestCase("rua=,mailto:a@example.com")]
        [TestCase("rua=mailto:a@example.com,,mailto:b@example.com")]
        [TestCase("rua=mailto:a@example.com, not a uri")]
        [TestCase("ruf=failures@example.com")]
        public void TestInvalidReportUris(string tag)
        {
            Assert.Throws<DmarcInvalidException>(() =>
            {
                DmarcCheck.ParseDmarcRecord("v=DMARC1; p=none; " + tag);
            });
        }

        [Test]
        [TestCase("")]
        [TestCase("v=DMARC1; adkim=s; aspf=x")]
        [TestCase("v=DMARC1; pct=10000")]
        [TestCase("v=DMARC1; pct=0100")]                 // 1*3DIGIT
        [TestCase("v=DMARC1; p=aaaa")]
        [TestCase("v=DMARC1; sp=aaaa")]
        [TestCase("v=DMARC1; np=aaaa")]
        [TestCase("v=DMARC1; t=maybe")]
        [TestCase("v=DMARC1; psd=x")]
        [TestCase("v=DMARC1; p=")]                       // Empty value
        [TestCase("v=DMARC1; p=reject; p=none")]         // Duplicate tag (RFC 6376 section 3.2)
        [TestCase("v=DMARC1; rua=mailto:a@example.com; rua=mailto:b@example.com")]
        [TestCase("v=DMARC1; p=reject; garbage")]        // Segment without a value
        [TestCase("v=DMARC1;; p=reject")]                // Empty segment in the middle
        [TestCase("v=DMARC1; p=reject; =none")]          // Empty tag name
        [TestCase("v=DMARC1; p=reject; p2=none")]        // Tag names are letters only
        [TestCase("v=DMARC1; p=reject; a-b=none")]
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
        public void TestNotFound()
        {
            var check = new DmarcCheck(new DummyResolver());

            Assert.Throws<DmarcNotFoundException>(() =>
            {
                check.GetDmarcRecord("example.com");
            });
        }

        // Domains that could alter the DNS query
        [TestCase("busi ness.nl")]
        [TestCase("business..nl")]
        [TestCase(".business.nl")]
        [TestCase("business.nl..")]
        [TestCase("busi\u0000ness.nl")]
        [TestCase("business.nl&type=A")]
        [TestCase("")]
        public void TestInvalidQueryInput(string domain)
        {
            var check = new DmarcCheck(new DummyResolver());

            Assert.Throws<ArgumentException>(() =>
            {
                check.GetDmarcRecord(domain);
            });
        }

        [Test]
        public void TestTrailingDotDomain()
        {
            var resolver = new DummyResolver("_dmarc.businessmonitor.nl", "v=DMARC1; p=reject");

            var check = new DmarcCheck(resolver);
            var record = check.GetDmarcRecord("businessmonitor.nl.");

            Assert.That(record.Policy, Is.EqualTo(ReceiverPolicy.Reject));
        }

        [Test]
        public void TestNullResolverResult()
        {
            var resolver = new DummyResolver { ReturnNullWhenEmpty = true };
            var check = new DmarcCheck(resolver);

            Assert.Throws<DmarcNotFoundException>(() =>
            {
                check.GetDmarcRecord("businessmonitor.nl");
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

        // Malformed numeric tags must throw DmarcInvalidException, not FormatException/OverflowException
        [TestCase("v=DMARC1; p=none; pct=abc")]
        [TestCase("v=DMARC1; p=none; pct=")]
        [TestCase("v=DMARC1; p=none; pct=+50")]
        [TestCase("v=DMARC1; p=none; pct=1O")]
        [TestCase("v=DMARC1; p=none; pct=99999999999999999999")]
        [TestCase("v=DMARC1; p=none; ri=abc")]
        [TestCase("v=DMARC1; p=none; ri=-1")]
        [TestCase("v=DMARC1; p=none; ri=+86400")]
        [TestCase("v=DMARC1; p=none; ri=99999999999999999999")]
        public void TestInvalidNumericTags(string value)
        {
            Assert.Throws<DmarcInvalidException>(() =>
            {
                DmarcCheck.ParseDmarcRecord(value);
            });
        }

        [Test]
        public void TestValidNumericTags()
        {
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=none; pct=50; ri=86400");

            Assert.That(record.PercentageTag, Is.EqualTo(50));
            Assert.That(record.ReportInterval, Is.EqualTo(86400));

            var record2 = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=none; pct=0");

            Assert.That(record2.PercentageTag, Is.EqualTo(0));
        }
    }
}
