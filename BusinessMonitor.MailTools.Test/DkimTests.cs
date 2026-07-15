using BusinessMonitor.MailTools.Dkim;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Test.Dns;
using NUnit.Framework;
using System.Linq;
using System;

namespace BusinessMonitor.MailTools.Test
{
    internal class DkimTests
    {
        [Test]
        public void TestParse()
        {
            var record = DkimCheck.ParseDkimRecord("v=DKIM1; p=7JWI64WVIQ==; n=Hello, World!");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.PublicKey, Is.EqualTo("7JWI64WVIQ=="));
            Assert.That(record.Notes, Is.EqualTo("Hello, World!"));
            Assert.That(record.KeyType, Is.EqualTo("rsa"));
            Assert.That(record.Algorithms.Length, Is.EqualTo(0));

            var record2 = DkimCheck.ParseDkimRecord("v=DKIM1; p=7JWI64WVIQ==; h=sha1:sha256; k=ed25519; s=email");

            Assert.That(record2.Algorithms, Does.Contain("sha1"));
            Assert.That(record2.KeyType, Is.EqualTo("ed25519"));
            Assert.That(record2.ServiceType, Does.Contain("email"));
        }

        [Test]
        public void TestFlags()
        {
            var record = DkimCheck.ParseDkimRecord("v=DKIM1; p=7JWI64WVIQ==; t=y:s");

            Assert.That(record, Is.Not.Null);
            Assert.That((record.Flags & DkimFlags.Testing) != 0, Is.True);
            Assert.That((record.Flags & DkimFlags.SameDomain) != 0, Is.True);

            var record2 = DkimCheck.ParseDkimRecord("v=DKIM1; p=7JWI64WVIQ==");

            Assert.That(record2, Is.Not.Null);
            Assert.That(record2.Flags, Is.EqualTo(DkimFlags.None));
        }

        [Test]
        public void TestLookup()
        {
            var resolver = new DummyResolver("test._domainkey.businessmonitor.nl", "v=DKIM1; p=7JWI64WVIQ==; n=Hello, World!");

            var check = new DkimCheck(resolver);
            var record = check.GetDkimRecord("businessmonitor.nl", "test");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.PublicKey, Is.EqualTo("7JWI64WVIQ=="));
            Assert.That(record.Notes, Is.EqualTo("Hello, World!"));
        }

        [Test]
        [TestCase("")]
        [TestCase("v=DKIM1; n=Notes")]
        [TestCase("v=DKIM1; p=?NotAValidBase64String?")]
        public void TestInvalid(string value)
        {
            Assert.Throws<DkimInvalidException>(() =>
            {
                DkimCheck.ParseDkimRecord(value);
            });
        }

        [Test]
        public void TestInvalidArguments()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new DkimCheck(null);
            });

            var check = new DkimCheck(new DummyResolver());

            Assert.Throws<ArgumentNullException>(() =>
            {
                check.GetDkimRecord(null, "test");
            });

            Assert.Throws<ArgumentNullException>(() =>
            {
                check.GetDkimRecord("test", null);
            });

            Assert.Throws<ArgumentException>(() =>
            {
                var domain = new string('a', 300);

                check.GetDkimRecord(domain, "test");
            });

            Assert.Throws<ArgumentNullException>(() =>
            {
                DkimCheck.ParseDkimRecord(null);
            });
        }

        [Test]
        public void TestNotFound()
        {
            var check = new DkimCheck(new DummyResolver());

            Assert.Throws<DkimNotFoundException>(() =>
            {
                check.GetDkimRecord("example.com", "test");
            });
        }

        [Test]
        public void TestRevoked()
        {
            var record = DkimCheck.ParseDkimRecord("v=DKIM1; p=");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.PublicKey, Is.Empty);
        }
    
        // Selectors and domains that could alter the DNS query
        [TestCase("business.nl", "sel ector")]
        [TestCase("business.nl", "sel..ector")]
        [TestCase("business.nl", ".selector")]
        [TestCase("business.nl", "selector.")]
        [TestCase("business.nl", "sel\u0000ector")]
        [TestCase("business.nl", "sel/ector")]
        [TestCase("business.nl", "-selector")]
        [TestCase("business.nl", "")]
        [TestCase("busi ness.nl", "default")]
        [TestCase("business..nl", "default")]
        [TestCase(".business.nl", "default")]
        [TestCase("business.nl.", "default")]
        public void TestInvalidQueryInput(string domain, string selector)
        {
            var check = new DkimCheck(new DummyResolver());

            Assert.Throws<ArgumentException>(() =>
            {
                check.GetDkimRecord(domain, selector);
            });
        }

        [Test]
        public void TestMultiLabelSelector()
        {
            // Selectors are sub-domains and may contain multiple labels
            var resolver = new DummyResolver("s1.s2._domainkey.business.nl", "v=DKIM1; p=");
            var check = new DkimCheck(resolver);

            Assert.DoesNotThrow(() =>
            {
                check.GetDkimRecord("business.nl", "s1.s2");
            });
        }

        [Test]
        public void TestCombinedNameTooLong()
        {
            var check = new DkimCheck(new DummyResolver());
            var domain = string.Join(".", Enumerable.Repeat(new string('a', 60), 4)); // 243 chars, valid on its own

            Assert.Throws<ArgumentException>(() =>
            {
                check.GetDkimRecord(domain, "selector");
            });
        }

    }
}
