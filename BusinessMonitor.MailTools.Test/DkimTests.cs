using BusinessMonitor.MailTools.Dkim;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Test.Dns;
using NUnit.Framework;
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
        public void TestRevoked()
        {
            var record = DkimCheck.ParseDkimRecord("v=DKIM1; p=");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.PublicKey, Is.Empty);
        }
    }
}
