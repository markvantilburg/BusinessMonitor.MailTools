using BusinessMonitor.MailTools.Dkim;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Test.Dns;
using NUnit.Framework;

namespace BusinessMonitor.MailTools.Test
{
    internal class DkimTests
    {
        [Test]
        public void TestParse()
        {
            var record = DkimCheck.ParseDkimRecord("v=DKIM1; p=7JWI64WVIQ==; n=Hello, World!");

            Assert.IsNotNull(record);
            Assert.AreEqual("7JWI64WVIQ==", record.PublicKey);
            Assert.AreEqual("Hello, World!", record.Notes);
            Assert.AreEqual("rsa", record.KeyType);
            Assert.AreEqual(0, record.Algorithms.Length);
        }

        [Test]
        public void TestFlags()
        {
            var record = DkimCheck.ParseDkimRecord("v=DKIM1; p=7JWI64WVIQ==; t=y:s");

            Assert.IsNotNull(record);
            Assert.IsTrue((record.Flags & DkimFlags.Testing) != 0);
            Assert.IsTrue((record.Flags & DkimFlags.SameDomain) != 0);

            var record2 = DkimCheck.ParseDkimRecord("v=DKIM1; p=7JWI64WVIQ==");

            Assert.IsNotNull(record2);
            Assert.AreEqual(DkimFlags.None, record2.Flags);
        }

        [Test]
        public void TestLookup()
        {
            var resolver = new DummyResolver("test._domainkey.businessmonitor.nl", "v=DKIM1; p=7JWI64WVIQ==; n=Hello, World!");

            var check = new DkimCheck(resolver);
            var record = check.GetDkimRecord("businessmonitor.nl", "test");

            Assert.IsNotNull(record);
            Assert.AreEqual("7JWI64WVIQ==", record.PublicKey);
            Assert.AreEqual("Hello, World!", record.Notes);
        }

        [Test]
        [TestCase("")]
        [TestCase("v=DKIM1; n=Notes")]
        [TestCase("v=DKIM1; p=?NotAValidBase64String?")]
        public void TestInvalid(string value)
        {
            Assert.Throws<InvalidDkimException>(() =>
            {
                DkimCheck.ParseDkimRecord(value);
            });
        }

        [Test]
        public void TestRevoked()
        {
            var record = DkimCheck.ParseDkimRecord("v=DKIM1; p=");

            Assert.IsNotNull(record);
            Assert.IsEmpty(record.PublicKey);
        }
    }
}
