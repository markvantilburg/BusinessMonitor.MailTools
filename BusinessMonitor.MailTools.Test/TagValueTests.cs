using BusinessMonitor.MailTools.Util;
using NUnit.Framework;

namespace BusinessMonitor.MailTools.Test
{
    internal class TagValueTests
    {
        [TestCase("v")]
        [TestCase("p")]
        [TestCase("rua")]
        [TestCase("V")]
        [TestCase("h1")]
        [TestCase("x_y")]
        [TestCase("a1_")]
        public void TestValidTagName(string value)
        {
            Assert.That(TagValue.IsValidTagName(value), Is.True);
        }

        [TestCase("")]
        [TestCase("1v")]
        [TestCase("_v")]
        [TestCase("v-1")]
        [TestCase("v 1")]
        [TestCase("v.1")]
        [TestCase("\u00EF")]
        public void TestInvalidTagName(string value)
        {
            Assert.That(TagValue.IsValidTagName(value), Is.False);
        }

        [TestCase("v")]
        [TestCase("rua")]
        [TestCase("ADKIM")]
        public void TestValidAlphaTagName(string value)
        {
            Assert.That(TagValue.IsValidAlphaTagName(value), Is.True);
        }

        [TestCase("")]
        [TestCase("h1")]
        [TestCase("x_y")]
        [TestCase("v-1")]
        [TestCase("v 1")]
        [TestCase("\u00EF")]
        public void TestInvalidAlphaTagName(string value)
        {
            Assert.That(TagValue.IsValidAlphaTagName(value), Is.False);
        }

        [TestCase("v=DMARC1; p=reject", "v", "DMARC1")]
        [TestCase(" v = DMARC1 ; p=reject", "v", "DMARC1")]
        [TestCase("v=DMARC1", "v", "DMARC1")]
        [TestCase("p=reject; v=DMARC1", "p", "reject")]
        [TestCase("v=", "v", "")]
        [TestCase("p=abc=def;", "p", "abc=def")]
        public void TestTryGetFirstTag(string record, string name, string value)
        {
            Assert.That(TagValue.TryGetFirstTag(record, out var n, out var v), Is.True);
            Assert.That(n, Is.EqualTo(name));
            Assert.That(v, Is.EqualTo(value));
        }

        [TestCase("")]
        [TestCase("DMARC1")]
        [TestCase("v;p=reject")]
        [TestCase(";v=DMARC1")]
        public void TestTryGetFirstTagWithoutTag(string record)
        {
            Assert.That(TagValue.TryGetFirstTag(record, out _, out _), Is.False);
        }

        [TestCase("v=DMARC1; p=reject", "DMARC1")]
        [TestCase(" v = DMARC1 ", "DMARC1")]
        [TestCase("v=BIMI1;l=", "BIMI1")]
        public void TestHasVersion(string record, string version)
        {
            Assert.That(TagValue.HasVersion(record, version), Is.True);
        }

        [TestCase("v=dmarc1; p=reject", "DMARC1")] // Case sensitive
        [TestCase("V=DMARC1; p=reject", "DMARC1")] // Tag names are case sensitive too
        [TestCase("p=reject; v=DMARC1", "DMARC1")] // Must be the first tag
        [TestCase("v=DMARC1.0", "DMARC1")]
        [TestCase("v=DMARC1", "BIMI1")]
        [TestCase("", "DMARC1")]
        public void TestHasVersionFalse(string record, string version)
        {
            Assert.That(TagValue.HasVersion(record, version), Is.False);
        }
    }
}
