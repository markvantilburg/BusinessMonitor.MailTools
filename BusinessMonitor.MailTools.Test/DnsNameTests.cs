using BusinessMonitor.MailTools.Util;
using NUnit.Framework;
using System;
using System.Linq;

namespace BusinessMonitor.MailTools.Test
{
    internal class DnsNameTests
    {
        [Test]
        [TestCase("a")]
        [TestCase("abc")]
        [TestCase("a-b")]
        [TestCase("a1")]
        [TestCase("1a")]
        [TestCase("_dmarc")]        // Labels may start with an underscore
        [TestCase("a_b")]
        [TestCase("a--b")]
        public void TestValidLabel(string value)
        {
            Assert.That(DnsName.IsValidLabel(value), Is.True);
        }

        [Test]
        [TestCase("")]
        [TestCase("-a")]            // Must not start or end with a hyphen
        [TestCase("a-")]
        [TestCase("-")]
        [TestCase("a b")]
        [TestCase("a.b")]
        [TestCase("a/b")]
        [TestCase("a\0b")]
        [TestCase("äbc")]      // No non-ASCII characters
        public void TestInvalidLabel(string value)
        {
            Assert.That(DnsName.IsValidLabel(value), Is.False);
        }

        [Test]
        public void TestLabelLength()
        {
            // A label is at most 63 characters
            Assert.That(DnsName.IsValidLabel(new string('a', 63)), Is.True);
            Assert.That(DnsName.IsValidLabel(new string('a', 64)), Is.False);
        }

        [Test]
        [TestCase("example.com")]
        [TestCase("a.b.c")]
        [TestCase("localhost")]     // A single label is a valid DNS name
        [TestCase("_spf.example.com")]
        [TestCase("xn--bcher-kva.example")]
        public void TestValidName(string value)
        {
            Assert.That(DnsName.IsValidName(value), Is.True);
        }

        [Test]
        [TestCase("")]
        [TestCase(".")]
        [TestCase("a..b")]          // Empty labels are not allowed
        [TestCase(".example.com")]
        [TestCase("example.com.")]
        [TestCase("exa mple.com")]
        [TestCase("example-.com")]
        public void TestInvalidName(string value)
        {
            Assert.That(DnsName.IsValidName(value), Is.False);
        }

        [Test]
        public void TestNameLength()
        {
            // A name is at most 253 characters
            var labels = Enumerable.Repeat(new string('a', 63), 3).ToList();

            labels.Add(new string('a', 61));
            var name = string.Join(".", labels);    // 253 characters

            Assert.That(name, Has.Length.EqualTo(253));
            Assert.That(DnsName.IsValidName(name), Is.True);

            labels[3] = new string('a', 62);
            name = string.Join(".", labels);        // 254 characters

            Assert.That(DnsName.IsValidName(name), Is.False);
        }

        [Test]
        public void TestValidateDomain()
        {
            Assert.DoesNotThrow(() =>
            {
                DnsName.ValidateDomain("example.com", "domain");
            });

            Assert.Throws<ArgumentNullException>(() =>
            {
                DnsName.ValidateDomain(null, "domain");
            });

            Assert.Throws<ArgumentException>(() =>
            {
                DnsName.ValidateDomain(new string('a', 300), "domain");
            });

            Assert.Throws<ArgumentException>(() =>
            {
                DnsName.ValidateDomain("not..a..domain", "domain");
            });
        }

        [Test]
        public void TestValidateSelector()
        {
            // A selector is a sub-domain and may consist of multiple labels
            Assert.DoesNotThrow(() =>
            {
                DnsName.ValidateSelector("selector", "selector");
            });

            Assert.DoesNotThrow(() =>
            {
                DnsName.ValidateSelector("s1.s2", "selector");
            });

            Assert.Throws<ArgumentNullException>(() =>
            {
                DnsName.ValidateSelector(null, "selector");
            });

            Assert.Throws<ArgumentException>(() =>
            {
                DnsName.ValidateSelector(".selector", "selector");
            });

            Assert.Throws<ArgumentException>(() =>
            {
                DnsName.ValidateSelector("sel ector", "selector");
            });
        }
    }
}
