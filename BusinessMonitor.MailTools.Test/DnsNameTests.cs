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
        [TestCase("abc\n")]   // A trailing newline is not part of a label, $ in a .NET regex would accept it
        [TestCase("abc\r\n")]
        [TestCase("\nabc")]
        [TestCase("a\nb")]
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

        [Test]
        public void TestValidateDomainTrailingDot()
        {
            // The absolute form is accepted and the trailing dot removed
            Assert.That(DnsName.ValidateDomain("example.com.", "domain"), Is.EqualTo("example.com"));
            Assert.That(DnsName.ValidateDomain("example.com", "domain"), Is.EqualTo("example.com"));

            // The length limit applies to the name without the dot
            Assert.That(DnsName.ValidateDomain(new string('a', 63) + "." + new string('b', 63) + "." + new string('c', 63) + "." + new string('d', 61) + ".", "domain").Length, Is.EqualTo(253));

            Assert.Throws<ArgumentException>(() =>
            {
                DnsName.ValidateDomain("example.com..", "domain");
            });

            Assert.Throws<ArgumentException>(() =>
            {
                DnsName.ValidateDomain(".", "domain");
            });
        }

        [TestCase("mail.example.com", "mail.example.com")]
        [TestCase("mail.example.com.", "mail.example.com")]   // Single trailing dot is removed
        [TestCase("MAIL.Example.COM", "MAIL.Example.COM")]    // Case is preserved
        [TestCase("3com.com", "3com.com")]                    // A label may start with a digit (RFC 1123)
        [TestCase("mail-1.example.com", "mail-1.example.com")]
        [TestCase("a.b.c.d.example.com", "a.b.c.d.example.com")]
        [TestCase("mail", "mail")]                            // A single label is a valid host name
        [TestCase("mail.example.c0m", "mail.example.c0m")]    // A TLD with a digit is not all digits
        public void TestTryNormalizeHostValid(string value, string expected)
        {
            Assert.That(DnsName.TryNormalizeHost(value, out var host), Is.True);
            Assert.That(host, Is.EqualTo(expected));
        }

        [Test]
        public void TestTryNormalizeHostMaxLabelLength()
        {
            Assert.That(DnsName.TryNormalizeHost(new string('a', 63) + ".example.com", out _), Is.True);
            Assert.That(DnsName.TryNormalizeHost(new string('a', 64) + ".example.com", out _), Is.False);
        }

        [TestCase(null)]
        [TestCase("")]
        [TestCase(".")]
        [TestCase("mail.example.com..")]
        [TestCase("mail example.com")]
        [TestCase("mail.example.com&type=TXT")]
        [TestCase("-mail.example.com")]
        [TestCase("mail.example.com-")]
        [TestCase("mail.-example.com")]
        [TestCase("mail\u0000.example.com")]
        [TestCase("mail.example.com/x")]
        // An MX exchange is a host name (RFC 1123 section 2.1), underscores are not allowed
        [TestCase("_spf.example.com")]
        [TestCase("_mx.example.com")]
        [TestCase("mail._tcp.example.com")]
        [TestCase("mail_1.example.com")]
        // IP address literals and numeric top-level domains are not host names
        [TestCase("192.0.2.1")]
        [TestCase("192.0.2.1.")]
        [TestCase("10.0.0.1")]
        [TestCase("2001:db8::1")]
        [TestCase("[2001:db8::1]")]
        [TestCase("::1")]
        [TestCase("mail.example.123")]
        [TestCase("1")]
        public void TestTryNormalizeHostInvalid(string value)
        {
            Assert.That(DnsName.TryNormalizeHost(value, out _), Is.False);
        }

        [TestCase("mail.example.com", true)]
        [TestCase("3com.com", true)]
        [TestCase("mail", true)]
        [TestCase("_spf.example.com", false)]  // Valid DNS name, not a host name
        [TestCase("192.0.2.1", false)]
        [TestCase("mail.example.123", false)]
        [TestCase("mail.example.com.", false)] // The trailing dot is not removed here
        [TestCase("", false)]
        [TestCase(null, false)]
        public void TestIsValidHostName(string value, bool expected)
        {
            Assert.That(DnsName.IsValidHostName(value), Is.EqualTo(expected));
        }

        [Test]
        public void TestIsValidHostNameMaxLength()
        {
            var name = new string('a', 63) + "." + new string('b', 63) + "." + new string('c', 63) + "." + new string('d', 61);

            Assert.That(name.Length, Is.EqualTo(253));
            Assert.That(DnsName.IsValidHostName(name), Is.True);
            Assert.That(DnsName.IsValidHostName(name + "e"), Is.False);
        }

        [TestCase(".", true)]
        [TestCase("", true)]
        [TestCase("mail.example.com.", false)]
        [TestCase(null, false)]
        public void TestIsNullMx(string value, bool expected)
        {
            Assert.That(DnsName.IsNullMx(value), Is.EqualTo(expected));
        }
    }
}
