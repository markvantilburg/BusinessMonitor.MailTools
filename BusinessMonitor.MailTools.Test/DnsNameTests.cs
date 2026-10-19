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

        [TestCase("example.com", "example.com")]
        [TestCase("Example.COM", "Example.COM")]                   // ASCII input is returned unchanged, case included
        [TestCase("xn--bcher-kva.de", "xn--bcher-kva.de")]         // Already an A-label
        [TestCase("bücher.de", "xn--bcher-kva.de")]
        [TestCase("Bücher.DE", "xn--bcher-kva.de")]                // IDNA mapping lower-cases the converted name
        [TestCase("bücher.de.", "xn--bcher-kva.de")]               // Trailing dot is removed before conversion
        [TestCase("mail.bücher.de", "mail.xn--bcher-kva.de")]      // ASCII labels are left alone
        [TestCase("münchen.de", "xn--mnchen-3ya.de")]
        [TestCase("例え.jp", "xn--r8jz45g.jp")]
        [TestCase("_dmarc.bücher.de", "_dmarc.xn--bcher-kva.de")]  // Underscore labels survive the conversion
        public void TestValidateDomainIdn(string value, string expected)
        {
            Assert.That(DnsName.ValidateDomain(value, "domain"), Is.EqualTo(expected));
        }

        [Test]
        public void TestValidateDomainIdnSharpS()
        {
            // IDNA2003 (.NET Framework, NLS) maps ß to ss, UTS #46 / IDNA2008 (ICU) keeps it, both are
            // valid outcomes of the runtime and are different registered domains
            Assert.That(DnsName.ValidateDomain("faß.de", "domain"), Is.AnyOf("fass.de", "xn--fa-hia.de"));
        }

        [TestCase("bü cher.de")]                 // Space
        [TestCase("bücher..de")]                 // Empty label
        [TestCase(".bücher.de")]
        [TestCase("bücher.de..")]
        [TestCase("bü\u0000cher.de")]            // Control character
        [TestCase("xn--bücher.de")]              // Mixed A-label prefix and U-label
        public void TestValidateDomainIdnInvalid(string value)
        {
            var ex = Assert.Throws<ArgumentException>(() => DnsName.ValidateDomain(value, "domain"));

            Assert.That(ex.ParamName, Is.EqualTo("domain"));
        }

        [Test]
        public void TestValidateDomainIdnLabelTooLong()
        {
            // The 63 character label limit applies to the A-label, 70 ü encode to more than that
            Assert.Throws<ArgumentException>(() => DnsName.ValidateDomain(new string('\u00FC', 70) + ".de", "domain"));
        }

        [Test]
        public void TestValidateDomainIdnMessageDoesNotEchoRawInput()
        {
            // The raw value may contain anything, the message names the parameter instead
            var ex = Assert.Throws<ArgumentException>(() => DnsName.ValidateDomain("bü cher.de", "domain"));

            Assert.That(ex.Message, Does.Contain("internationalized domain name"));
            Assert.That(ex.Message, Does.Not.Contain("bü cher"));
        }

        [TestCase("selector", "selector")]
        [TestCase("Selector", "Selector")]
        [TestCase("s1.s2", "s1.s2")]
        [TestCase("sélecteur", "xn--slecteur-b1a")]
        [TestCase("sélecteur.s2", "xn--slecteur-b1a.s2")]
        public void TestValidateSelectorReturnsAsciiForm(string value, string expected)
        {
            Assert.That(DnsName.ValidateSelector(value, "selector"), Is.EqualTo(expected));
        }

        [TestCase("sé lecteur")]
        [TestCase("sélecteur..s2")]
        public void TestValidateSelectorIdnInvalid(string value)
        {
            Assert.Throws<ArgumentException>(() => DnsName.ValidateSelector(value, "selector"));
        }

        [TestCase("example.com", "example.com")]
        [TestCase("Example.COM", "Example.COM")]
        [TestCase("bücher.de", "xn--bcher-kva.de")]
        public void TestToAsciiName(string value, string expected)
        {
            Assert.That(DnsName.ToAsciiName(value, "value"), Is.EqualTo(expected));
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
        // Special-use names never receive internet mail
        [TestCase("localhost")]
        [TestCase("LOCALHOST.")]
        [TestCase("mail.localhost")]
        [TestCase("mail.local")]
        [TestCase("mail.internal")]
        [TestCase("mail.home.arpa")]
        [TestCase("mail.onion")]
        [TestCase("mail.test")]
        [TestCase("mail.example")]
        [TestCase("mail.invalid")]
        public void TestTryNormalizeHostInvalid(string value)
        {
            Assert.That(DnsName.TryNormalizeHost(value, out _), Is.False);
        }

        [TestCase("localhost", true)]
        [TestCase("LocalHost", true)]
        [TestCase("mail.localhost", true)]
        [TestCase("a.b.localhost", true)]
        [TestCase("test", true)]
        [TestCase("mail.test", true)]
        [TestCase("example", true)]
        [TestCase("mail.example", true)]
        [TestCase("invalid", true)]
        [TestCase("mail.invalid", true)]
        [TestCase("local", true)]
        [TestCase("printer.local", true)]
        [TestCase("onion", true)]
        [TestCase("abc.onion", true)]
        [TestCase("home.arpa", true)]
        [TestCase("router.home.arpa", true)]
        [TestCase("internal", true)]
        [TestCase("mail.corp.internal", true)]
        // Similar but delegated names
        [TestCase("notlocalhost", false)]
        [TestCase("localhost.example.com", false)]
        [TestCase("example.com", false)]
        [TestCase("mail.example.com", false)]
        [TestCase("internal.example.com", false)]
        [TestCase("mylocal.com", false)]
        [TestCase("local.example.com", false)]
        [TestCase("arpa", false)]
        [TestCase("mail.in-addr.arpa", false)]
        [TestCase("test.com", false)]
        [TestCase("onion.example.com", false)]
        [TestCase("", false)]
        [TestCase(null, false)]
        public void TestIsSpecialUseName(string value, bool expected)
        {
            Assert.That(DnsName.IsSpecialUseName(value), Is.EqualTo(expected));
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
