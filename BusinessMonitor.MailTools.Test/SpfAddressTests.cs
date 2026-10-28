using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Spf;
using NUnit.Framework;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace BusinessMonitor.MailTools.Test
{
    internal class SpfAddressTests
    {
        [Test]
        public void TestParseIPv4WithoutPrefix()
        {
            var address = SpfAddress.Parse("192.0.2.1", AddressFamily.InterNetwork);

            Assert.That(address.Address, Is.EqualTo(IPAddress.Parse("192.0.2.1")));
            Assert.That(address.Length, Is.Null);
        }

        [Test]
        public void TestParseIPv4WithPrefix()
        {
            var address = SpfAddress.Parse("192.0.2.0/24", AddressFamily.InterNetwork);

            Assert.That(address.Address, Is.EqualTo(IPAddress.Parse("192.0.2.0")));
            Assert.That(address.Length, Is.EqualTo(24));
        }

        [TestCase("192.0.2.1/0", 0)]
        [TestCase("192.0.2.1/32", 32)]
        public void TestParseIPv4PrefixBounds(string value, int length)
        {
            Assert.That(SpfAddress.Parse(value, AddressFamily.InterNetwork).Length, Is.EqualTo(length));
        }

        [Test]
        public void TestParseIPv6WithoutPrefix()
        {
            var address = SpfAddress.Parse("2001:db8::1", AddressFamily.InterNetworkV6);

            Assert.That(address.Address, Is.EqualTo(IPAddress.Parse("2001:db8::1")));
            Assert.That(address.Length, Is.Null);
        }

        [Test]
        public void TestParseIPv6WithPrefix()
        {
            var address = SpfAddress.Parse("2001:db8::/32", AddressFamily.InterNetworkV6);

            Assert.That(address.Address, Is.EqualTo(IPAddress.Parse("2001:db8::")));
            Assert.That(address.Length, Is.EqualTo(32));
        }

        [TestCase("2001:db8::1/0", 0)]
        [TestCase("2001:db8::1/128", 128)]
        public void TestParseIPv6PrefixBounds(string value, int length)
        {
            Assert.That(SpfAddress.Parse(value, AddressFamily.InterNetworkV6).Length, Is.EqualTo(length));
        }

        [TestCase("192.0.2.1/33")]            // Above the IPv4 maximum
        [TestCase("192.0.2.1/128")]           // IPv6 maximum is not valid for IPv4
        [TestCase("192.0.2.1/-1")]            // Negative, NumberStyles.None rejects the sign
        [TestCase("192.0.2.1/024")]           // Leading zero (RFC 7208 section 12)
        [TestCase("192.0.2.1/00")]            // Leading zero
        [TestCase("192.0.2.1/")]              // Empty prefix
        [TestCase("192.0.2.1/abc")]           // Not a number
        [TestCase("192.0.2.1/24/24")]         // Second slash ends up in the prefix
        [TestCase("192.0.2.1/ 24")]           // Whitespace
        [TestCase("192.0.2.1/+24")]           // Sign
        [TestCase("192.0.2.1/2147483648")]    // Overflow
        public void TestParseIPv4InvalidPrefix(string value)
        {
            Assert.Throws<SpfInvalidException>(() => SpfAddress.Parse(value, AddressFamily.InterNetwork));
        }

        [TestCase("2001:db8::1/129")]         // Above the IPv6 maximum
        [TestCase("2001:db8::1/-1")]
        [TestCase("2001:db8::1/064")]         // Leading zero
        [TestCase("2001:db8::1/")]
        [TestCase("2001:db8::1/x")]
        public void TestParseIPv6InvalidPrefix(string value)
        {
            Assert.Throws<SpfInvalidException>(() => SpfAddress.Parse(value, AddressFamily.InterNetworkV6));
        }

        [TestCase("")]                        // Empty
        [TestCase("not-an-ip")]
        [TestCase("192.0.2")]                 // .NET parses this shorthand as 192.0.0.2, SPF requires a full dotted quad
        [TestCase("192.0.2.1.5")]             // Too many octets
        [TestCase("192.0.2.256")]             // Octet out of range
        [TestCase("192.000.2.1")]             // Leading zeros in an octet (RFC 7208 section 12)
        [TestCase("192.0.2.01")]
        [TestCase("0x7F.0.0.1")]              // Hex octet .NET accepts
        [TestCase("015.1.1.1")]               // Octal octet .NET accepts
        [TestCase("2130706433")]              // Decimal form of 127.0.0.1
        [TestCase("192.0.2.1%eth0")]          // Zone identifier
        public void TestParseInvalidIPv4(string value)
        {
            Assert.Throws<SpfInvalidException>(() => SpfAddress.Parse(value, AddressFamily.InterNetwork));
        }

        [TestCase("")]
        [TestCase("not-an-ip")]
        [TestCase("2001:db8:::1")]            // Triple colon
        [TestCase("2001:db8::1::2")]          // Two double colons
        [TestCase("2001:db8::g")]             // Invalid hex digit
        [TestCase("fe80::1%eth0")]            // Zone identifier (RFC 7208 section 12)
        [TestCase("fe80::1%25")]
        [TestCase("fe80::1%")]
        [TestCase("[2001:db8::1]")]           // Bracketed address, accepted by .NET but not by the grammar
        [TestCase("[2001:db8::1]:25")]        // Bracketed address with a port
        [TestCase("[2001:db8::1]/64")]
        public void TestParseInvalidIPv6(string value)
        {
            Assert.Throws<SpfInvalidException>(() => SpfAddress.Parse(value, AddressFamily.InterNetworkV6));
        }

        [TestCase("2001:db8::1")]
        [TestCase("2001:db8::1/64")]
        [TestCase("::1")]
        [TestCase("::ffff:192.0.2.1")]        // IPv4-mapped IPv6 is still IPv6
        public void TestParseIPv6RejectedForIp4(string value)
        {
            Assert.Throws<SpfInvalidException>(() => SpfAddress.Parse(value, AddressFamily.InterNetwork));
        }

        [TestCase("192.0.2.1")]
        [TestCase("192.0.2.0/24")]
        public void TestParseIPv4RejectedForIp6(string value)
        {
            Assert.Throws<SpfInvalidException>(() => SpfAddress.Parse(value, AddressFamily.InterNetworkV6));
        }

        [Test]
        public void TestParseIPv4ZeroOctetsAreAllowed()
        {
            // A single zero is not a leading zero
            var address = SpfAddress.Parse("0.0.0.0/0", AddressFamily.InterNetwork);

            Assert.That(address.Address, Is.EqualTo(IPAddress.Any));
            Assert.That(address.Length, Is.EqualTo(0));
        }

        [Test]
        public void TestEqualsSameNetwork()
        {
            var a = SpfAddress.Parse("192.0.2.0/24", AddressFamily.InterNetwork);
            var b = SpfAddress.Parse("192.0.2.0/24", AddressFamily.InterNetwork);

            Assert.That(a.Equals(b), Is.True);
            Assert.That(a == b, Is.True);
            Assert.That(a.GetHashCode(), Is.EqualTo(b.GetHashCode()));
        }

        [TestCase("192.0.2.1", "192.0.2.1/32", AddressFamily.InterNetwork)]
        [TestCase("192.0.2.1/32", "192.0.2.1", AddressFamily.InterNetwork)]
        [TestCase("2001:db8::1", "2001:db8::1/128", AddressFamily.InterNetworkV6)]
        [TestCase("2001:db8::1/128", "2001:db8::1", AddressFamily.InterNetworkV6)]
        public void TestEqualsSingleAddressAndFullPrefix(string first, string second, AddressFamily family)
        {
            // A mechanism without a prefix covers the single address, which is the same
            // network as the full prefix length (RFC 7208 section 5.6)
            var a = SpfAddress.Parse(first, family);
            var b = SpfAddress.Parse(second, family);

            Assert.That(a.Equals(b), Is.True);
            Assert.That(a == b, Is.True);
            Assert.That(a.GetHashCode(), Is.EqualTo(b.GetHashCode()));
        }

        [TestCase("192.0.2.0/24", "192.0.2.1/24", AddressFamily.InterNetwork)]
        [TestCase("192.0.2.1/24", "192.0.2.255/24", AddressFamily.InterNetwork)]
        [TestCase("192.0.2.0/25", "192.0.2.127/25", AddressFamily.InterNetwork)]   // Partial byte prefix
        [TestCase("10.1.2.3/8", "10.255.255.255/8", AddressFamily.InterNetwork)]
        [TestCase("1.2.3.4/0", "5.6.7.8/0", AddressFamily.InterNetwork)]           // A zero prefix covers everything
        [TestCase("2001:db8::/32", "2001:db8:ffff::1/32", AddressFamily.InterNetworkV6)]
        [TestCase("2001:db8::/33", "2001:db8:7fff::1/33", AddressFamily.InterNetworkV6)]
        public void TestEqualsSameNetworkDifferentBase(string first, string second, AddressFamily family)
        {
            // The host bits of the prefix are ignored (RFC 7208 section 5.6), both cover the same network
            var a = SpfAddress.Parse(first, family);
            var b = SpfAddress.Parse(second, family);

            Assert.That(a.Equals(b), Is.True);
            Assert.That(a == b, Is.True);
            Assert.That(a.GetHashCode(), Is.EqualTo(b.GetHashCode()));
            Assert.That(a.Network, Is.EqualTo(b.Network));
        }

        [TestCase("192.0.2.1/24", "192.0.2.0")]
        [TestCase("192.0.2.129/25", "192.0.2.128")]
        [TestCase("192.0.2.1", "192.0.2.1")]
        [TestCase("1.2.3.4/0", "0.0.0.0")]
        [TestCase("2001:db8:ffff::1/32", "2001:db8::")]
        [TestCase("2001:db8::1", "2001:db8::1")]
        public void TestNetwork(string value, string expected)
        {
            var family = value.IndexOf(':') != -1 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            var address = SpfAddress.Parse(value, family);

            Assert.That(address.Network, Is.EqualTo(IPAddress.Parse(expected)));
            Assert.That(address.ToString(), Is.EqualTo(value)); // The address is kept as written
        }

        [TestCase("192.0.2.0/24", "192.0.2.0/25", AddressFamily.InterNetwork)]     // Different prefix
        [TestCase("192.0.2.0/25", "192.0.2.128/25", AddressFamily.InterNetwork)]   // Differ in the partial byte
        [TestCase("192.0.2.0/24", "192.0.3.0/24", AddressFamily.InterNetwork)]     // Different network
        [TestCase("192.0.2.0/24", "192.0.3.0/24", AddressFamily.InterNetwork)]     // Different network
        [TestCase("192.0.2.1", "192.0.2.2", AddressFamily.InterNetwork)]           // Different single address
        [TestCase("192.0.2.1", "192.0.2.1/31", AddressFamily.InterNetwork)]        // Single address is not a /31
        [TestCase("2001:db8::/32", "2001:db8::/48", AddressFamily.InterNetworkV6)]
        [TestCase("2001:db8::1", "2001:db8::2", AddressFamily.InterNetworkV6)]
        public void TestNotEquals(string first, string second, AddressFamily family)
        {
            var a = SpfAddress.Parse(first, family);
            var b = SpfAddress.Parse(second, family);

            Assert.That(a.Equals(b), Is.False);
            Assert.That(a != b, Is.True);
        }

        [Test]
        public void TestNotEqualsAcrossAddressFamilies()
        {
            var a = SpfAddress.Parse("0.0.0.0/0", AddressFamily.InterNetwork);
            var b = SpfAddress.Parse("::/0", AddressFamily.InterNetworkV6);

            Assert.That(a.Equals(b), Is.False);
        }

        [Test]
        public void TestNotEqualsNull()
        {
            var a = SpfAddress.Parse("192.0.2.1", AddressFamily.InterNetwork);

            Assert.That(a.Equals(null), Is.False);
            Assert.That(a == null, Is.False);
            Assert.That(a != null, Is.True);
        }

        [Test]
        public void TestHashSetDeduplicatesEquivalentAddresses()
        {
            // ParseDirective relies on this to detect duplicate ip4/ip6 mechanisms
            var set = new HashSet<SpfAddress>
            {
                SpfAddress.Parse("192.0.2.1", AddressFamily.InterNetwork),
                SpfAddress.Parse("192.0.2.1/32", AddressFamily.InterNetwork),
                SpfAddress.Parse("192.0.2.0/24", AddressFamily.InterNetwork),
                SpfAddress.Parse("192.0.2.0/24", AddressFamily.InterNetwork),
                SpfAddress.Parse("192.0.2.0/25", AddressFamily.InterNetwork),
                SpfAddress.Parse("2001:db8::1", AddressFamily.InterNetworkV6),
                SpfAddress.Parse("2001:db8::1/128", AddressFamily.InterNetworkV6),
            };

            Assert.That(set.Count, Is.EqualTo(4));
        }

        [Test]
        public void TestContainsSingleAddress()
        {
            var address = SpfAddress.Parse("192.0.2.1", AddressFamily.InterNetwork);

            Assert.That(address.Contains(IPAddress.Parse("192.0.2.1")), Is.True);
            Assert.That(address.Contains(IPAddress.Parse("192.0.2.2")), Is.False);
            Assert.That(address.Contains(IPAddress.Parse("::ffff:192.0.2.1")), Is.False);
        }

        [Test]
        public void TestContainsNetwork()
        {
            var address = SpfAddress.Parse("192.0.2.0/24", AddressFamily.InterNetwork);

            Assert.That(address.Contains(IPAddress.Parse("192.0.2.0")), Is.True);
            Assert.That(address.Contains(IPAddress.Parse("192.0.2.255")), Is.True);
            Assert.That(address.Contains(IPAddress.Parse("192.0.3.0")), Is.False);
            Assert.That(address.Contains(IPAddress.Parse("192.0.1.255")), Is.False);
            Assert.That(address.Contains(IPAddress.Parse("2001:db8::1")), Is.False);
        }

        [Test]
        public void TestContainsIPv6Network()
        {
            var address = SpfAddress.Parse("2001:db8::/32", AddressFamily.InterNetworkV6);

            Assert.That(address.Contains(IPAddress.Parse("2001:db8::1")), Is.True);
            Assert.That(address.Contains(IPAddress.Parse("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")), Is.True);
            Assert.That(address.Contains(IPAddress.Parse("2001:db9::1")), Is.False);
            Assert.That(address.Contains(IPAddress.Parse("192.0.2.1")), Is.False);
        }

        [Test]
        public void TestContainsZeroPrefixMatchesEverything()
        {
            var address = SpfAddress.Parse("0.0.0.0/0", AddressFamily.InterNetwork);

            Assert.That(address.Contains(IPAddress.Parse("1.2.3.4")), Is.True);
            Assert.That(address.Contains(IPAddress.Parse("255.255.255.255")), Is.True);
        }

        [TestCase("192.0.2.1", AddressFamily.InterNetwork, "192.0.2.1")]
        [TestCase("192.0.2.0/24", AddressFamily.InterNetwork, "192.0.2.0/24")]
        [TestCase("192.0.2.1/32", AddressFamily.InterNetwork, "192.0.2.1/32")]       // The explicit prefix is kept
        [TestCase("2001:db8::1", AddressFamily.InterNetworkV6, "2001:db8::1")]
        [TestCase("2001:db8::/32", AddressFamily.InterNetworkV6, "2001:db8::/32")]
        [TestCase("2001:0db8:0000:0000:0000:0000:0000:0001", AddressFamily.InterNetworkV6, "2001:db8::1")] // Normalized by IPAddress
        public void TestToString(string value, AddressFamily family, string expected)
        {
            Assert.That(SpfAddress.Parse(value, family).ToString(), Is.EqualTo(expected));
        }
    }
}
