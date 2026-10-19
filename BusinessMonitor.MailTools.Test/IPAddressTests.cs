using BusinessMonitor.MailTools.Util;
using NUnit.Framework;
using System.Net;

namespace BusinessMonitor.MailTools.Test
{
    internal class IPAddressTests
    {
        [Test]
        public void TestRange()
        {
            var network = IPAddress.Parse("192.168.0.1"); // 192.168.0.1/24

            var address1 = IPAddress.Parse("192.168.0.100");
            var address2 = IPAddress.Parse("192.168.1.100");
            var address3 = IPAddress.Parse("10.10.0.10");

            Assert.That(IPAddressHelper.IsInRange(address1, network, 24), Is.True);
            Assert.That(IPAddressHelper.IsInRange(address2, network, 24), Is.False);
            Assert.That(IPAddressHelper.IsInRange(address3, network, 24), Is.False);
        }

        [Test]
        public void TestRange2()
        {
            var network = IPAddress.Parse("192.0.2.128"); // 192.0.2.128/28;

            var address1 = IPAddress.Parse("192.0.2.129");
            var address2 = IPAddress.Parse("192.0.2.65");

            Assert.That(IPAddressHelper.IsInRange(address1, network, 28), Is.True);
            Assert.That(IPAddressHelper.IsInRange(address2, network, 28), Is.False);
        }

        [Test]
        public void TestMixedAddressFamilies()
        {
            var network4 = IPAddress.Parse("1.2.3.0");
            var network6 = IPAddress.Parse("2001:db8::");

            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("2001:db8::1"), network4, 24), Is.False);
            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("::1"), network4, 24), Is.False);
            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("1.2.3.4"), network6, 32), Is.False);
            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("2001:db8::1"), network6, 32), Is.True);
        }


        [Test]
        public void TestUnalignedNetworkBase()
        {
            // Network address with host bits set: 192.168.0.1/24 must behave as 192.168.0.0/24
            var network = IPAddress.Parse("192.168.0.1");

            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("192.168.0.0"), network, 24), Is.True);
            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("192.168.0.255"), network, 24), Is.True);
            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("192.168.1.0"), network, 24), Is.False);

            var network6 = IPAddress.Parse("2001:db8::1");

            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("2001:db8::"), network6, 32), Is.True);
            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"), network6, 32), Is.True);
            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("2001:db9::"), network6, 32), Is.False);
        }


        // Non-octet-aligned prefixes, unaligned bases
        [TestCase("10.0.129.5", 17, "10.0.128.0", true)]     // base masks to 10.0.128.0
        [TestCase("10.0.129.5", 17, "10.0.255.255", true)]   // top of /17
        [TestCase("10.0.129.5", 17, "10.0.127.255", false)]  // just below range
        [TestCase("10.0.129.5", 17, "10.1.0.0", false)]      // just above range
        [TestCase("192.168.37.200", 19, "192.168.32.0", true)]
        [TestCase("192.168.37.200", 19, "192.168.63.255", true)]
        [TestCase("192.168.37.200", 19, "192.168.64.0", false)]
        [TestCase("192.168.37.200", 19, "192.168.31.255", false)]
        [TestCase("172.16.5.77", 30, "172.16.5.76", true)]
        [TestCase("172.16.5.77", 30, "172.16.5.79", true)]
        [TestCase("172.16.5.77", 30, "172.16.5.80", false)]
        [TestCase("1.2.3.4", 0, "255.255.255.255", true)]    // /0 matches everything
        [TestCase("1.2.3.4", 32, "1.2.3.4", true)]           // /32 exact host
        [TestCase("1.2.3.4", 32, "1.2.3.5", false)]
        [TestCase("2001:db8:abcd:8000::1", 49, "2001:db8:abcd:8000::", true)]
        [TestCase("2001:db8:abcd:8000::1", 49, "2001:db8:abcd:ffff:ffff:ffff:ffff:ffff", true)]
        [TestCase("2001:db8:abcd:8000::1", 49, "2001:db8:abcd:7fff::", false)]
        [TestCase("10.0.0.7", 31, "10.0.0.6", true)]          // /31 = exactly 2 addresses
        [TestCase("10.0.0.7", 31, "10.0.0.7", true)]
        [TestCase("10.0.0.7", 31, "10.0.0.5", false)]
        [TestCase("10.0.0.7", 31, "10.0.0.8", false)]
        [TestCase("2001:db8::3", 127, "2001:db8::2", true)]   // /127 = exactly 2 addresses
        [TestCase("2001:db8::3", 127, "2001:db8::3", true)]
        [TestCase("2001:db8::3", 127, "2001:db8::1", false)]
        [TestCase("2001:db8::3", 127, "2001:db8::4", false)]
        [TestCase("2001:db8::5", 128, "2001:db8::5", true)]   // /128 exact host
        [TestCase("2001:db8::5", 128, "2001:db8::4", false)]
        [TestCase("2001:db8::5", 128, "2001:db8::6", false)]
        // Long non-aligned IPv6 prefixes, the difference sits deep in the last bytes
        [TestCase("6734:5a65:c36:d1d8:2251:543e:3c3c:6007", 114, "6734:5a65:c36:d1d8:2251:543e:3c3c:6027", true)]  // differs only in host bits
        [TestCase("2001:db8::c000", 114, "2001:db8::8000", false)]  // differs in the last prefix bit
        [TestCase("2001:db8::c000", 114, "2001:db8::ffff", true)]   // /114 spans the low 14 bits
        [TestCase("2001:db8::c000", 114, "2001:db8::bfff", false)]  // just below the range
        public void TestArbitraryPrefixLengths(string network, int length, string address, bool expected)
        {
            var result = IPAddressHelper.IsInRange(IPAddress.Parse(address), IPAddress.Parse(network), length);

            Assert.That(result, Is.EqualTo(expected));
        }

        [Test]
        public void TestZeroPrefixIPv6()
        {
            // /0 matches every address
            var network = IPAddress.Parse("2001:db8::");

            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("::1"), network, 0), Is.True);
            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), network, 0), Is.True);
        }

        [Test]
        public void TestOutOfRangeLength()
        {
            // An invalid prefix length is never a match, it must not throw
            var network4 = IPAddress.Parse("192.168.0.0");
            var network6 = IPAddress.Parse("2001:db8::");

            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("192.168.0.1"), network4, 33), Is.False);
            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("192.168.0.1"), network4, 128), Is.False);
            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("192.168.0.1"), network4, -1), Is.False);
            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("2001:db8::1"), network6, 129), Is.False);
        }

        [Test]
        public void TestMappedIPv6IsNotIPv4()
        {
            // An IPv4 mapped IPv6 address is a different address family and never
            // matches an IPv4 network
            var network = IPAddress.Parse("192.168.0.0");

            Assert.That(IPAddressHelper.IsInRange(IPAddress.Parse("::ffff:192.168.0.1"), network, 24), Is.False);
        }

        // IPv4 non-routable ranges
        [TestCase("0.1.2.3", true)]               // 0.0.0.0/8
        [TestCase("10.0.0.1", true)]              // 10.0.0.0/8
        [TestCase("10.255.255.255", true)]        // 10.0.0.0/8 upper bound
        [TestCase("127.0.0.1", true)]             // loopback
        [TestCase("127.255.255.255", true)]       // loopback upper bound
        [TestCase("172.16.0.1", true)]            // 172.16.0.0/12 lower bound
        [TestCase("172.31.255.255", true)]        // 172.16.0.0/12 upper bound
        [TestCase("192.168.1.1", true)]           // 192.168.0.0/16
        [TestCase("169.254.169.254", true)]       // link-local
        [TestCase("100.64.0.1", true)]            // CGNAT lower bound
        [TestCase("100.127.255.255", true)]       // CGNAT upper bound
        [TestCase("192.0.0.1", true)]             // IETF protocol assignments
        [TestCase("192.0.2.1", true)]             // TEST-NET-1
        [TestCase("198.51.100.1", true)]          // TEST-NET-2
        [TestCase("203.0.113.1", true)]           // TEST-NET-3
        [TestCase("198.18.0.1", true)]            // benchmarking lower bound
        [TestCase("198.19.255.255", true)]        // benchmarking upper bound
        [TestCase("224.0.0.1", true)]             // multicast
        [TestCase("239.255.255.255", true)]       // multicast upper bound
        [TestCase("240.0.0.1", true)]             // reserved
        [TestCase("255.255.255.255", true)]       // broadcast
        // IPv4 routable neighbours of those ranges
        [TestCase("1.1.1.1", false)]
        [TestCase("8.8.8.8", false)]
        [TestCase("9.255.255.255", false)]        // just below 10/8
        [TestCase("11.0.0.0", false)]             // just above 10/8
        [TestCase("126.255.255.255", false)]      // just below loopback
        [TestCase("128.0.0.1", false)]            // just above loopback
        [TestCase("172.15.255.255", false)]       // just below 172.16/12
        [TestCase("172.32.0.0", false)]           // just above 172.16/12
        [TestCase("192.167.255.255", false)]      // just below 192.168/16
        [TestCase("192.169.0.0", false)]          // just above 192.168/16
        [TestCase("169.253.255.255", false)]      // just below link-local
        [TestCase("169.255.0.0", false)]          // just above link-local
        [TestCase("100.63.255.255", false)]       // just below CGNAT
        [TestCase("100.128.0.0", false)]          // just above CGNAT
        [TestCase("192.0.1.1", false)]            // between 192.0.0/24 and TEST-NET-1
        [TestCase("192.0.3.1", false)]            // just above TEST-NET-1
        [TestCase("198.51.99.1", false)]          // just below TEST-NET-2
        [TestCase("198.51.101.1", false)]         // just above TEST-NET-2
        [TestCase("203.0.112.1", false)]          // just below TEST-NET-3
        [TestCase("203.0.114.1", false)]          // just above TEST-NET-3
        [TestCase("198.17.255.255", false)]       // just below benchmarking
        [TestCase("198.20.0.0", false)]           // just above benchmarking
        [TestCase("223.255.255.255", false)]      // just below multicast
        // IPv6 non-routable ranges
        [TestCase("::", true)]                    // unspecified
        [TestCase("::1", true)]                   // loopback
        [TestCase("fe80::1", true)]               // link-local fe80::/10
        [TestCase("febf::1", true)]               // link-local upper bound
        [TestCase("fec0::1", true)]               // site-local fec0::/10 (deprecated)
        [TestCase("ff02::1", true)]               // multicast ff00::/8
        [TestCase("fc00::1", true)]               // unique local fc00::/7
        [TestCase("fd12:3456::1", true)]          // unique local fc00::/7
        [TestCase("2001:db8::1", true)]           // documentation 2001:db8::/32
        [TestCase("::a00:1", true)]               // IPv4-compatible ::/96 (deprecated)
        [TestCase("::ffff:0:0", true)]            // IPv4-mapped prefix with 0.0.0.0
        // IPv6 routable
        [TestCase("2606:4700:4700::1111", false)]
        [TestCase("2a00:1450:4001:80b::200e", false)]
        [TestCase("2001:db7:ffff:ffff::1", false)]   // just below documentation range
        [TestCase("2001:db9::1", false)]             // just above documentation range
        [TestCase("fbff::1", false)]                 // just below unique local
        [TestCase("fe00::1", false)]                 // between unique local and link-local
        [TestCase("fe7f::1", false)]                 // just below link-local
        // IPv4-mapped IPv6 is checked on the embedded IPv4 address
        [TestCase("::ffff:127.0.0.1", true)]
        [TestCase("::ffff:10.0.0.1", true)]
        [TestCase("::ffff:192.168.0.1", true)]
        [TestCase("::ffff:8.8.8.8", false)]
        // 6to4 2002:a.b.c.d::/48 embeds the IPv4 address after the prefix
        [TestCase("2002:a00:1::1", true)]            // 10.0.0.1
        [TestCase("2002:7f00:1::1", true)]           // 127.0.0.1
        [TestCase("2002:c0a8:1::1", true)]           // 192.168.0.1
        [TestCase("2002:808:808::1", false)]         // 8.8.8.8
        // Teredo 2001::/32 embeds the inverted IPv4 address in the last 32 bits
        [TestCase("2001::f5ff:fffe", true)]          // ~10.0.0.1
        [TestCase("2001::80ff:fffe", true)]          // ~127.0.0.1
        [TestCase("2001::f7f7:f7f7", false)]         // ~8.8.8.8
        // NAT64 64:ff9b::/96 embeds the IPv4 address in the last 32 bits
        [TestCase("64:ff9b::a00:1", true)]           // 10.0.0.1
        [TestCase("64:ff9b::c0a8:1", true)]          // 192.168.0.1
        [TestCase("64:ff9b::808:808", false)]        // 8.8.8.8
        [TestCase("64:ff9b:1::a00:1", false)]        // not the /96 well-known prefix, no embedded address
        public void TestIsNonRoutable(string address, bool expected)
        {
            Assert.That(IPAddressHelper.IsNonRoutable(IPAddress.Parse(address)), Is.EqualTo(expected));
        }

        [Test]
        public void TestIsNonRoutableWellKnownAddresses()
        {
            Assert.That(IPAddressHelper.IsNonRoutable(IPAddress.Any), Is.True);
            Assert.That(IPAddressHelper.IsNonRoutable(IPAddress.Loopback), Is.True);
            Assert.That(IPAddressHelper.IsNonRoutable(IPAddress.Broadcast), Is.True);
            Assert.That(IPAddressHelper.IsNonRoutable(IPAddress.IPv6Any), Is.True);
            Assert.That(IPAddressHelper.IsNonRoutable(IPAddress.IPv6Loopback), Is.True);
        }
    }
}
