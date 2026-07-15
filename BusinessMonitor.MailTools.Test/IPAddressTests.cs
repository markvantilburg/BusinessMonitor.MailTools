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
        public void TestArbitraryPrefixLengths(string network, int length, string address, bool expected)
        {
            var result = IPAddressHelper.IsInRange(IPAddress.Parse(address), IPAddress.Parse(network), length);

            Assert.That(result, Is.EqualTo(expected));
        }

    }
}