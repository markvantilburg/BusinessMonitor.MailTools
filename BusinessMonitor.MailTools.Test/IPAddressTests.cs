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

    }
}