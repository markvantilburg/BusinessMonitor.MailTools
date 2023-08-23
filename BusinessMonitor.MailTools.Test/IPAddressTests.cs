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

            Assert.IsTrue(IPAddressHelper.IsInRange(address1, network, 24));
            Assert.IsFalse(IPAddressHelper.IsInRange(address2, network, 24));
            Assert.IsFalse(IPAddressHelper.IsInRange(address3, network, 24));
        }

        [Test]
        public void TestRange2()
        {
            var network = IPAddress.Parse("192.0.2.128"); // 192.0.2.128/28;

            var address1 = IPAddress.Parse("192.0.2.129");
            var address2 = IPAddress.Parse("192.0.2.65");

            Assert.IsTrue(IPAddressHelper.IsInRange(address1, network, 28));
            Assert.IsFalse(IPAddressHelper.IsInRange(address2, network, 28));
        }
    }
}
