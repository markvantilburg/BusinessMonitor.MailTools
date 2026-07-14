using NUnit.Framework;
using Moq;
using System;
using System.Net;
using BusinessMonitor.MailTools.Mx;
using BusinessMonitor.MailTools.Dns;

namespace BusinessMonitor.MailTools.Test
{
    [TestFixture]
    public class MxValidatorTests
    {
        private static MxValidator.MxValidationResult Validate(params string[] addresses)
        {
            var mockResolver = new Mock<IResolver>();
            mockResolver.Setup(r => r.GetMailRecords("example.com"))
                .Returns(new[] { "mail.example.com" });
            mockResolver.Setup(r => r.GetAddressRecords("mail.example.com"))
                .Returns(Array.ConvertAll(addresses, IPAddress.Parse));

            var validator = new MxValidator(mockResolver.Object);

            return validator.ValidateMxRecords("example.com");
        }

        [Test]
        public void ValidateMxRecords_WithValidMxRecords_ReturnsValidResult()
        {
            // Arrange
            var mockResolver = new Mock<IResolver>();
            mockResolver.Setup(r => r.GetMailRecords("businessmonitor.nl"))
                .Returns(new[] { "mail1.businessmonitor.nl", "mail2.businessmonitor.nl" });
            mockResolver.Setup(r => r.GetAddressRecords("mail1.businessmonitor.nl"))
                .Returns(new[] { IPAddress.Parse("222.222.1.1") });
            mockResolver.Setup(r => r.GetAddressRecords("mail2.businessmonitor.nl"))
                .Returns(new[] { IPAddress.Parse("222.222.1.2") });

            var validator = new MxValidator(mockResolver.Object);

            // Act
            var result = validator.ValidateMxRecords("businessmonitor.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Is.Empty);
        }

        [Test]
        public void ValidateMxRecords_WithInvalidMxRecords_ReturnsInvalidResult()
        {
            // Arrange
            var mockResolver = new Mock<IResolver>();
            mockResolver.Setup(r => r.GetMailRecords("geen.nl"))
                .Returns(new[] { "bogus.dmrmail.nl" });
            mockResolver.Setup(r => r.GetAddressRecords("bogus.dmrmail.nl"))
                .Returns(new[] { IPAddress.Parse("127.0.0.1") });

            var validator = new MxValidator(mockResolver.Object);

            // Act
            var result = validator.ValidateMxRecords("geen.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords.Count, Is.EqualTo(1));
            Assert.That(result.InvalidMxRecords, Does.Contain("bogus.dmrmail.nl"));
        }

        [Test]
        public void ValidateMxRecords_WithNoMxRecords_ReturnsNoRecords()
        {
            // Arrange
            var mockResolver = new Mock<IResolver>();
            mockResolver.Setup(r => r.GetMailRecords("nonexistentdomain.nl"))
                .Returns(new string[0]);

            var validator = new MxValidator(mockResolver.Object);

            // Act
            var result = validator.ValidateMxRecords("nonexistentdomain.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.False);
            Assert.That(result.InvalidMxRecords, Is.Empty);
        }

        [Test]
        public void Constructor_WithNullResolver_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new MxValidator(null);
            });
        }

        [Test]
        public void ValidateMxRecords_WithNullMailRecords_ReturnsNoRecords()
        {
            // Arrange
            var mockResolver = new Mock<IResolver>();
            mockResolver.Setup(r => r.GetMailRecords("nullmail.nl"))
                .Returns((string[])null);

            var validator = new MxValidator(mockResolver.Object);

            // Act
            var result = validator.ValidateMxRecords("nullmail.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.False);
            Assert.That(result.InvalidMxRecords, Is.Empty);
        }

        [Test]
        public void ValidateMxRecords_WithNullAddressRecords_TreatsRecordAsValid()
        {
            // Arrange
            var mockResolver = new Mock<IResolver>();
            mockResolver.Setup(r => r.GetMailRecords("nulladdress.nl"))
                .Returns(new[] { "mail.nulladdress.nl" });
            mockResolver.Setup(r => r.GetAddressRecords("mail.nulladdress.nl"))
                .Returns((IPAddress[])null);

            var validator = new MxValidator(mockResolver.Object);

            // Act
            var result = validator.ValidateMxRecords("nulladdress.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Is.Empty);
        }

        // IPv4 non-routable ranges
        [TestCase("0.1.2.3")]         // 0.0.0.0/8
        [TestCase("10.0.0.1")]        // 10.0.0.0/8
        [TestCase("10.255.255.255")]  // 10.0.0.0/8 upper bound
        [TestCase("127.0.0.1")]       // loopback 127.0.0.0/8
        [TestCase("127.255.255.255")] // loopback upper bound
        [TestCase("169.254.1.1")]     // link-local 169.254.0.0/16
        [TestCase("172.16.0.1")]      // 172.16.0.0/12 lower bound
        [TestCase("172.31.255.255")]  // 172.16.0.0/12 upper bound
        [TestCase("192.168.0.1")]     // 192.168.0.0/16
        [TestCase("192.168.255.255")] // 192.168.0.0/16 upper bound
        [TestCase("100.64.0.1")]      // CGNAT 100.64.0.0/10 lower bound
        [TestCase("100.127.255.255")] // CGNAT upper bound
        [TestCase("224.0.0.1")]       // multicast lower bound
        [TestCase("239.255.255.255")] // multicast upper bound
        [TestCase("240.0.0.1")]       // reserved
        [TestCase("255.255.255.255")] // broadcast
        // IPv6 non-routable ranges
        [TestCase("::")]              // unspecified
        [TestCase("::1")]             // loopback
        [TestCase("fe80::1")]         // link-local fe80::/10
        [TestCase("fec0::1")]         // site-local fec0::/10 (deprecated)
        [TestCase("ff02::1")]         // multicast ff00::/8
        [TestCase("fc00::1")]         // unique local fc00::/7 lower half
        [TestCase("fd12:3456:789a::1")] // unique local fc00::/7 upper half
        public void ValidateMxRecords_WithNonRoutableAddress_MarksRecordInvalid(string address)
        {
            var result = Validate(address);

            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Does.Contain("mail.example.com"));
        }

        // IPv4 routable addresses, including boundaries just outside the non-routable ranges
        [TestCase("1.1.1.1")]
        [TestCase("9.255.255.255")]   // just below 10.0.0.0/8
        [TestCase("11.0.0.1")]        // just above 10.0.0.0/8
        [TestCase("126.255.255.255")] // just below loopback
        [TestCase("128.0.0.1")]       // just above loopback
        [TestCase("169.253.255.255")] // just below link-local
        [TestCase("169.255.0.1")]     // just above link-local
        [TestCase("172.15.255.255")]  // just below 172.16.0.0/12
        [TestCase("172.32.0.1")]      // just above 172.16.0.0/12
        [TestCase("192.167.255.255")] // just below 192.168.0.0/16
        [TestCase("192.169.0.1")]     // just above 192.168.0.0/16
        [TestCase("100.63.255.255")]  // just below CGNAT
        [TestCase("100.128.0.1")]     // just above CGNAT
        [TestCase("223.255.255.255")] // just below multicast
        // IPv6 routable addresses
        [TestCase("2001:db8::1")]
        [TestCase("2606:4700:4700::1111")]
        [TestCase("fbff::1")]         // just below fc00::/7
        [TestCase("fe00::1")]         // just above fc00::/7, below fe80::/10
        public void ValidateMxRecords_WithRoutableAddress_MarksRecordValid(string address)
        {
            var result = Validate(address);

            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Is.Empty);
        }

        [Test]
        public void ValidateMxRecords_WithMixedAddresses_MarksRecordInvalid()
        {
            // A single non-routable address among routable ones invalidates the MX record
            var result = Validate("1.1.1.1", "10.0.0.1");

            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Does.Contain("mail.example.com"));
        }
    }
}
