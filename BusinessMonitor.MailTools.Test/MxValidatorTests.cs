using NUnit.Framework;
using Moq;
using System.Collections.Generic;
using BusinessMonitor.MailTools.Mx;
using BusinessMonitor.MailTools.Dns;

namespace BusinessMonitor.MailTools.Test
{
    [TestFixture]
    public class MxValidatorTests
    {
        [Test]
        public void ValidateMxRecords_WithValidMxRecords_ReturnsValidResult()
        {
            // Arrange
            var mockResolver = new Mock<IResolver>();
            mockResolver.Setup(r => r.GetMailRecords("businessmonitor.nl"))
                .Returns(new[] { "mail1.businessmonitor.nl", "mail2.businessmonitor.nl" });
            mockResolver.Setup(r => r.GetAddressRecords("mail1.businessmonitor.nl"))
                .Returns(new[] { System.Net.IPAddress.Parse("192.168.1.1") });
            mockResolver.Setup(r => r.GetAddressRecords("mail2.businessmonitor.nl"))
                .Returns(new[] { System.Net.IPAddress.Parse("192.168.1.2") });

            var validator = new MxValidator(mockResolver.Object);

            // Act
            var result = validator.ValidateMxRecords("businessmonitor.nl");

            // Assert
            Assert.IsTrue(result.HasMxRecords);
            Assert.IsEmpty(result.InvalidMxRecords);
        }

        [Test]
        public void ValidateMxRecords_WithInvalidMxRecords_ReturnsInvalidResult()
        {
            // Arrange
            var mockResolver = new Mock<IResolver>();
            mockResolver.Setup(r => r.GetMailRecords("geen.nl"))
                .Returns(new[] { "bogus.dmrmail.nl" });
            mockResolver.Setup(r => r.GetAddressRecords("bogus.dmrmail.nl"))
                .Returns(new[] { System.Net.IPAddress.Parse("127.0.0.1") });

            var validator = new MxValidator(mockResolver.Object);

            // Act
            var result = validator.ValidateMxRecords("geen.nl");

            // Assert
            Assert.IsTrue(result.HasMxRecords);
            Assert.AreEqual(1, result.InvalidMxRecords.Count);
            Assert.Contains("bogus.dmrmail.nl", result.InvalidMxRecords);
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
            Assert.IsFalse(result.HasMxRecords);
            Assert.IsEmpty(result.InvalidMxRecords);
        }
    }
}