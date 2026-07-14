using BusinessMonitor.MailTools.Util;
using NUnit.Framework;

namespace BusinessMonitor.MailTools.Test
{
    internal class StringExtensionsTests
    {
        [Test]
        public void TestSplit()
        {
            var result = "hello,world,yes".SplitTrim(',');

            Assert.That(result.Length, Is.EqualTo(3));
            Assert.That(result[0], Is.EqualTo("hello"));
            Assert.That(result[1], Is.EqualTo("world"));
            Assert.That(result[2], Is.EqualTo("yes"));
        }

        [Test]
        public void TestTrimsEntries()
        {
            var result = " hello ,  world,yes  ".SplitTrim(',');

            Assert.That(result.Length, Is.EqualTo(3));
            Assert.That(result[0], Is.EqualTo("hello"));
            Assert.That(result[1], Is.EqualTo("world"));
            Assert.That(result[2], Is.EqualTo("yes"));
        }

        [Test]
        public void TestRemovesEmptyEntries()
        {
            var result = "hello,,world".SplitTrim(',');

            Assert.That(result.Length, Is.EqualTo(2));
            Assert.That(result[0], Is.EqualTo("hello"));
            Assert.That(result[1], Is.EqualTo("world"));
        }

        [Test]
        public void TestWhitespaceOnlyEntryBecomesEmpty()
        {
            // Whitespace-only entries are not removed by RemoveEmptyEntries but are trimmed to empty strings
            var result = "hello,   ,world".SplitTrim(',');

            Assert.That(result.Length, Is.EqualTo(3));
            Assert.That(result[1], Is.EqualTo(""));
        }

        [Test]
        public void TestNoSeparator()
        {
            var result = "hello".SplitTrim(',');

            Assert.That(result.Length, Is.EqualTo(1));
            Assert.That(result[0], Is.EqualTo("hello"));
        }

        [Test]
        public void TestEmptyString()
        {
            var result = "".SplitTrim(',');

            Assert.That(result, Is.Empty);
        }

        [Test]
        public void TestOnlySeparators()
        {
            var result = ",,,".SplitTrim(',');

            Assert.That(result, Is.Empty);
        }

        [Test]
        public void TestLeadingAndTrailingSeparators()
        {
            var result = ",hello,world,".SplitTrim(',');

            Assert.That(result.Length, Is.EqualTo(2));
            Assert.That(result[0], Is.EqualTo("hello"));
            Assert.That(result[1], Is.EqualTo("world"));
        }

        [Test]
        public void TestOtherSeparator()
        {
            var result = "sha1 : sha256".SplitTrim(':');

            Assert.That(result.Length, Is.EqualTo(2));
            Assert.That(result[0], Is.EqualTo("sha1"));
            Assert.That(result[1], Is.EqualTo("sha256"));
        }
    }
}
