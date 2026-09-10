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
        public void TestKeepEmptyEntries()
        {
            // The options overload can keep empty entries
            var result = "hello, ,world".SplitTrim(',', System.StringSplitOptions.None);

            Assert.That(result.Length, Is.EqualTo(3));
            Assert.That(result[1], Is.EqualTo(""));

            var result2 = "hello,,world".SplitTrim(',', System.StringSplitOptions.None);

            Assert.That(result2.Length, Is.EqualTo(3));
            Assert.That(result2[1], Is.EqualTo(""));
        }

        [Test]
        public void TestSanitizeKeepsVisibleAscii()
        {
            var value = "include:_spf.example.com/24 <b>&amp;'\"";

            Assert.That(value.Sanitize(), Is.EqualTo(value));
        }

        [Test]
        public void TestSanitizeReplacesControlAndNonAscii()
        {
            Assert.That("a\r\nb\tc\0d".Sanitize(), Is.EqualTo("a??b?c?d"));
            Assert.That("\u001b[31mred".Sanitize(), Is.EqualTo("?[31mred"));
            Assert.That("exampl\u0435.com".Sanitize(), Is.EqualTo("exampl?.com")); // Cyrillic е
            Assert.That("\u007f".Sanitize(), Is.EqualTo("?"));
        }

        [Test]
        public void TestSanitizeTruncates()
        {
            var value = new string('a', StringExtensions.MaxMessageValueLength + 1);

            Assert.That(value.Sanitize(), Is.EqualTo(new string('a', StringExtensions.MaxMessageValueLength) + "..."));
            Assert.That(new string('a', StringExtensions.MaxMessageValueLength).Sanitize(), Is.EqualTo(new string('a', StringExtensions.MaxMessageValueLength)));
        }

        [Test]
        public void TestSanitizeNullAndEmpty()
        {
            Assert.That(((string)null).Sanitize(), Is.EqualTo(""));
            Assert.That("".Sanitize(), Is.EqualTo(""));
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
