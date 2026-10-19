using BusinessMonitor.MailTools.Util;
using NUnit.Framework;
using System.Net;

namespace BusinessMonitor.MailTools.Test
{
    internal class ResolverExtensionsTests
    {
        [Test]
        public void TestNullArrayBecomesEmpty()
        {
            string[] results = null;

            var result = results.WithoutNulls();

            Assert.That(result, Is.Not.Null);
            Assert.That(result, Is.Empty);
        }

        [Test]
        public void TestEmptyArrayStaysEmpty()
        {
            var results = new string[0];

            Assert.That(results.WithoutNulls(), Is.Empty);
        }

        [Test]
        public void TestArrayWithoutNullsIsReturnedAsIs()
        {
            // No copy is made when there is nothing to remove
            var results = new[] { "a", "b", "c" };

            var result = results.WithoutNulls();

            Assert.That(result, Is.SameAs(results));
        }

        [Test]
        public void TestNullEntriesAreRemoved()
        {
            var results = new[] { null, "a", null, "b", null };

            var result = results.WithoutNulls();

            Assert.That(result, Is.EqualTo(new[] { "a", "b" }));
            Assert.That(result, Is.Not.SameAs(results));
        }

        [Test]
        public void TestLeadingNullIsRemoved()
        {
            var results = new[] { null, "a" };

            Assert.That(results.WithoutNulls(), Is.EqualTo(new[] { "a" }));
        }

        [Test]
        public void TestTrailingNullIsRemoved()
        {
            var results = new[] { "a", null };

            Assert.That(results.WithoutNulls(), Is.EqualTo(new[] { "a" }));
        }

        [Test]
        public void TestOnlyNullsBecomesEmpty()
        {
            var results = new string[] { null, null };

            Assert.That(results.WithoutNulls(), Is.Empty);
        }

        [Test]
        public void TestPreservesOrder()
        {
            var results = new[] { "c", null, "a", "b" };

            Assert.That(results.WithoutNulls(), Is.EqualTo(new[] { "c", "a", "b" }));
        }

        [Test]
        public void TestWorksForReferenceTypesOtherThanString()
        {
            var one = IPAddress.Parse("192.0.2.1");
            var two = IPAddress.Parse("192.0.2.2");
            var results = new[] { one, null, two };

            var result = results.WithoutNulls();

            Assert.That(result, Is.EqualTo(new[] { one, two }));
        }
    }
}
