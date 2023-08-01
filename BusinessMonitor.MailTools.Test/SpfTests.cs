using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Spf;
using BusinessMonitor.MailTools.Test.Dns;
using NUnit.Framework;

namespace BusinessMonitor.MailTools.Test
{
    internal class SpfTests
    {
        [Test]
        public void TestParse()
        {
            var record = SpfCheck.ParseSpfRecord("v=spf1 ip4:192.0.2.1 ip4:192.0.2.129 -all");

            Assert.IsNotNull(record);
            Assert.AreEqual(3, record.Directives.Count);

            SpfDirective directive;

            // ip4:192.0.2.1
            directive = record.Directives[0];

            Assert.AreEqual(SpfQualifier.Pass, directive.Qualifier);
            Assert.AreEqual(SpfMechanism.IP4, directive.Mechanism);
            Assert.IsNotNull(directive.IP4);
            Assert.AreEqual("192.0.2.1", directive.IP4.ToString());

            // ip4:192.0.2.129
            directive = record.Directives[1];

            Assert.AreEqual(SpfQualifier.Pass, directive.Qualifier);
            Assert.AreEqual(SpfMechanism.IP4, directive.Mechanism);
            Assert.IsNotNull(directive.IP4);
            Assert.AreEqual("192.0.2.129", directive.IP4.ToString());

            // -all
            directive = record.Directives[2];

            Assert.AreEqual(SpfQualifier.Fail, directive.Qualifier);
            Assert.AreEqual(SpfMechanism.All, directive.Mechanism);
        }

        [Test]
        [TestCase("")]
        [TestCase("v=spf1 -boop")]
        [TestCase("v=spf1 boop:boop")]
        public void TestInvalid(string value)
        {
            Assert.Throws<InvalidSpfException>(() =>
            {
                SpfCheck.ParseSpfRecord(value);
            });
        }

        [Test]
        public void TestLookup()
        {
            var resolver = new DummyResolver();

            resolver.AddDomain("businessmonitor.nl", "v=spf1 include:survey.businessmonitor.nl -all");
            resolver.AddDomain("survey.businessmonitor.nl", "v=spf1 ip4:192.0.2.1 -all");

            var check = new SpfCheck(resolver);
            var record = check.GetSpfRecord("businessmonitor.nl");

            Assert.IsNotNull(record);
            Assert.IsNotNull(record.Directives[0].Included);

            var included = record.Directives[0].Included;

            Assert.AreEqual(2, included.Directives.Count);
            Assert.AreEqual(SpfMechanism.IP4, included.Directives[0].Mechanism);
            Assert.AreEqual("192.0.2.1", included.Directives[0].IP4.ToString());
        }

        [Test]
        public void TestMaxLookups()
        {
            var resolver = new DummyResolver("businessmonitor.nl", "v=spf1 include:businessmonitor.nl");
            var check = new SpfCheck(resolver);

            Assert.Throws<InvalidSpfException>(() =>
            {
                check.GetSpfRecord("businessmonitor.nl");
            });
        }
    }
}
