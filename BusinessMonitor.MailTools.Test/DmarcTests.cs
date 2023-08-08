using BusinessMonitor.MailTools.Dmarc;
using NUnit.Framework;

namespace BusinessMonitor.MailTools.Test
{
    internal class DmarcTests
    {
        [Test]
        public void TestParse()
        {
            var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; adkim=s; aspf=s");

            Assert.IsNotNull(record);
            Assert.AreEqual(record.DkimMode, AlignmentMode.Strict);
            Assert.AreEqual(record.SpfMode, AlignmentMode.Strict);
        }
    }
}
