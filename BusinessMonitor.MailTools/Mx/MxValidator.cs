using System.Collections.Generic;
using System.Linq;
using System.Net;
using BusinessMonitor.MailTools.Dns;

namespace BusinessMonitor.MailTools.Mx
{
    public class MxValidator
    {
        private readonly IResolver _resolver;

        public MxValidator(IResolver resolver)
        {
            _resolver = resolver;
        }

        public class MxValidationResult
        {
            public bool HasMxRecords { get; set; }
            public List<string> InvalidMxRecords { get; set; }

            public MxValidationResult()
            {
                InvalidMxRecords = new List<string>();
            }
        }

        public MxValidationResult ValidateMxRecords(string domain)
        {
            var result = new MxValidationResult();
            var mxRecords = _resolver.GetMailRecords(domain);
            if (mxRecords == null || mxRecords.Length == 0)
            {
                result.HasMxRecords = false;
                return result;
            }

            result.HasMxRecords = true;
            foreach (var mxRecord in mxRecords)
            {
                var ipAddresses = _resolver.GetAddressRecords(mxRecord);
                if (ipAddresses.Any(ip => ip.ToString() == "127.0.0.1"))
                {
                    result.InvalidMxRecords.Add(mxRecord);
                }
            }

            return result;
        }
    }
}