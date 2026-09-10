using System.Collections.Generic;
using System.Linq;
using System.Net;
using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Util;

namespace BusinessMonitor.MailTools.Mx
{
    public class MxValidator
    {
        /// <summary>
        /// The maximum number of MX records that will be resolved for a domain (normally maximum is 5)
        /// </summary>
        private const int MaxMxRecords = 10;

        private readonly IResolver _resolver;

        public MxValidator(IResolver resolver)
        {
            if (resolver == null)
            {
                throw new ArgumentNullException(nameof(resolver));
            }

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

        /// <exception cref="MxException">The domain has more than 10 MX records</exception>
        public MxValidationResult ValidateMxRecords(string domain)
        {
            var result = new MxValidationResult();
            var mxRecords = _resolver.GetMailRecords(domain);
            if (mxRecords == null || mxRecords.Length == 0)
            {
                result.HasMxRecords = false;
                return result;
            }

            if (mxRecords.Length > MaxMxRecords)
            {
                throw new MxException($"Domain exceeds max MX records of {MaxMxRecords}");
            }

            result.HasMxRecords = true;
            foreach (var mxRecord in mxRecords)
            {
                IPAddress[] ipAddresses = _resolver.GetAddressRecords(mxRecord);
                if (ipAddresses != null && ipAddresses.Any(IPAddressHelper.IsNonRoutable))
                {
                    result.InvalidMxRecords.Add(mxRecord);
                }
            }

            return result;
        }
    }
}