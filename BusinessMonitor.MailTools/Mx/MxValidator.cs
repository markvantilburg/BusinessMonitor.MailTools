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
        /// <exception cref="ArgumentException">The domain is not a valid DNS name</exception>
        public MxValidationResult ValidateMxRecords(string domain)
        {
            domain = DnsName.ValidateDomain(domain, nameof(domain));

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
                // A null MX (RFC 7505) has no host to resolve
                if (DnsName.IsNullMx(mxRecord))
                {
                    continue;
                }

                // The MX host comes from DNS, a host that is not a valid name can never
                // deliver mail and is not passed back to the resolver
                if (!DnsName.TryNormalizeHost(mxRecord, out var host))
                {
                    result.InvalidMxRecords.Add(mxRecord);
                    continue;
                }

                IPAddress[] ipAddresses = _resolver.GetAddressRecords(host);
                if (ipAddresses != null && ipAddresses.Any(IPAddressHelper.IsNonRoutable))
                {
                    result.InvalidMxRecords.Add(mxRecord);
                }
            }

            return result;
        }
    }
}