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
            /// <summary>
            /// Whether the domain has MX records
            /// </summary>
            public bool HasMxRecords { get; set; }

            /// <summary>
            /// Whether the domain has no MX records but does have address records, mail is then delivered
            /// to the domain itself as if it had an MX record with preference 0 pointing to that host
            /// (RFC 5321 section 5.1)
            /// </summary>
            public bool HasImplicitMx { get; set; }

            /// <summary>
            /// Whether the domain has a null MX record (RFC 7505), an MX pointing to the root name which
            /// states the domain accepts no mail. The preference cannot be verified as the resolver only
            /// returns the exchange. A null MX must be the only MX record of the domain, when other MX
            /// records are present the null MX is reported in <see cref="InvalidMxRecords"/>.
            /// </summary>
            public bool HasNullMx { get; set; }

            /// <summary>
            /// Whether, as far as DNS is concerned, the domain can receive mail: at least one MX host or
            /// the implicit MX host is a valid name that resolves to address records of which none is
            /// non-routable. False when there are no MX and no address records, for a null MX (RFC 7505),
            /// or when every mail host is invalid, non-routable or has no address records. No SMTP
            /// connection is made, a server that exists may still refuse mail.
            /// </summary>
            public bool CanReceiveMail { get; set; }

            /// <summary>
            /// The MX hosts that are not valid or resolve to a non-routable address, for an implicit MX
            /// this is the domain itself, a null MX next to other MX records is reported once
            /// </summary>
            public List<string> InvalidMxRecords { get; set; }

            public MxValidationResult()
            {
                InvalidMxRecords = new List<string>();
            }
        }

        /// <summary>
        /// Validates the MX records of a domain. A domain without MX records falls back to the implicit
        /// MX (RFC 5321 section 5.1), the address records of the domain itself are then validated and
        /// <see cref="MxValidationResult.HasImplicitMx"/> is set. A null MX (RFC 7505) is an MX record
        /// and does not fall back.
        /// </summary>
        /// <exception cref="MxException">The domain has more than 10 MX records</exception>
        /// <exception cref="ArgumentException">The domain is not a valid DNS name</exception>
        public MxValidationResult ValidateMxRecords(string domain)
        {
            domain = DnsName.ValidateDomain(domain, nameof(domain));

            var result = new MxValidationResult();
            var mxRecords = _resolver.GetMailRecords(domain).WithoutNulls();
            if (mxRecords.Length == 0)
            {
                // An empty list of MXs is treated as an implicit MX with preference 0 pointing to the
                // domain itself (RFC 5321 section 5.1), without address records no mail can be delivered
                result.HasMxRecords = false;

                var addresses = _resolver.GetAddressRecords(domain).WithoutNulls();
                if (addresses.Length > 0)
                {
                    result.HasImplicitMx = true;

                    if (addresses.Any(IPAddressHelper.IsNonRoutable))
                    {
                        result.InvalidMxRecords.Add(domain);
                    }
                    else
                    {
                        result.CanReceiveMail = true;
                    }
                }

                return result;
            }

            if (mxRecords.Length > MaxMxRecords)
            {
                throw new MxException($"Domain exceeds max MX records of {MaxMxRecords}");
            }

            result.HasMxRecords = true;
            foreach (var mxRecord in mxRecords)
            {
                // A null MX (RFC 7505) has no host to resolve, it must be the only MX record of the domain
                if (DnsName.IsNullMx(mxRecord))
                {
                    if (!result.HasNullMx && mxRecords.Length > 1)
                    {
                        result.InvalidMxRecords.Add(mxRecord);
                    }

                    result.HasNullMx = true;
                    continue;
                }

                // The MX host comes from DNS, a host that is not a valid name can never
                // deliver mail and is not passed back to the resolver
                if (!DnsName.TryNormalizeHost(mxRecord, out var host))
                {
                    result.InvalidMxRecords.Add(mxRecord);
                    continue;
                }

                IPAddress[] ipAddresses = _resolver.GetAddressRecords(host).WithoutNulls();
                if (ipAddresses.Any(IPAddressHelper.IsNonRoutable))
                {
                    result.InvalidMxRecords.Add(mxRecord);
                }
                else if (ipAddresses.Length > 0)
                {
                    // A host without address records is not reported as invalid, the name may
                    // exist but mail cannot be delivered to it
                    result.CanReceiveMail = true;
                }
            }

            return result;
        }
    }
}