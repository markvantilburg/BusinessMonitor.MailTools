using System.Net;
using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Util;

namespace BusinessMonitor.MailTools.Mx
{
    public class MxValidator
    {
        /// <summary>
        /// The maximum number of MX hosts that are resolved for a domain, a domain normally has a handful,
        /// the limit protects against a DNS server that answers with a flood of MX records, each of which
        /// costs an address lookup. Hosts beyond the limit are reported in
        /// <see cref="MxValidationResult.UnvalidatedMxRecords"/>
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
            /// non-routable, in other words at least one MX host is not in <see cref="InvalidMxRecords"/>.
            /// False when there are no MX and no address records, for a null MX (RFC 7505), or when every
            /// mail host is invalid. No SMTP connection is made, a server that exists may still refuse mail.
            /// </summary>
            public bool CanReceiveMail { get; set; }

            /// <summary>
            /// The MX hosts that are not a valid host name, have no address records or resolve to a
            /// non-routable address, for an implicit MX this is the domain itself, a null MX next to other
            /// MX records is reported once
            /// </summary>
            public List<string> InvalidMxRecords { get; set; }

            /// <summary>
            /// The MX hosts that were not resolved because the domain has more than 10 distinct MX hosts,
            /// in the order returned by DNS after the first 10. Their validity is unknown, they are neither
            /// in <see cref="InvalidMxRecords"/> nor counted toward <see cref="CanReceiveMail"/>.
            /// A null MX and a host that is not a valid name need no lookup and are still reported.
            /// </summary>
            public List<string> UnvalidatedMxRecords { get; set; }

            /// <summary>
            /// Whether the domain has more than 10 distinct MX hosts and <see cref="UnvalidatedMxRecords"/>
            /// lists the hosts that were not resolved
            /// </summary>
            public bool MxRecordLimitExceeded { get; set; }

            public MxValidationResult()
            {
                InvalidMxRecords = new List<string>();
                UnvalidatedMxRecords = new List<string>();
            }
        }

        /// <summary>
        /// Validates the MX records of a domain. A domain without MX records falls back to the implicit
        /// MX (RFC 5321 section 5.1), the address records of the domain itself are then validated and
        /// <see cref="MxValidationResult.HasImplicitMx"/> is set. A null MX (RFC 7505) is an MX record
        /// and does not fall back. At most 10 distinct MX hosts are resolved, any further hosts are
        /// reported in <see cref="MxValidationResult.UnvalidatedMxRecords"/>.
        /// </summary>
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

            result.HasMxRecords = true;

            // DNS names are case-insensitive, a host listed more than once is resolved and reported once
            var seenHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

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

                if (!seenHosts.Add(host))
                {
                    continue;
                }

                // Only the first hosts are resolved, the rest are reported as not validated
                if (seenHosts.Count > MaxMxRecords)
                {
                    result.MxRecordLimitExceeded = true;
                    result.UnvalidatedMxRecords.Add(mxRecord);
                    continue;
                }

                // A host without address records cannot receive mail (RFC 5321 section 5.1)
                IPAddress[] ipAddresses = _resolver.GetAddressRecords(host).WithoutNulls();
                if (ipAddresses.Length == 0 || ipAddresses.Any(IPAddressHelper.IsNonRoutable))
                {
                    result.InvalidMxRecords.Add(mxRecord);
                }
                else
                {
                    result.CanReceiveMail = true;
                }
            }

            return result;
        }
    }
}