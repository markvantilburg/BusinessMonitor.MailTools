using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Util;
using System.Globalization;

namespace BusinessMonitor.MailTools.Dmarc
{
    /// <summary>
    /// Parses, checks and lookups DMARC (Domain-based Message Authentication, Reporting, and Conformance)
    /// records on domain names, following RFC 9989
    /// </summary>
    public class DmarcCheck
    {
        private readonly IResolver _resolver;

        /// <summary>
        /// Initializes a new DMARC check instance with the provided DNS resolver
        /// </summary>
        /// <param name="resolver">The DNS resolver to use</param>
        public DmarcCheck(IResolver resolver)
        {
            if (resolver == null)
            {
                throw new ArgumentNullException(nameof(resolver));
            }

            _resolver = resolver;
        }

        /// <summary>
        /// Gets the DMARC record published at _dmarc.domain
        /// </summary>
        /// <remarks>
        /// Only the given domain is queried. The policy discovery of RFC 9989 section 4.10.1 continues with
        /// the organizational domain when a subdomain has no record, this is left to the caller as it
        /// requires the public suffix list or a DNS tree walk.
        /// </remarks>
        /// <param name="domain">The domain of the sender</param>
        /// <returns>The parsed DMARC record</returns>
        /// <exception cref="DmarcNotFoundException">No DMARC record was found for the domain</exception>
        /// <exception cref="DmarcInvalidException">The DMARC record was invalid, or the domain publishes more than one record</exception>
        /// <exception cref="ArgumentException">The domain is not a valid DNS name</exception>
        public DmarcRecord GetDmarcRecord(string domain)
        {
            domain = DnsName.ValidateDomain(domain, nameof(domain));

            var name = "_dmarc." + domain;

            if (name.Length > 253)
            {
                throw new ArgumentException("Domain exceeds the maximum DNS name length of 253 characters with the _dmarc prefix", nameof(domain));
            }

            var records = _resolver.GetTextRecords(name) ?? Array.Empty<string>();

            // Records that do not start with a version tag are discarded (RFC 9989 section 4.10.1)
            var dmarcRecords = records.Where(IsDmarcRecord).ToList();

            if (dmarcRecords.Count == 0)
            {
                throw new DmarcNotFoundException("No DMARC record found on domain");
            }

            // Multiple records are all discarded by receivers, no policy applies (RFC 9989 section 4.10.1)
            if (dmarcRecords.Count > 1)
            {
                throw new DmarcInvalidException("Multiple DMARC records found on domain, receivers discard all of them (RFC 9989 section 4.10.1)");
            }

            // Parse and validate the record and return it
            return ParseDmarcRecord(dmarcRecords[0]);
        }

        /// <summary>
        /// Parses and validates a DMARC record and return the record
        /// </summary>
        /// <remarks>
        /// Parsing is stricter than a receiver has to be. RFC 9989 section 4.8 lets receivers ignore
        /// syntax errors in favour of defaults, this parser reports them as <see cref="DmarcInvalidException"/>
        /// so a domain owner can fix them. Unknown tags are ignored as the RFC requires.
        /// </remarks>
        /// <param name="value">The record content</param>
        /// <returns>The parsed DMARC record</returns>
        /// <exception cref="DmarcInvalidException">The DMARC record was invalid</exception>
        public static DmarcRecord ParseDmarcRecord(string value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            // The version must be the first tag and its value is case sensitive (RFC 9989 section 4.7)
            if (!IsDmarcRecord(value))
            {
                throw new DmarcInvalidException("Not a valid DMARC record, the first tag must be v=DMARC1");
            }

            var tags = value.Split(';');
            var record = new DmarcRecord();

            // Tags follow the DKIM tag-value syntax, a duplicate tag makes the record invalid (RFC 6376 section 3.2)
            var seen = new HashSet<string>(StringComparer.Ordinal) { "v" };

            // Tags may appear in any order (RFC 9989 section 4.8), the policies are resolved after parsing
            // because sp and np inherit from tags that may follow them
            ReceiverPolicy? policy = null;
            ReceiverPolicy? subdomainPolicy = null;
            ReceiverPolicy? nonExistentSubdomainPolicy = null;
            FailureOptions? failureOptions = null;

            for (var index = 1; index < tags.Length; index++)
            {
                var t = tags[index];
                var i = t.IndexOf('=');

                if (i == -1)
                {
                    // A trailing separator is allowed (RFC 9989 section 4.8), any other segment must be a tag=value pair
                    if (index == tags.Length - 1 && t.Trim().Length == 0)
                    {
                        continue;
                    }

                    throw new DmarcInvalidException($"DMARC record contains a malformed tag '{t.Trim().Sanitize()}'");
                }

                var tag = t.Substring(0, i).Trim();
                var val = t.Substring(i + 1).Trim();

                // A tag name is one or more letters (RFC 9989 section 4.8)
                if (!IsValidTagName(tag))
                {
                    throw new DmarcInvalidException($"DMARC record contains an invalid tag name '{tag.Sanitize()}'");
                }

                if (!seen.Add(tag))
                {
                    throw new DmarcInvalidException($"DMARC record contains duplicate tag '{tag}'");
                }

                // A tag value is at least one character (RFC 9989 section 4.8)
                if (val.Length == 0)
                {
                    throw new DmarcInvalidException($"DMARC record tag '{tag}' has an empty value");
                }

                // Process the tag, tag values other than the version are case insensitive
                switch (tag)
                {
                    // DKIM Identifier Alignment mode
                    case "adkim":
                        record.DkimMode = GetAlignmentMode(val, tag);
                        break;

                    // SPF Identifier Alignment mode
                    case "aspf":
                        record.SpfMode = GetAlignmentMode(val, tag);
                        break;

                    // Failure reporting options, only applied when a ruf tag is present
                    case "fo":
                        failureOptions = GetFailureOptions(val);
                        break;

                    // Policy for non-existent subdomains
                    case "np":
                        nonExistentSubdomainPolicy = GetReceiverPolicy(val, tag);
                        break;

                    // Domain Owner Assessment Policy
                    case "p":
                        policy = GetReceiverPolicy(val, tag);
                        break;

                    // Percentage tag, removed in RFC 9989 and ignored by receivers following it,
                    // still parsed for receivers following RFC 7489
#pragma warning disable CS0618
                    case "pct":
                        record.PercentageTag = GetPercentage(val);
                        break;

                    // Public Suffix Domain flag
                    case "psd":
                        record.PublicSuffixDomain = GetPublicSuffixDomain(val);
                        break;

                    // Report format, removed in RFC 9989
                    case "rf":
                        record.ReportFormat = val.SplitTrim(':', StringSplitOptions.None);
                        break;

                    // Interval requested between aggregate reports, removed in RFC 9989
                    case "ri":
                        if (!uint.TryParse(val, NumberStyles.None, CultureInfo.InvariantCulture, out var interval))
                        {
                            throw new DmarcInvalidException($"Invalid report interval tag '{val.Sanitize()}', must be a positive number");
                        }

                        record.ReportInterval = interval;
                        break;
#pragma warning restore CS0618

                    // Addresses to which aggregate feedback is to be sent
                    case "rua":
                        record.AggregatedReportAddresses = GetReportUris(val, tag);
                        break;

                    // Addresses to which message-specific failure information is to be reported
                    case "ruf":
                        record.ForensicReportAddresses = GetReportUris(val, tag);
                        break;

                    // Policy for subdomains
                    case "sp":
                        subdomainPolicy = GetReceiverPolicy(val, tag);
                        break;

                    // Test mode
                    case "t":
                        record.TestMode = GetYesNo(val, tag);
                        break;

                    // Unknown tags must be ignored (RFC 9989 section 4.8)
                    default:
                        break;
                }
            }

            // An absent p tag is treated as p=none (RFC 9989 section 4.7)
            record.PolicySpecified = policy != null;
            record.Policy = policy ?? ReceiverPolicy.None;

            // Subdomains inherit the p policy, non-existent subdomains inherit sp and then p (RFC 9989 section 4.7)
            record.SubdomainPolicy = subdomainPolicy ?? record.Policy;
            record.NonExistentSubdomainPolicy = nonExistentSubdomainPolicy ?? record.SubdomainPolicy;

            // The fo tag must be ignored when no ruf tag is present (RFC 9989 section 4.7)
            if (failureOptions != null && record.ForensicReportAddresses.Length > 0)
            {
                record.FailureOptions = failureOptions.Value;
            }

            // Return the record
            return record;
        }

        /// <summary>
        /// Checks whether a TXT record is a DMARC record, the first tag must be the version
        /// with the case sensitive value DMARC1, whitespace around the equals sign is allowed
        /// (RFC 9989 sections 4.7 and 4.8)
        /// </summary>
        private static bool IsDmarcRecord(string value)
        {
            var end = value.IndexOf(';');
            var first = end == -1 ? value : value.Substring(0, end);
            var index = first.IndexOf('=');

            if (index == -1)
            {
                return false;
            }

            return first.Substring(0, index).Trim() == "v"
                && string.Equals(first.Substring(index + 1).Trim(), "DMARC1", StringComparison.Ordinal);
        }

        /// <summary>
        /// Checks whether a value is a valid tag name, one or more ASCII letters (RFC 9989 section 4.8)
        /// </summary>
        private static bool IsValidTagName(string value)
        {
            if (value.Length == 0)
            {
                return false;
            }

            foreach (var c in value)
            {
                if ((c < 'a' || c > 'z') && (c < 'A' || c > 'Z'))
                {
                    return false;
                }
            }

            return true;
        }

        private static AlignmentMode GetAlignmentMode(string value, string tag)
        {
            if (value.Equals("r", StringComparison.OrdinalIgnoreCase)) return AlignmentMode.Relaxed;
            if (value.Equals("s", StringComparison.OrdinalIgnoreCase)) return AlignmentMode.Strict;

            throw new DmarcInvalidException($"Invalid {tag} tag '{value.Sanitize()}', alignment mode must be r or s");
        }

        private static ReceiverPolicy GetReceiverPolicy(string value, string tag)
        {
            if (value.Equals("none", StringComparison.OrdinalIgnoreCase)) return ReceiverPolicy.None;
            if (value.Equals("quarantine", StringComparison.OrdinalIgnoreCase)) return ReceiverPolicy.Quarantine;
            if (value.Equals("reject", StringComparison.OrdinalIgnoreCase)) return ReceiverPolicy.Reject;

            throw new DmarcInvalidException($"Invalid {tag} tag '{value.Sanitize()}', policy must be none, quarantine or reject");
        }

        private static bool GetYesNo(string value, string tag)
        {
            if (value.Equals("y", StringComparison.OrdinalIgnoreCase)) return true;
            if (value.Equals("n", StringComparison.OrdinalIgnoreCase)) return false;

            throw new DmarcInvalidException($"Invalid {tag} tag '{value.Sanitize()}', must be y or n");
        }

        private static PublicSuffixDomain GetPublicSuffixDomain(string value)
        {
            if (value.Equals("y", StringComparison.OrdinalIgnoreCase)) return PublicSuffixDomain.Yes;
            if (value.Equals("n", StringComparison.OrdinalIgnoreCase)) return PublicSuffixDomain.No;
            if (value.Equals("u", StringComparison.OrdinalIgnoreCase)) return PublicSuffixDomain.Unknown;

            throw new DmarcInvalidException($"Invalid psd tag '{value.Sanitize()}', must be y, n or u");
        }

        private static int GetPercentage(string value)
        {
            // 1*3DIGIT (RFC 7489 section 6.4)
            if (value.Length > 3 || !int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var percentage))
            {
                throw new DmarcInvalidException($"Invalid percentage tag '{value.Sanitize()}', must be a number");
            }

            if (percentage > 100)
            {
                throw new DmarcInvalidException("Invalid percentage tag, must be between 0 and 100");
            }

            return percentage;
        }

        /// <summary>
        /// Parses the failure reporting options, a colon separated list containing at most one of
        /// 0 or 1 and each of d and s at most once (RFC 9989 section 4.8)
        /// </summary>
        private static FailureOptions GetFailureOptions(string value)
        {
            var options = FailureOptions.None;

            foreach (var option in value.SplitTrim(':', StringSplitOptions.None))
            {
                FailureOptions flag;

                switch (option.ToLowerInvariant())
                {
                    case "0": flag = FailureOptions.All; break;
                    case "1": flag = FailureOptions.Any; break;
                    case "d": flag = FailureOptions.DkimFailure; break;
                    case "s": flag = FailureOptions.SpfFailure; break;
                    default:
                        throw new DmarcInvalidException($"Invalid fo tag '{value.Sanitize()}', options must be 0, 1, d or s");
                }

                if ((options & flag) != 0)
                {
                    throw new DmarcInvalidException($"Invalid fo tag '{value.Sanitize()}', option '{option}' appears more than once");
                }

                if ((flag == FailureOptions.All && (options & FailureOptions.Any) != 0)
                    || (flag == FailureOptions.Any && (options & FailureOptions.All) != 0))
                {
                    throw new DmarcInvalidException($"Invalid fo tag '{value.Sanitize()}', options 0 and 1 cannot be combined");
                }

                options |= flag;
            }

            return options;
        }

        /// <summary>
        /// Parses a comma separated list of report URIs (RFC 9989 section 4.8), whitespace around the
        /// commas is allowed and the obsolete report size suffix of RFC 7489 such as !10m is removed
        /// </summary>
        private static string[] GetReportUris(string value, string tag)
        {
            var uris = value.SplitTrim(',', StringSplitOptions.None);

            for (var i = 0; i < uris.Length; i++)
            {
                var uri = StripReportSize(uris[i]);

                if (uri.Length == 0 || !Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
                {
                    throw new DmarcInvalidException($"Invalid {tag} tag, '{uris[i].Sanitize()}' is not a valid URI");
                }

                // A mailto URI must contain an address, receivers are only required to support mailto
                if (parsed.Scheme == "mailto" && parsed.AbsoluteUri.IndexOf('@') == -1)
                {
                    throw new DmarcInvalidException($"Invalid {tag} tag, '{uris[i].Sanitize()}' is not a valid mailto URI");
                }

                uris[i] = uri;
            }

            return uris;
        }

        /// <summary>
        /// Removes the obsolete report size suffix, an exclamation mark followed by digits and an
        /// optional k, m, g or t unit (RFC 9989 section 4.8, obs-dmarc-report-size). Exclamation
        /// marks that are part of the URI itself must be percent encoded so any present is a suffix
        /// </summary>
        private static string StripReportSize(string uri)
        {
            var index = uri.LastIndexOf('!');

            if (index == -1)
            {
                return uri;
            }

            var size = uri.Substring(index + 1);

            if (size.Length > 0 && "kmgtKMGT".IndexOf(size[size.Length - 1]) != -1)
            {
                size = size.Substring(0, size.Length - 1);
            }

            if (size.Length == 0 || !size.All(c => c >= '0' && c <= '9'))
            {
                return uri;
            }

            return uri.Substring(0, index);
        }
    }
}
