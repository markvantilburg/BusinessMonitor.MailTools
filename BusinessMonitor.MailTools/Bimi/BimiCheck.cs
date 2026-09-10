using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Util;
using System.Net;

namespace BusinessMonitor.MailTools.Bimi
{
    /// <summary>
    /// Parses, checks and lookups BIMI (Brand Indicators for Message Identification) records on domain names
    /// </summary>
    public class BimiCheck
    {
        private readonly IResolver _resolver;

        /// <summary>
        /// Initializes a new BIMI check instance with the provided DNS resolver
        /// </summary>
        /// <param name="resolver">The DNS resolver to use</param>
        public BimiCheck(IResolver resolver)
        {
            if (resolver == null)
            {
                throw new ArgumentNullException(nameof(resolver));
            }

            _resolver = resolver;
        }

        /// <summary>
        /// Gets a BIMI record from a domain
        /// </summary>
        /// <param name="domain">The domain of the sender</param>
        /// <param name="selector">The selector</param>
        /// <returns>The parsed BIMI record</returns>
        /// <exception cref="BimiNotFoundException">No BIMI record was found for the domain</exception>
        /// <exception cref="BimiInvalidException">The BIMI record was invalid, or the selector publishes more than one record</exception>
        public BimiRecord GetBimiRecord(string domain, string selector = "default")
        {
            domain = DnsName.ValidateDomain(domain, nameof(domain));
            DnsName.ValidateSelector(selector, nameof(selector));

            var name = selector + "._bimi." + domain;

            if (name.Length > 253)
            {
                throw new ArgumentException("Selector and domain combined exceed the maximum DNS name length of 253 characters", nameof(selector));
            }

            var records = _resolver.GetTextRecords(name) ?? Array.Empty<string>();

            // Records that do not start with a version tag are discarded (BIMI draft section 7.2)
            var bimiRecords = records.Where(IsBimiRecord).ToList();

            if (bimiRecords.Count == 0)
            {
                throw new BimiNotFoundException($"No BIMI record found for selector '{selector}' on domain");
            }

            // Multiple records terminate discovery, BIMI processing is not performed (BIMI draft section 7.2)
            if (bimiRecords.Count > 1)
            {
                throw new BimiInvalidException($"Multiple BIMI records found for selector '{selector}' on domain, receivers discard all of them");
            }

            // Parse and validate the record and return it
            return ParseBimiRecord(bimiRecords[0]);
        }

        /// <summary>
        /// Parses and validates a BIMI record and return the record
        /// </summary>
        /// <param name="value">The record content</param>
        /// <returns>The parsed BIMI record</returns>
        /// <exception cref="BimiInvalidException">The BIMI record was invalid</exception>
        public static BimiRecord ParseBimiRecord(string value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            // The version must be the first tag and match BIMI1 precisely (BIMI draft section 4.3)
            if (!IsBimiRecord(value))
            {
                throw new BimiInvalidException("Not a valid BIMI record, the first tag must be v=BIMI1");
            }

            // Split all tags
            var tags = value.Split(';');
            var record = new BimiRecord();

            // Tags follow the DKIM tag-value syntax, a duplicate tag makes the record invalid (RFC 6376 section 3.2)
            var seen = new HashSet<string>(StringComparer.Ordinal) { "v" };

            for (var index = 1; index < tags.Length; index++)
            {
                var t = tags[index];
                var i = t.IndexOf('=');

                if (i == -1)
                {
                    // A trailing separator is allowed, any other segment must be a tag=value pair
                    if (index == tags.Length - 1 && t.Trim().Length == 0)
                    {
                        continue;
                    }

                    throw new BimiInvalidException($"BIMI record contains a malformed tag '{t.Trim().Sanitize()}'");
                }

                var tag = t.Substring(0, i).Trim();
                var val = t.Substring(i + 1).Trim();

                if (!IsValidTagName(tag))
                {
                    throw new BimiInvalidException($"BIMI record contains an invalid tag name '{tag.Sanitize()}'");
                }

                if (!seen.Add(tag))
                {
                    throw new BimiInvalidException($"BIMI record contains duplicate tag '{tag}'");
                }

                // Process the tag, unknown tags are ignored
                switch (tag)
                {
                    // Authority Evidence Location
                    case "a":
                        ValidateUri(val, "evidence location");
                        record.Evidence = val;

                        break;

                    // Location of Brand Indicator file
                    case "l":
                        ValidateUri(val, "location");
                        record.Location = val;

                        break;

                    // Local-Part Selector
                    case "lps":
                        record.LocalPartSelectors = GetLocalPartSelectors(val);

                        break;

                    // Avatar Preference
                    // TODO s= tag was removed in v9, remove when spec no longer is a draft
                    case "s":
                    case "avp":
                        record.AvatarPreference = GetAvatarPreference(val);

                        break;
                }
            }

            // Check for required tags
            if (record.Location == null)
            {
                throw new BimiInvalidException("BIMI record is missing a required location tag");
            }

            // Return the record
            return record;
        }

        /// <summary>
        /// Checks whether a TXT record is a BIMI record, the first tag must be the version with the
        /// value BIMI1 which must match precisely (BIMI draft section 4.3), whitespace around the
        /// equals sign is allowed by the tag-value syntax
        /// </summary>
        private static bool IsBimiRecord(string value)
        {
            var end = value.IndexOf(';');
            var first = end == -1 ? value : value.Substring(0, end);
            var index = first.IndexOf('=');

            if (index == -1)
            {
                return false;
            }

            return first.Substring(0, index).Trim() == "v"
                && string.Equals(first.Substring(index + 1).Trim(), "BIMI1", StringComparison.Ordinal);
        }

        /// <summary>
        /// Checks whether a value is a valid tag name, a letter followed by letters, digits or
        /// underscores (RFC 6376 section 3.2)
        /// </summary>
        private static bool IsValidTagName(string value)
        {
            if (value.Length == 0)
            {
                return false;
            }

            var first = value[0];

            if ((first < 'a' || first > 'z') && (first < 'A' || first > 'Z'))
            {
                return false;
            }

            for (var i = 1; i < value.Length; i++)
            {
                var c = value[i];

                if ((c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_')
                {
                    return false;
                }
            }

            return true;
        }

        private static void ValidateUri(string value, string type)
        {
            // May be empty, so don't fail validation then
            if (string.IsNullOrEmpty(value))
            {
                return;
            }

            Uri uri;
            try
            {
                uri = new Uri(value);
            }
            catch (UriFormatException)
            {
                throw new BimiInvalidException($"BIMI record {type} is not a well-formed URI");
            }

            // Check the transport scheme
            if (uri.Scheme != "https")
            {
                throw new BimiInvalidException($"BIMI record {type} is invalid, transport must be HTTPS");
            }

            // A consumer is expected to fetch these locations, reject the targets that would turn
            // that fetch into a request against the consumer itself or its internal network. A host
            // name that resolves to such an address can only be caught at fetch time.
            if (!string.IsNullOrEmpty(uri.UserInfo))
            {
                throw new BimiInvalidException($"BIMI record {type} is invalid, must not contain credentials");
            }

            var host = uri.DnsSafeHost;

            if (host.Length == 0)
            {
                throw new BimiInvalidException($"BIMI record {type} is invalid, must contain a host");
            }

            if (uri.HostNameType == UriHostNameType.IPv4 || uri.HostNameType == UriHostNameType.IPv6)
            {
                if (IPAddress.TryParse(host, out var address) && IPAddressHelper.IsNonRoutable(address))
                {
                    throw new BimiInvalidException($"BIMI record {type} is invalid, must not point to a non-routable address");
                }
            }
            else if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
            {
                throw new BimiInvalidException($"BIMI record {type} is invalid, must not point to localhost");
            }
        }

        private static string[] GetLocalPartSelectors(string value)
        {
            var selectors = value.SplitTrim(',');

            if (selectors.Length == 0)
            {
                throw new BimiInvalidException("Invalid local-part selector, value must not be empty");
            }

            foreach (var selector in selectors)
            {
                if (!IsValidDnsLabel(selector))
                {
                    throw new BimiInvalidException($"Invalid local-part selector '{selector.Sanitize()}', selector must be a valid DNS label");
                }
            }

            return selectors;
        }

        /// <summary>
        /// Checks whether a value is a valid DNS label
        /// ASCII letters, digits or hyphens only, and must not start or end with a hyphen
        /// </summary>
        private static bool IsValidDnsLabel(string value)
        {
            return DnsName.IsValidLabel(value);
        }

        private static AvatarPreference GetAvatarPreference(string value)
        {
            // TODO bimi value was removed in v10, remove when spec no longer is a draft
            if (value != "personal" && value != "brand" && value != "bimi")
            {
                throw new BimiInvalidException("Invalid avatar preference, must be personal or brand");
            }

            return value == "personal" ? AvatarPreference.Personal : AvatarPreference.Brand;
        }
    }
}
