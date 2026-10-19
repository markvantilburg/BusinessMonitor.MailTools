using System.Globalization;
using System.Text.RegularExpressions;

namespace BusinessMonitor.MailTools.Util
{
    /// <summary>
    /// Validation helpers for DNS names, labels and selectors
    /// </summary>
    internal static class DnsName
    {
        private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

        // Converts internationalized domain names (U-labels) to their ASCII A-label (punycode) form.
        // UseStd3AsciiRules is left off so an underscore label such as a selector is not rejected here,
        // the label regexes decide what is allowed
        private static readonly IdnMapping Idn = new IdnMapping { AllowUnassigned = false, UseStd3AsciiRules = false };

        // \z rather than $, in .NET $ also matches before a trailing newline so "abc\n" would be a valid label
        private static readonly Regex LabelRegex = new(
            @"^[a-zA-Z0-9_]([a-zA-Z0-9_\-]{0,61}[a-zA-Z0-9_])?\z",
            RegexOptions.None,
            RegexTimeout);

        // A host name label (RFC 1123 section 2.1), as a DNS label but without underscores
        private static readonly Regex HostLabelRegex = new(
            @"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\z",
            RegexOptions.None,
            RegexTimeout);

        private static readonly Regex DigitsRegex = new(@"^[0-9]+\z", RegexOptions.None, RegexTimeout);

        // Special-use domain names that are never delegated on the public internet, a host under one of
        // these can never receive internet mail
        private static readonly string[] SpecialUseNames =
        {
            "localhost",  // RFC 6761 section 6.3
            "test",       // RFC 6761 section 6.2
            "example",    // RFC 6761 section 6.5
            "invalid",    // RFC 6761 section 6.4
            "local",      // RFC 6762 (multicast DNS)
            "onion",      // RFC 7686
            "home.arpa",  // RFC 8375
            "internal",   // ICANN reserved private-use TLD (2024)
        };

        /// <summary>
        /// Checks whether a value is a valid DNS label
        /// ASCII letters, digits, underscores or hyphens only, must not start or end with a hyphen, at most 63 characters
        /// </summary>
        internal static bool IsValidLabel(string value)
        {
            return LabelRegex.IsMatch(value);
        }

        /// <summary>
        /// Checks whether a value is a valid DNS name, one or more valid labels separated by dots, at most 253 characters
        /// </summary>
        internal static bool IsValidName(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length > 253)
            {
                return false;
            }

            var labels = value.Split('.');

            foreach (var label in labels)
            {
                if (!IsValidLabel(label))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Checks whether a value is a valid host name (RFC 1123 section 2.1), a DNS name whose labels
        /// consist of letters, digits and hyphens only and whose last label is not all digits, which
        /// rejects IP address literals and numeric top-level domains. Mail exchanges (MX) must be host names.
        /// </summary>
        internal static bool IsValidHostName(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length > 253)
            {
                return false;
            }

            var labels = value.Split('.');

            foreach (var label in labels)
            {
                if (!HostLabelRegex.IsMatch(label))
                {
                    return false;
                }
            }

            return !DigitsRegex.IsMatch(labels[labels.Length - 1]);
        }

        /// <summary>
        /// Checks whether a host name is, or is under, a special-use domain name (RFC 6761 and others) that
        /// is never delegated on the public internet, such as localhost, .local, .test or .internal
        /// </summary>
        internal static bool IsSpecialUseName(string host)
        {
            if (string.IsNullOrEmpty(host))
            {
                return false;
            }

            foreach (var name in SpecialUseNames)
            {
                if (host.Length == name.Length)
                {
                    if (host.Equals(name, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                else if (host.Length > name.Length
                    && host[host.Length - name.Length - 1] == '.'
                    && host.EndsWith(name, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Converts a caller-provided name with non-ASCII characters, an internationalized domain name in
        /// its Unicode (U-label) form such as bücher.de, to the ASCII A-label form used in DNS such as
        /// xn--bcher-kva.de. A name that is already ASCII is returned unchanged, case included.
        /// </summary>
        /// <remarks>
        /// The mapping follows the IDNA implementation of the runtime, .NET Framework and NLS apply IDNA2003
        /// (ß becomes ss), .NET with ICU applies UTS #46 / IDNA2008 (ß is kept as xn--zca), these can be
        /// different registered domains.
        /// </remarks>
        /// <exception cref="ArgumentException">The name cannot be converted to A-labels</exception>
        internal static string ToAsciiName(string value, string paramName)
        {
            if (!HasNonAscii(value))
            {
                return value;
            }

            try
            {
                return Idn.GetAscii(value);
            }
            catch (ArgumentException ex)
            {
                throw new ArgumentException($"'{paramName}' contains characters that cannot be converted to an internationalized domain name (IDNA A-label)", paramName, ex);
            }
        }

        private static bool HasNonAscii(string value)
        {
            foreach (var c in value)
            {
                if (c > 0x7F)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Validates a caller-provided domain name, throws when it is not a valid DNS name.
        /// A single trailing dot, the absolute (FQDN) form, is accepted and removed. An internationalized
        /// domain name (U-labels, such as bücher.de) is converted to its A-label form (xn--bcher-kva.de),
        /// see <see cref="ToAsciiName"/>
        /// </summary>
        /// <returns>The domain without a trailing dot, in A-label form</returns>
        internal static string ValidateDomain(string domain, string paramName)
        {
            if (domain == null)
            {
                throw new ArgumentNullException(paramName);
            }

            if (domain.Length > 1 && domain[domain.Length - 1] == '.')
            {
                domain = domain.Substring(0, domain.Length - 1);
            }

            domain = ToAsciiName(domain, paramName);

            if (domain.Length > 253)
            {
                throw new ArgumentException("Domain must not exceed 253 characters", paramName);
            }

            if (!IsValidName(domain))
            {
                throw new ArgumentException($"Domain '{domain.Sanitize()}' is not a valid DNS name", paramName);
            }

            return domain;
        }

        /// <summary>
        /// Checks whether a host name returned by DNS is a null MX target (RFC 7505), the root name
        /// </summary>
        internal static bool IsNullMx(string value)
        {
            return value != null && (value.Length == 0 || value == ".");
        }

        /// <summary>
        /// Normalizes a host name returned by DNS, such as an MX exchange, before it is resolved again.
        /// A single trailing dot is removed. Returns false when the value is not a valid host name
        /// (RFC 1123 section 2.1, see <see cref="IsValidHostName"/>) or is a special-use name that can
        /// never receive internet mail (see <see cref="IsSpecialUseName"/>), such a name must not be
        /// passed back to the resolver.
        /// </summary>
        internal static bool TryNormalizeHost(string value, out string host)
        {
            host = value ?? string.Empty;

            if (host.Length > 1 && host[host.Length - 1] == '.')
            {
                host = host.Substring(0, host.Length - 1);
            }

            return IsValidHostName(host) && !IsSpecialUseName(host);
        }

        /// <summary>
        /// Validates a caller-provided selector, throws when it is not a valid DNS name.
        /// A selector is a sub-domain and may consist of multiple labels. A selector with non-ASCII
        /// characters is converted to its A-label form, see <see cref="ToAsciiName"/>
        /// </summary>
        /// <returns>The selector in A-label form</returns>
        internal static string ValidateSelector(string selector, string paramName)
        {
            if (selector == null)
            {
                throw new ArgumentNullException(paramName);
            }

            selector = ToAsciiName(selector, paramName);

            if (!IsValidName(selector))
            {
                throw new ArgumentException($"Selector '{selector.Sanitize()}' is not a valid DNS name", paramName);
            }

            return selector;
        }
    }
}
