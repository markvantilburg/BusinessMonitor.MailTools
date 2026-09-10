using System.Text.RegularExpressions;

namespace BusinessMonitor.MailTools.Util
{
    /// <summary>
    /// Validation helpers for DNS names, labels and selectors
    /// </summary>
    internal static class DnsName
    {
        private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

        // \z rather than $, in .NET $ also matches before a trailing newline so "abc\n" would be a valid label
        private static readonly Regex LabelRegex = new(
            @"^[a-zA-Z0-9_]([a-zA-Z0-9_\-]{0,61}[a-zA-Z0-9_])?\z",
            RegexOptions.None,
            RegexTimeout);

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
        /// Validates a caller-provided domain name, throws when it is not a valid DNS name.
        /// A single trailing dot, the absolute (FQDN) form, is accepted and removed
        /// </summary>
        /// <returns>The domain without a trailing dot</returns>
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
        /// A single trailing dot is removed. Returns false when the value is not a valid DNS name,
        /// such a name must not be passed back to the resolver.
        /// </summary>
        internal static bool TryNormalizeHost(string value, out string host)
        {
            host = value ?? string.Empty;

            if (host.Length > 1 && host[host.Length - 1] == '.')
            {
                host = host.Substring(0, host.Length - 1);
            }

            return IsValidName(host);
        }

        /// <summary>
        /// Validates a caller-provided selector, throws when it is not a valid DNS name
        /// A selector is a sub-domain and may consist of multiple labels
        /// </summary>
        internal static void ValidateSelector(string selector, string paramName)
        {
            if (selector == null)
            {
                throw new ArgumentNullException(paramName);
            }

            if (!IsValidName(selector))
            {
                throw new ArgumentException($"Selector '{selector.Sanitize()}' is not a valid DNS name", paramName);
            }
        }
    }
}
