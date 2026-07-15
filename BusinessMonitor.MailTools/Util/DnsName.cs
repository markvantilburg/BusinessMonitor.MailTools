using System.Text.RegularExpressions;

namespace BusinessMonitor.MailTools.Util
{
    /// <summary>
    /// Validation helpers for DNS names, labels and selectors
    /// </summary>
    internal static class DnsName
    {
        private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

        private static readonly Regex LabelRegex = new(
            @"^[a-zA-Z0-9_]([a-zA-Z0-9_\-]{0,61}[a-zA-Z0-9_])?$",
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
        /// Validates a caller-provided domain name, throws when it is not a valid DNS name
        /// </summary>
        internal static void ValidateDomain(string domain, string paramName)
        {
            if (domain == null)
            {
                throw new ArgumentNullException(paramName);
            }

            if (domain.Length > 253)
            {
                throw new ArgumentException("Domain must not exceed 253 characters", paramName);
            }

            if (!IsValidName(domain))
            {
                throw new ArgumentException($"Domain '{domain}' is not a valid DNS name", paramName);
            }
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
                throw new ArgumentException($"Selector '{selector}' is not a valid DNS name", paramName);
            }
        }
    }
}
