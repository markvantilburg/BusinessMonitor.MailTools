using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;
using System.Net;

namespace BusinessMonitor.MailTools.Spf
{
    /// <summary>
    /// Parses, checks and lookups SPF (Sender Policy Framework) records on domain names
    /// </summary>
    public class SpfCheck
    {
        /// <summary>
        /// The number of lookups the resolver can make
        /// </summary>
        private const int MaxLookups = 10;

        /// <summary>
        /// The valid mechanisms
        /// </summary>
        private static readonly string[] Mechanisms = new[] { "a", "mx", "ptr", "ip4", "ip6", "exists", "all", "include" };

        /// <summary>
        /// The valid qualifiers
        /// </summary>
        private static readonly string[] Qualifiers = new[] { "+", "-", "~", "?" };

        private IResolver _resolver;
        private int _lookups;

        /// <summary>
        /// Initializes a new SPF check instance with the provided DNS resolver
        /// </summary>
        /// <param name="resolver">The DNS resolver to use</param>
        public SpfCheck(IResolver resolver)
        {
            _resolver = resolver;
            _lookups = 0;
        }

        /// <summary>
        /// Gets a SPF record from a domain
        /// </summary>
        /// <param name="domain">The domain</param>
        public SpfRecord GetSpfRecord(string domain)
        {
            var records = _resolver.GetTextRecords(domain);
            _lookups++;

            // Find the SPF record
            var record = records.FirstOrDefault(x => x.StartsWith("v=spf1"));

            if (record == default)
            {
                throw new InvalidSpfException("Domain does not contain a SPF record");
            }

            // Parse and validate the record and return it
            var parsed = ParseSpfRecord(record);

            foreach (var directive in parsed.Directives)
            {
                if (directive.Mechanism == SpfMechanism.Include && directive.Include != null)
                {
                    if (_lookups >= MaxLookups)
                    {
                        throw new InvalidSpfException("SPF record exceeds max lookups of 10");
                    }

                    var included = GetSpfRecord(directive.Include);
                    _lookups++;

                    directive.Included = included;
                }
            }

            return parsed;
        }

        /// <summary>
        /// Checks an IP address for a host
        /// </summary>
        /// <param name="address">The IP address to check</param>
        /// <param name="domain">The host to check</param>
        /// <returns>Whether the host allows the IP address</returns>
        public bool CheckSpfRecord(IPAddress address, string domain)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Parses and validates a SPF record and return the record
        /// </summary>
        /// <param name="value">The record content</param>
        /// <returns>The parsed SPF record</returns>
        public static SpfRecord ParseSpfRecord(string value)
        {
            // Check if the record starts with SPF version 1
            if (!value.StartsWith("v=spf1"))
            {
                throw new InvalidSpfException("Not a valid SPF record, does not contain a version");
            }

            // Split the mechanisms
            var split = value.Split(' ').Skip(1);
            var directives = new List<SpfDirective>();

            foreach (var d in split)
            {
                var directive = d;

                // Extract the qualifier if any
                var qualifier = directive.Substring(0, 1);

                if (Qualifiers.Contains(qualifier))
                {
                    directive = directive.Substring(1);
                }
                else
                {
                    qualifier = "+";
                }

                // Extract the value if any
                var index = directive.IndexOf(':');

                var mechanism = directive;
                var val = string.Empty;

                if (index != -1)
                {
                    val = directive.Substring(index + 1);
                    mechanism = directive.Substring(0, index);
                }

                // Parse the directive
                var parsed = ParseDirective(qualifier, mechanism, val);

                directives.Add(parsed);
            }

            return new SpfRecord(directives);
        }

        /// <summary>
        /// Parses a SPF directive
        /// </summary>
        /// <param name="qualifier">The qualifier</param>
        /// <param name="mechanism">The mechanism</param>
        /// <param name="value">The mechanism value</param>
        /// <returns>The parsed directive</returns>
        private static SpfDirective ParseDirective(string qualifier, string mechanism, string value)
        {
            if (!Mechanisms.Contains(mechanism))
            {
                throw new InvalidSpfException($"Not a valid SPF record, '{mechanism}' is not a valid mechanism");
            }

            // Convert the qualifier and mechanism to matching types
            var qual = (SpfQualifier)Array.IndexOf(Qualifiers, qualifier);
            var mech = (SpfMechanism)Enum.Parse(typeof(SpfMechanism), mechanism, true);

            var directive = new SpfDirective(qual, mech);

            // Process the mechanism
            switch (directive.Mechanism)
            {
                case SpfMechanism.Include:
                    directive.Include = value;

                    break;

                case SpfMechanism.IP4:
                case SpfMechanism.IP6:
                    var address = SpfAddress.Parse(value);
                    if (directive.Mechanism == SpfMechanism.IP4) directive.IP4 = address; else directive.IP6 = address;

                    break;

                default:
                    break;
            }

            return directive;
        }
    }
}
