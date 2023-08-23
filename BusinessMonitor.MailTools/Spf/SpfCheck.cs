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

        private readonly IResolver _resolver;
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
            _lookups = 0;

            return GetRecord(domain);
        }

        internal SpfRecord GetRecord(string domain)
        {
            var records = _resolver.GetTextRecords(domain);
            _lookups++;

            // Find the SPF record
            var record = records.FirstOrDefault(x => x.StartsWith("v=spf1", StringComparison.InvariantCultureIgnoreCase));

            if (record == default)
            {
                throw new SpfNotFoundException("No SPF record found on domain");
            }

            // Parse and validate the record and return it
            var parsed = ParseSpfRecord(record);

            foreach (var directive in parsed.Directives)
            {
                if (directive.Mechanism == SpfMechanism.Include && directive.Include != null)
                {
                    if (_lookups >= MaxLookups)
                    {
                        throw new SpfLookupException("SPF record exceeds max lookups of 10");
                    }

                    try
                    {
                        var included = GetRecord(directive.Include);

                        directive.Included = included;
                    }
                    catch (SpfException ex)
                    {
                        throw new SpfLookupException($"SPF include lookup failed for '{directive.Include}', see inner exception", ex);
                    }
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
            if (!value.StartsWith("v=spf1", StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SpfInvalidException("Not a valid SPF record, does not contain a version");
            }

            // Split the terms
            var split = value.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).Skip(1);

            var directives = new List<SpfDirective>();
            var modifiers = new List<SpfModifier>();

            foreach (var term in split)
            {
                var index = term.IndexOf('=');

                // Check if term is a modifier
                if (index != -1)
                {
                    var modifier = ParseModifier(term);

                    modifiers.Add(modifier);
                }
                else
                {
                    var directive = ParseDirective(term);

                    directives.Add(directive);
                }
            }

            return new SpfRecord(directives, modifiers);
        }

        /// <summary>
        /// Parses a SPF directive
        /// </summary>
        /// <param name="term">The term to parse</param>
        /// <returns>The parsed directive</returns>
        private static SpfDirective ParseDirective(string term)
        {
            // Extract the qualifier if any
            var qualifier = term.Substring(0, 1);

            if (Qualifiers.Contains(qualifier))
            {
                term = term.Substring(1);
            }
            else
            {
                qualifier = "+";
            }

            // Extract the value if any
            var index = term.IndexOf(':');

            var mechanism = term;
            var value = string.Empty;

            if (index != -1)
            {
                value = term.Substring(index + 1);
                mechanism = term.Substring(0, index);
            }

            return ParseDirective(qualifier, mechanism, value);
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
            if (!Mechanisms.Contains(mechanism.ToLower()))
            {
                throw new SpfInvalidException($"Not a valid SPF record, '{mechanism}' is not a valid mechanism");
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

        /// <summary>
        /// Parse a SPF modifier
        /// </summary>
        /// <param name="term">The term to parse</param>
        /// <returns>The parsed modifier</returns>
        private static SpfModifier ParseModifier(string term)
        {
            var index = term.IndexOf("=");

            var name = term.Substring(0, index);
            var value = term.Substring(index + 1);

            return new SpfModifier(name, value);
        }
    }
}
