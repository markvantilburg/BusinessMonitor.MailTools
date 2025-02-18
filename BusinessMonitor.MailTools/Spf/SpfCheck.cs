using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;
using System.Net;
using System.Text.RegularExpressions;

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
            if (resolver == null)
            {
                throw new ArgumentNullException(nameof(resolver));
            }

            _resolver = resolver;
            _lookups = 0;
        }

        /// <summary>
        /// Gets a SPF record from a domain
        /// </summary>
        /// <param name="domain">The domain</param>
        /// <returns>The parsed SPF record</returns>
        /// <exception cref="SpfNotFoundException">No SPF record was found for the domain</exception>
        /// <exception cref="SpfInvalidException">The SPF record was invalid</exception>
        /// <exception cref="SpfLookupException">An include lookup failed, see inner exception</exception>
        public SpfRecord GetSpfRecord(string domain)
        {
            if (domain == null)
            {
                throw new ArgumentNullException(nameof(domain));
            }

            if (domain.Length > 253)
            {
                throw new ArgumentException("Domain must not exceed 253 characters", nameof(domain));
            }

            _lookups = 0;

            return GetRecord(domain);
        }

        private SpfRecord GetRecord(string domain)
        {
            var records = _resolver.GetTextRecords(domain);

            // Find the SPF record
            var record = records.FirstOrDefault(x => x.StartsWith("v=spf1", StringComparison.InvariantCultureIgnoreCase));

            if (record == default)
            {
                throw new SpfNotFoundException("No SPF record found on domain");
            }

            if (records.Count(x => x.StartsWith("v=spf1", StringComparison.InvariantCultureIgnoreCase)) > 1)
            {
                throw new SpfInvalidException("Too many SPF records found on domain");
            }

            // Parse and validate the record and return it
            var parsed = ParseSpfRecord(record);

            foreach (var directive in parsed.Directives)
            {
                if (directive.Mechanism == SpfMechanism.Include && directive.Include != null)
                {
                    _lookups++;

                    if (_lookups > MaxLookups)
                    {
                        throw new SpfLookupException("SPF record exceeds max lookups of 10");
                    }

                    try
                    {
                        var included = GetRecord(directive.Include);

                        directive.Included = included;
                    }
                    catch (SpfException ex) when (ex is not SpfLookupException)
                    {
                        throw new SpfLookupException($"SPF include lookup failed for '{directive.Include}', see inner exception", ex);
                    }
                }

                if (directive.Mechanism == SpfMechanism.A || directive.Mechanism == SpfMechanism.MX)
                {
                    _lookups++;

                    if (_lookups > MaxLookups)
                    {
                        throw new SpfLookupException("SPF record exceeds max lookups of 10");
                    }

                    if (string.IsNullOrEmpty(directive.Domain))
                    {
                        directive.Domain = domain;
                    }

                    directive.Addresses = ResolveDirective(directive);
                }
            }

            return parsed;
        }

        /// <summary>
        /// Parses and validates a SPF record and return the record
        /// </summary>
        /// <param name="value">The record content</param>
        /// <returns>The parsed SPF record</returns>
        /// <exception cref="SpfInvalidException">The SPF record was invalid</exception>
        public static SpfRecord ParseSpfRecord(string value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

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

                    // do a sanity check on the domain name to make sure its legal
                    if (!Regex.IsMatch(value, @"^[a-z|A-Z|0-9|\-|_]{1,63}(\.[a-z|A-Z|0-9|\-|_]{1,63})+$"))
                    {
                        // and individual labels can't be bigger than 63 chars
                        throw new SpfInvalidException($"Include must be a domain name. The include value '{value}' fails");
                    }

                    break;

                case SpfMechanism.IP4:
                case SpfMechanism.IP6:
                    var address = SpfAddress.Parse(value);
                    if (directive.Mechanism == SpfMechanism.IP4) directive.IP4 = address; else directive.IP6 = address;

                    break;

                case SpfMechanism.A:
                case SpfMechanism.MX:
                    directive.Domain = value;

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

        private IPAddress[] ResolveDirective(SpfDirective directive)
        {
            // If a mechanism lookup the addresses and return
            if (directive.Mechanism == SpfMechanism.A)
            {
                var ARecords = _resolver.GetAddressRecords(directive.Domain);
                if (ARecords.Length < 1)
                {
                    throw new SpfInvalidException(string.Format("A ({0}) does not resolve",directive.Domain));
                }
            }

            // Lookup all MX records and do a lookup on those
            var records = _resolver.GetMailRecords(directive.Domain);

            if (records.Length > 10)
            {
                throw new SpfException("MX mechanism exceeds max MX records of 10");
            }

            var addresses = new List<IPAddress>();
            foreach (var record in records)
            {
                addresses.AddRange(_resolver.GetAddressRecords(record));
            }

            return addresses.ToArray();
        }
    }
}
