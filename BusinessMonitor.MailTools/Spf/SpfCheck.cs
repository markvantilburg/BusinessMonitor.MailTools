using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Util;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace BusinessMonitor.MailTools.Spf
{
    /// <summary>
    /// Parses, checks and lookups SPF (Sender Policy Framework) records on domain names.
    /// Instances hold no per-call state and can be shared between threads.
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

        /// <summary>
        /// Counts the DNS lookups of a single evaluation toward the limit of 10 (RFC 7208 section 4.6.4).
        /// Kept per call rather than per instance so concurrent evaluations on a shared instance
        /// cannot reset or inflate each other's count.
        /// </summary>
        private sealed class LookupCounter
        {
            public int Count { get; private set; }

            public void Add()
            {
                Count++;

                if (Count > MaxLookups)
                {
                    throw new SpfLookupException("SPF record exceeds max lookups of 10");
                }
            }
        }

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
        }

        /// <summary>
        /// Gets a SPF record from a domain
        /// </summary>
        /// <param name="domain">The domain</param>
        /// <returns>The parsed SPF record</returns>
        /// <exception cref="SpfNotFoundException">No SPF record was found for the domain</exception>
        /// <exception cref="SpfInvalidException">The SPF record was invalid</exception>
        /// <exception cref="SpfLookupException">An include lookup failed, see inner exception</exception>
        /// <exception cref="ArgumentException">The domain is not a valid DNS name</exception>
        public SpfRecord GetSpfRecord(string domain)
        {
            domain = DnsName.ValidateDomain(domain, nameof(domain));

            return GetRecord(domain, new LookupCounter());
        }

        private SpfRecord GetRecord(string domain, LookupCounter counter)
        {
            var start = counter.Count;
            var records = _resolver.GetTextRecords(domain).WithoutNulls();

            // Find the SPF record
            var record = records.FirstOrDefault(IsSpfRecord);

            if (record == default)
            {
                throw new SpfNotFoundException("No SPF record found on domain");
            }

            if (records.Count(IsSpfRecord) > 1)
            {
                throw new SpfInvalidException("Too many SPF records found on domain");
            }

            // Parse and validate the record and return it
            var parsed = ParseSpfRecord(record);

            foreach (var directive in parsed.Directives)
            {
                if (directive.Mechanism == SpfMechanism.Include && directive.Include != null)
                {
                    counter.Add();

                    // A domain with macros can only be resolved during evaluation
                    if (directive.Include.IndexOf('%') == -1)
                    {
                        try
                        {
                            var included = GetRecord(directive.Include, counter);

                            directive.Included = included;
                        }
                        catch (SpfException ex) when (ex is not SpfLookupException)
                        {
                            throw new SpfLookupException($"SPF include lookup failed for '{directive.Include}', see inner exception", ex);
                        }
                    }
                }

                if (directive.Mechanism == SpfMechanism.A || directive.Mechanism == SpfMechanism.MX)
                {
                    counter.Add();

                    if (string.IsNullOrEmpty(directive.Domain))
                    {
                        directive.Domain = domain;
                    }

                    // A domain with macros can only be resolved during evaluation
                    if (directive.Domain.IndexOf('%') == -1)
                    {
                        directive.Addresses = ResolveDirective(directive);
                    }
                }

                // The ptr and exists mechanisms require a DNS lookup during evaluation
                // and count toward the lookup limit (RFC 7208 section 4.6.4)
                if (directive.Mechanism == SpfMechanism.Ptr || directive.Mechanism == SpfMechanism.Exists)
                {
                    counter.Add();
                }
            }

            // Process a redirect modifier, it is ignored when the record contains
            // an all mechanism (RFC 7208 section 6.1)
            var redirect = parsed.Modifiers.FirstOrDefault(x => x.Name.Equals("redirect", StringComparison.OrdinalIgnoreCase));

            if (redirect != null && !parsed.Directives.Any(x => x.Mechanism == SpfMechanism.All))
            {
                counter.Add();

                // A domain with macros can only be resolved during evaluation
                if (redirect.Value.IndexOf('%') == -1)
                {
                    try
                    {
                        redirect.Included = GetRecord(redirect.Value, counter);
                    }
                    catch (SpfException ex) when (ex is not SpfLookupException)
                    {
                        throw new SpfLookupException($"SPF redirect lookup failed for '{redirect.Value}', see inner exception", ex);
                    }
                }
            }

            parsed.Lookups = counter.Count - start;

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
            // HashSet to track seen IP addresses
            HashSet<SpfAddress> seenIpAddresses = new HashSet<SpfAddress>();

            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            // Check if the record starts with SPF version 1, the version must be the
            // complete first term of the record (RFC 7208 section 4.5)
            if (!IsSpfRecord(value))
            {
                throw new SpfInvalidException("Not a valid SPF record, does not start with a v=spf1 version");
            }

            // Split the terms
            var split = value.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).Skip(1);

            var directives = new List<SpfDirective>();
            var modifiers = new List<SpfModifier>();

            foreach (var term in split)
            {
                var index = term.IndexOf('=');

                // Check if term is a modifier, the name must be a letter followed by
                // letters, digits, hyphens, underscores or dots (RFC 7208 section 4.6.1),
                // an equals sign may also appear in a mechanism macro
                if (index != -1 && IsModifierName(term.Substring(0, index)))
                {
                    var modifier = ParseModifier(term);

                    // The redirect and exp modifiers must appear at most once (RFC 7208
                    // section 6) and their values must be a domain name
                    if (modifier.Name.Equals("redirect", StringComparison.OrdinalIgnoreCase) ||
                        modifier.Name.Equals("exp", StringComparison.OrdinalIgnoreCase))
                    {
                        if (modifiers.Any(x => x.Name.Equals(modifier.Name, StringComparison.OrdinalIgnoreCase)))
                        {
                            throw new SpfInvalidException($"SPF record contains more than one {modifier.Name.ToLowerInvariant()} modifier");
                        }

                        modifier.Value = ValidateDomainSpec(modifier.Value, modifier.Name.ToLowerInvariant());
                    }

                    modifiers.Add(modifier);
                }
                else
                {
                    var directive = ParseDirective(term, seenIpAddresses);

                    directives.Add(directive);
                }
            }

            return new SpfRecord(directives, modifiers);
        }

        /// <summary>
        /// Checks whether a value is a valid modifier name, a letter followed by
        /// letters, digits, hyphens, underscores or dots (RFC 7208 section 4.6.1)
        /// </summary>
        private static bool IsModifierName(string value)
        {
            if (value.Length == 0 || !IsLetter(value[0]))
            {
                return false;
            }

            for (var i = 1; i < value.Length; i++)
            {
                var c = value[i];

                if (!IsLetter(c) && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.')
                {
                    return false;
                }
            }

            return true;
        }

        private static bool IsLetter(char c)
        {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        }

        /// <summary>
        /// Parses the domain and optional dual CIDR lengths of an a or mx mechanism,
        /// such as a, a/24, a//64, a:example.com/24//64 (RFC 7208 section 5.3)
        /// </summary>
        private static void ParseDomainCidr(SpfDirective directive, string value)
        {
            // The CIDR lengths are taken from the end of the value so a slash inside
            // a macro does not break the domain, such as a:%{d/-}.example.com/24

            // An IPv6 CIDR length is separated by a double slash, such as /24//64 or //64
            var end = TryTakeCidr(value, value.Length, "//", 128, out var length6);

            if (length6 != null)
            {
                directive.IP6Length = length6;
            }

            end = TryTakeCidr(value, end, "/", 32, out var length4);

            if (length4 != null)
            {
                directive.IP4Length = length4;
            }

            directive.Domain = value.Substring(0, end);
        }

        /// <summary>
        /// Takes a CIDR length such as /24 or //64 from the end of a value and
        /// returns the new end position, the length is null when there is none
        /// </summary>
        private static int TryTakeCidr(string value, int end, string separator, int max, out int? length)
        {
            length = null;

            // Scan the trailing digits
            var start = end;

            while (start > 0 && value[start - 1] >= '0' && value[start - 1] <= '9')
            {
                start--;
            }

            if (start == end || start < separator.Length)
            {
                return end;
            }

            // The digits must be preceded by the separator
            for (var i = 0; i < separator.Length; i++)
            {
                if (value[start - separator.Length + i] != separator[i])
                {
                    return end;
                }
            }

            // A single slash separator must not be the second slash of a double one
            if (separator.Length == 1 && start > 1 && value[start - 2] == '/')
            {
                return end;
            }

            length = ParseCidrLength(value.Substring(start, end - start), max, value);

            return start - separator.Length;
        }

        /// <summary>
        /// Parses a CIDR prefix length and validates it is within range
        /// </summary>
        private static int ParseCidrLength(string value, int max, string term)
        {
            // Leading zeros are not allowed (RFC 7208 section 12)
            if (value.Length > 1 && value[0] == '0')
            {
                throw new SpfInvalidException($"Invalid CIDR prefix length in '{term.Sanitize()}', must not contain leading zeros");
            }

            if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var length) || length > max)
            {
                throw new SpfInvalidException($"Invalid CIDR prefix length in '{term.Sanitize()}', must be between 0 and {max}");
            }

            return length;
        }

        /// <summary>
        /// Validates the domain of a mechanism or modifier, the value must be a valid
        /// DNS name with at least two labels or a valid macro string (RFC 7208 section 7)
        /// </summary>
        /// <returns>The domain without its trailing dot, a macro string is returned as is</returns>
        private static string ValidateDomainSpec(string value, string term)
        {
            // A domain with macros can only be expanded during evaluation
            if (value.IndexOf('%') != -1)
            {
                if (!IsValidMacroString(value))
                {
                    throw new SpfInvalidException($"The {term} value '{value.Sanitize()}' contains an invalid macro");
                }

                return value;
            }

            // A single trailing dot is allowed (RFC 7208 section 7.1)
            var name = value;

            if (name.Length > 1 && name[name.Length - 1] == '.')
            {
                name = name.Substring(0, name.Length - 1);
            }

            if (!DnsName.IsValidName(name) || name.IndexOf('.') == -1)
            {
                throw new SpfInvalidException($"The {term} value '{value.Sanitize()}' must be a domain name");
            }

            // The top label must not be all digits (RFC 7208 section 7.1)
            var top = name.Substring(name.LastIndexOf('.') + 1);

            if (top.All(x => x >= '0' && x <= '9'))
            {
                throw new SpfInvalidException($"The {term} value '{value.Sanitize()}' must not end in an all numeric top label");
            }

            // The trailing dot is removed so the name is passed to the resolver and exposed the same
            // way as every other name in the library
            return name;
        }

        /// <summary>
        /// Checks whether a value is a valid macro string (RFC 7208 section 7.1)
        /// </summary>
        private static bool IsValidMacroString(string value)
        {
            for (var i = 0; i < value.Length; i++)
            {
                var c = value[i];

                if (c == '%')
                {
                    if (i + 1 >= value.Length) return false;

                    var next = value[++i];

                    // %% is a literal percent, %_ is a space and %- is an url encoded space
                    if (next == '%' || next == '_' || next == '-') continue;
                    if (next != '{') return false;

                    var end = value.IndexOf('}', i);
                    if (end == -1) return false;

                    // A macro is a letter followed by optional digits, an optional
                    // reverse marker and optional delimiters, such as %{ir} or %{d2}
                    var inner = value.Substring(i + 1, end - i - 1);
                    if (inner.Length == 0) return false;

                    // The c, r and t letters are only valid in an exp text
                    if ("slodiphv".IndexOf(char.ToLowerInvariant(inner[0])) == -1) return false;

                    var j = 1;

                    while (j < inner.Length && inner[j] >= '0' && inner[j] <= '9') j++;
                    if (j < inner.Length && (inner[j] == 'r' || inner[j] == 'R')) j++;
                    while (j < inner.Length && ".-+,/_=".IndexOf(inner[j]) != -1) j++;

                    if (j != inner.Length) return false;

                    i = end;
                }
                else if (c < 0x21 || c > 0x7E)
                {
                    // Literals must be visible ASCII characters
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Checks whether a TXT record is a SPF record, the version must be exactly
        /// the first term of the record (RFC 7208 section 4.5)
        /// </summary>
        private static bool IsSpfRecord(string value)
        {
            return value.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)
                && (value.Length == 6 || value[6] == ' ');
        }

        /// <summary>
        /// Parses a SPF directive
        /// </summary>
        /// <param name="term">The term to parse</param>
        /// <returns>The parsed directive</returns>
        private static SpfDirective ParseDirective(string term, HashSet<SpfAddress> seenIpAddresses)
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

                if (value.Length == 0)
                {
                    throw new SpfInvalidException($"The {mechanism.Sanitize()} mechanism has an empty value");
                }
            }
            else
            {
                // A dual CIDR length may follow the a and mx mechanisms directly, such as a/24
                var slash = term.IndexOf('/');

                if (slash != -1)
                {
                    mechanism = term.Substring(0, slash);
                    value = term.Substring(slash);
                }
            }

            return ParseDirective(qualifier, mechanism, value, seenIpAddresses);
        }

        /// <summary>
        /// Parses a SPF directive
        /// </summary>
        /// <param name="qualifier">The qualifier</param>
        /// <param name="mechanism">The mechanism</param>
        /// <param name="value">The mechanism value</param>
        /// <returns>The parsed directive</returns>
        private static SpfDirective ParseDirective(string qualifier, string mechanism, string value, HashSet<SpfAddress> seenIpAddresses)
        {
            // Mechanism names are case insensitive (RFC 7208 section 4.6.1), the comparison must not
            // depend on the current culture, Turkish lower cases I to a dotless i which breaks the lookup
            if (!Mechanisms.Contains(mechanism.ToLowerInvariant()))
            {
                throw new SpfInvalidException($"Not a valid SPF record, '{mechanism.Sanitize()}' is not a valid mechanism");
            }

            // Convert the qualifier and mechanism to matching types
            var qual = (SpfQualifier)Array.IndexOf(Qualifiers, qualifier);
            var mech = (SpfMechanism)Enum.Parse(typeof(SpfMechanism), mechanism, true);

            var directive = new SpfDirective(qual, mech);

            // Process the mechanism
            switch (directive.Mechanism)
            {
                case SpfMechanism.Include:
                    directive.Include = ValidateDomainSpec(value, "include");

                    break;

                case SpfMechanism.IP4:
                    var address4 = SpfAddress.Parse(value, AddressFamily.InterNetwork);
                    // Check if the IP4 has already been seen
                    if (seenIpAddresses.Contains(address4))
                    {
                        throw new SpfInvalidException($"Duplicate IP4 mechanism detected: {address4}");
                    }

                    // Add the IP address to the list
                    seenIpAddresses.Add(address4);
                    directive.IP4 = address4;

                    break;

                case SpfMechanism.IP6:
                    var address6 = SpfAddress.Parse(value, AddressFamily.InterNetworkV6);
                    // Check if the IP6 has already been seen
                    if (seenIpAddresses.Contains(address6))
                    {
                        throw new SpfInvalidException($"Duplicate IP6 mechanism detected: {address6}");
                    }

                    // Add the IP address to the list
                    seenIpAddresses.Add(address6);
                    directive.IP6 = address6;

                    break;

                case SpfMechanism.A:
                case SpfMechanism.MX:
                    ParseDomainCidr(directive, value);

                    if (!string.IsNullOrEmpty(directive.Domain))
                    {
                        directive.Domain = ValidateDomainSpec(directive.Domain, mechanism.ToLowerInvariant());
                    }

                    break;

                case SpfMechanism.All:
                    // The all mechanism takes no value (RFC 7208 section 5.1)
                    if (value.Length > 0)
                    {
                        throw new SpfInvalidException("The all mechanism does not take a value");
                    }

                    break;

                case SpfMechanism.Exists:
                    // The exists mechanism requires a domain (RFC 7208 section 5.7)
                    if (value.Length == 0)
                    {
                        throw new SpfInvalidException("The exists mechanism requires a domain");
                    }

                    directive.Domain = ValidateDomainSpec(value, "exists");

                    break;

                case SpfMechanism.Ptr:
                    // The ptr mechanism takes an optional domain (RFC 7208 section 5.5)
                    if (value.Length > 0)
                    {
                        directive.Domain = ValidateDomainSpec(value, "ptr");
                    }

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
            var index = term.IndexOf('=');

            var name = term.Substring(0, index);
            var value = term.Substring(index + 1);

            return new SpfModifier(name, value);
        }

        private IPAddress[] ResolveDirective(SpfDirective directive)
        {
            // If a mechanism lookup the addresses and return, a domain without any
            // addresses is not an error, the mechanism simply never matches
            if (directive.Mechanism == SpfMechanism.A)
            {
                return _resolver.GetAddressRecords(directive.Domain).WithoutNulls();
            }

            // Lookup all MX records and do a lookup on those
            var records = _resolver.GetMailRecords(directive.Domain).WithoutNulls();

            if (records.Length > 10)
            {
                throw new SpfException("MX mechanism exceeds max MX records of 10");
            }

            var addresses = new List<IPAddress>();
            foreach (var record in records)
            {
                // A null MX (RFC 7505) has no host to resolve
                if (DnsName.IsNullMx(record))
                {
                    continue;
                }

                // The MX host comes from DNS and is only passed back to the resolver when it is a valid name
                if (!DnsName.TryNormalizeHost(record, out var host))
                {
                    throw new SpfException($"MX record of '{directive.Domain.Sanitize()}' contains an invalid host name '{record.Sanitize()}'");
                }

                addresses.AddRange(_resolver.GetAddressRecords(host).WithoutNulls());
            }

            return addresses.ToArray();
        }
    }
}
