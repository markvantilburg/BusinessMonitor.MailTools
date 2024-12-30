using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;

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
        /// <exception cref="BimiInvalidException">The BIMI record was invalid</exception>
        public BimiRecord GetBimiRecord(string domain, string selector = "default")
        {
            if (domain == null)
            {
                throw new ArgumentNullException(nameof(domain));
            }

            if (selector == null)
            {
                throw new ArgumentNullException(nameof(selector));
            }

            if (domain.Length > 253)
            {
                throw new ArgumentException("Domain must not exceed 253 characters", nameof(domain));
            }

            var name = selector + "._bimi." + domain;
            var records = _resolver.GetTextRecords(name);

            // Find the BIMI record
            var record = records.FirstOrDefault(x => x.StartsWith("v=BIMI1"));

            if (record == default)
            {
                throw new BimiNotFoundException($"No BIMI record found for selector '{selector}' on domain");
            }

            // Parse and validate the record and return it
            return ParseBimiRecord(record);
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

            // Check if the record starts with BIMI version 1
            if (!value.StartsWith("v=BIMI1"))
            {
                throw new BimiInvalidException("Not a valid BIMI record, does not contain a version");
            }

            // Split all tags
            var tags = value.Split(';').Skip(1);
            var record = new BimiRecord();

            foreach (var t in tags)
            {
                var i = t.IndexOf('=');
                if (i == -1) continue;

                var tag = t.Substring(0, i).Trim();
                var val = t.Substring(i + 1).Trim();

                // Process the tag
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

                    // Avatar Preference
                    case "s":
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
        }

        private static AvatarPreference GetAvatarPreference(string value)
        {
            if (value != "personal" && value != "bimi")
            {
                throw new BimiInvalidException("Invalid avatar preference, must be personal or bimi");
            }

            return value == "personal" ? AvatarPreference.Personal : AvatarPreference.Bimi;
        }
    }
}
