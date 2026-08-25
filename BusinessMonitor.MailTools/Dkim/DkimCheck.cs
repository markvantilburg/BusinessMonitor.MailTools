using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Util;

namespace BusinessMonitor.MailTools.Dkim
{
    /// <summary>
    /// Parses, checks and lookups DKIM (DomainKeys Identified Mail) records on domain names
    /// </summary>
    public class DkimCheck
    {
        private readonly IResolver _resolver;

        /// <summary>
        /// Initializes a new DKIM check instance with the provided DNS resolver
        /// </summary>
        /// <param name="resolver">The DNS resolver to use</param>
        public DkimCheck(IResolver resolver)
        {
            if (resolver == null)
            {
                throw new ArgumentNullException(nameof(resolver));
            }

            _resolver = resolver;
        }

        /// <summary>
        /// Gets a DKIM record from a domain
        /// </summary>
        /// <param name="domain">The domain of the sender</param>
        /// <param name="selector">The selector from the signature</param>
        /// <returns>The parsed DKIM record</returns>
        /// <exception cref="DkimNotFoundException">No DKIM record was found for the domain and selector</exception>
        /// <exception cref="DkimInvalidException">The DKIM record was invalid</exception>
        public DkimRecord GetDkimRecord(string domain, string selector)
        {
            DnsName.ValidateDomain(domain, nameof(domain));
            DnsName.ValidateSelector(selector, nameof(selector));

            var name = selector + "._domainkey." + domain;

            if (name.Length > 253)
            {
                throw new ArgumentException("Selector and domain combined exceed the maximum DNS name length of 253 characters", nameof(selector));
            }

            var records = _resolver.GetTextRecords(name);

            // Find the DKIM record
            var dkimRecords = records.Where(LooksLikeDkimRecord).ToList();

            if (dkimRecords.Count == 0)
            {
                throw new DkimNotFoundException($"No DKIM record found for selector '{selector}' on domain");
            }

            if (dkimRecords.Count > 1)
            {
                throw new DkimInvalidException($"Multiple DKIM records found for selector '{selector}' on domain. RFC 6376 requires exactly one DKIM record per selector.");
            }

            // Parse and validate the record and return it
            return ParseDkimRecord(dkimRecords[0]);
        }

        /// <summary>
        /// Parses and validates a DKIM record and return the record
        /// </summary>
        /// <param name="value">The record content</param>
        /// <returns>The parsed DKIM record</returns>
        /// <exception cref="DkimInvalidException">The DKIM record was invalid</exception>
        public static DkimRecord ParseDkimRecord(string value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            // Split all tags
            var tags = value.Split(';');
            var record = new DkimRecord();

            var seen = new HashSet<string>(StringComparer.Ordinal);

            for (var index = 0; index < tags.Length; index++)
            {
                var t = tags[index];

                var i = t.IndexOf('=');
                if (i == -1)
                {
                    // A trailing semicolon is allowed, any other segment must be a tag=value pair
                    if (index == tags.Length - 1 && t.Trim().Length == 0)
                    {
                        continue;
                    }

                    throw new DkimInvalidException($"DKIM record contains a malformed tag '{t.Trim()}'");
                }

                var tag = t.Substring(0, i).Trim();
                var val = t.Substring(i + 1).Trim();

                if (!IsValidTagName(tag))
                {
                    throw new DkimInvalidException($"DKIM record contains an invalid tag name '{tag}'");
                }

                if (!seen.Add(tag))
                {
                    throw new DkimInvalidException($"DKIM record contains duplicate tag '{tag}'");
                }

                // Process the tag
                switch (tag)
                {
                    // Version, optional but must be the first tag and exactly DKIM1 when present
                    case "v":
                        if (index != 0)
                        {
                            throw new DkimInvalidException("DKIM record version tag must be the first tag");
                        }

                        if (val != "DKIM1")
                        {
                            throw new DkimInvalidException("DKIM record version must be DKIM1");
                        }

                        break;

                    // Acceptable hash algorithms
                    case "h":
                        // Whitespace around the colons is allowed, empty entries are
                        // kept so they fail the validation below
                        var algorithms = val.SplitTrim(':', StringSplitOptions.None);

                        foreach (var algorithm in algorithms)
                        {
                            if (algorithm != "sha1" && algorithm != "sha256")
                            {
                                throw new DkimInvalidException("DKIM record invalid hash algorithm only sha1 or sha256 supported");
                            }
                        }

                        record.Algorithms = algorithms;
                        break;

                    // Key type
                    case "k":
                        record.KeyType = val switch
                        {
                            null or "" => "rsa",
                            "ed25519" => "ed25519",
                            "rsa" => "rsa",
                            _ => throw new DkimInvalidException("DKIM record invalid key type only rsa or ed25519 supported")
                        };
                        break;

                    // Notes
                    case "n":
                        record.Notes = val;
                        break;

                    // Public key data
                    case "p":
                        if (string.IsNullOrWhiteSpace(val))
                        {
                            record.IsRevoked = true;
                            record.PublicKey = "";
                        }
                        else
                        {
                            ValidateBase64(val);
                            record.PublicKey = val;
                        }

                        break;

                    // Service Type
                    case "s":
                        var serviceTypes = val.SplitTrim(':');

                        // Unrecognized service types are ignored, but the record must apply to
                        // email or all service types
                        if (!serviceTypes.Any(x => x == "*" || x == "email"))
                        {
                            throw new DkimInvalidException("DKIM record service type must include email or *");
                        }

                        record.ServiceType = serviceTypes;

                        break;

                    // Flags
                    case "t":
                        var flags = val.SplitTrim(':');

                        foreach (var flag in flags)
                        {
                            if (flag == "y") record.Flags |= DkimFlags.Testing;
                            if (flag == "s") record.Flags |= DkimFlags.SameDomain;
                        }

                        break;
                }
            }

            // Check for required tags, public key is allowed to be empty when key is revoked
            if (record.PublicKey == null)
            {
                throw new DkimInvalidException("DKIM record is missing a required public key");
            }

            // An ed25519 key can only be used with sha256, a record that does not allow
            // sha256 can never verify a signature (RFC 8463)
            if (record.KeyType == "ed25519" && record.Algorithms.Length > 0 && !record.Algorithms.Contains("sha256"))
            {
                throw new DkimInvalidException("DKIM record with an ed25519 key must allow the sha256 hash algorithm");
            }

            // Validate the public key data against the key type
            if (!record.IsRevoked)
            {
                ValidatePublicKey(record);
            }

            // Return the record
            return record;
        }

        /// <summary>
        /// Checks whether a value is a valid tag name, a letter followed by
        /// letters, digits or underscores (RFC 6376 section 3.2)
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

        /// <summary>
        /// Validates the public key data against the key type and sets the key size
        /// </summary>
        private static void ValidatePublicKey(DkimRecord record)
        {
            var key = Convert.FromBase64String(record.PublicKey!);

            if (record.KeyType == "ed25519")
            {
                // An ed25519 public key is a raw 32 byte public key (RFC 8463)
                if (key.Length != 32)
                {
                    throw new DkimInvalidException("DKIM record ed25519 public key must be a raw 32 byte public key");
                }

                record.KeySize = 256;

                return;
            }

            // An RSA public key is a DER encoded SubjectPublicKeyInfo structure (RFC 6376)
            if (!DkimKeyReader.TryGetRsaModulusBits(key, out var bits))
            {
                throw new DkimInvalidException("DKIM record RSA public key is not a valid DER encoded RSA public key");
            }

            // RFC 8301 requires a minimum RSA key size of 1024 bits
            if (bits < 1024)
            {
                throw new DkimInvalidException($"DKIM record RSA public key of {bits} bits is below the minimum of 1024 bits");
            }

            record.KeySize = bits;
        }

        /// <summary>
        /// Checks whether a TXT record looks like a DKIM record, either by its version tag
        /// or, since the version tag is optional, by the presence of a public key tag
        /// </summary>
        private static bool LooksLikeDkimRecord(string value)
        {
            var tags = value.Split(';');

            // A record starting with a v tag is a DKIM record only when the version is DKIM1
            var first = tags[0];
            var index = first.IndexOf('=');

            if (index != -1 && first.Substring(0, index).Trim() == "v")
            {
                return first.Substring(index + 1).Trim() == "DKIM1";
            }

            // No version tag, look for a public key tag
            return tags.Any(t =>
            {
                var i = t.IndexOf('=');

                return i != -1 && t.Substring(0, i).Trim() == "p";
            });
        }

        private static void ValidateBase64(string value)
        {
            // Empty strings shouldn't throw
            if (string.IsNullOrEmpty(value))
            {
                return;
            }

            try
            {
                _ = Convert.FromBase64String(value);
            }
            catch (FormatException)
            {
                throw new DkimInvalidException("DKIM record public key must contain valid base64");
            }
        }
    }
}
