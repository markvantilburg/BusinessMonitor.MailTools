﻿using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;

namespace BusinessMonitor.MailTools.Dkim
{
    /// <summary>
    /// Parses, checks and lookups DKIM (DomainKeys Identified Mail) records on domain names
    /// </summary>
    public class DkimCheck
    {
        private IResolver _resolver;

        /// <summary>
        /// Initializes a new DKIM check instance with the provided DNS resolver
        /// </summary>
        /// <param name="resolver">The DNS resolver to use</param>
        public DkimCheck(IResolver resolver)
        {
            _resolver = resolver;
        }

        /// <summary>
        /// Gets a DKIM record from a domain
        /// </summary>
        /// <param name="domain">The domain of the sender</param>
        /// <param name="selector">The selector from the signature</param>
        public DkimRecord GetDkimRecord(string domain, string selector)
        {
            var name = selector + "._domainkey." + domain;
            var records = _resolver.GetTextRecords(name);

            // Find the DKIM record
            var record = records.FirstOrDefault(x => x.StartsWith("v=DKIM1"));

            if (record == default)
            {
                throw new InvalidDkimException("Domain does not contain a DKIM record for selector");
            }

            // Parse and validate the record and return it
            return ParseDkimRecord(record);
        }

        /// <summary>
        /// Parses and validates a DKIM record and return the record
        /// </summary>
        /// <param name="value">The record content</param>
        /// <returns>The parsed DKIM record</returns>
        public static DkimRecord ParseDkimRecord(string value)
        {
            // Check if the record starts with DKIM version 1
            if (!value.StartsWith("v=DKIM1"))
            {
                throw new InvalidDkimException("Not a valid DKIM record, does not contain a version");
            }

            // Split all tags
            var tags = value.Split(';').Skip(1);
            var record = new DkimRecord();

            foreach (var t in tags)
            {
                var i = t.IndexOf('=');
                var tag = t.Substring(0, i).Trim();
                var val = t.Substring(i + 1).Trim();

                // Process the tag
                switch (tag)
                {
                    // Acceptable hash algorithms
                    case "h":
                        record.Algorithms = val;
                        break;

                    // Key type
                    case "k":
                        record.KeyType = val;
                        break;

                    // Notes
                    case "n":
                        record.Notes = val;
                        break;

                    // Public key data
                    case "p":
                        ValidateBase64(val);
                        record.PublicKey = val;

                        break;

                    // Service Type
                    case "s":
                        record.ServiceType = val;
                        break;

                    // Flags
                    case "t":
                        record.Flags = val;
                        break;

                    default:
                        break;
                }
            }

            // Check for required tags, public key is allowed to be empty when key is revoked
            if (record.PublicKey == null)
            {
                throw new InvalidDkimException("DKIM record is missing a required public key");
            }

            // Return the record
            return record;
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
                throw new InvalidDkimException("DKIM record public key must contain valid base64");
            }
        }
    }
}
