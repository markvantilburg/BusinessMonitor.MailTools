using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;

namespace BusinessMonitor.MailTools.Dmarc
{
    /// <summary>
    /// Parses, checks and lookups DMARC (Domain-based Message Authentication, Reporting, and Conformance) records on domain names
    /// </summary>
    public class DmarcCheck
    {
        private IResolver _resolver;

        /// <summary>
        /// Initializes a new DMARC check instance with the provided DNS resolver
        /// </summary>
        /// <param name="resolver">The DNS resolver to use</param>
        public DmarcCheck(IResolver resolver)
        {
            _resolver = resolver;
        }

        /// <summary>
        /// Gets a DMARC record from a domain
        /// </summary>
        /// <param name="domain">The domain of the sender</param>
        public DmarcRecord GetDmarcRecord(string domain)
        {
            var name = "_dmarc." + domain;
            var records = _resolver.GetTextRecords(name);

            // Find the DMARC record
            var record = records.FirstOrDefault(x => x.StartsWith("v=DMARC1"));

            if (record == default)
            {
                throw new InvalidDmarcException("Domain does not contain a DMARC record");
            }

            // Parse and validate the record and return it
            return ParseDmarcRecord(record);
        }

        /// <summary>
        /// Parses and validates a DMARC record and return the record
        /// </summary>
        /// <param name="value">The record content</param>
        /// <returns>The parsed DMARC record</returns>
        public static DmarcRecord ParseDmarcRecord(string value)
        {
            // Check if the record starts with DMARC version 1
            if (!value.StartsWith("v=DMARC1"))
            {
                throw new InvalidDmarcException("Not a valid DMARC record, does not contain a version");
            }

            // Split all tags
            var tags = value.Split(';').Skip(1);
            var record = new DmarcRecord();

            foreach (var t in tags)
            {
                var i = t.IndexOf('=');
                var tag = t.Substring(0, i).Trim();
                var val = t.Substring(i + 1).Trim();

                // Process the tag
                switch (tag)
                {
                    // DKIM Identifier Alignment mode
                    case "adkim":
                        record.DkimMode = GetAlignmentMode(val);

                        break;

                    // SPF Identifier Alignment mode
                    case "aspf":
                        record.SpfMode = GetAlignmentMode(val);

                        break;

                    case "fo":
                        break;

                    case "p":
                        break;

                    case "pct":
                        break;

                    case "rf":
                        break;

                    case "ri":
                        break;

                    case "rua":
                        break;

                    case "ruf":
                        break;

                    case "sp":
                        break;
                }
            }

            // Return the record
            return record;
        }

        private static AlignmentMode GetAlignmentMode(string value)
        {
            if (value != "r" && value != "s")
            {
                throw new InvalidDmarcException("Invalid alignment mode, must be relaxed or strict");
            }

            return value == "r" ? AlignmentMode.Relaxed : AlignmentMode.Strict;
        }
    }
}
