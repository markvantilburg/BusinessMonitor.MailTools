using BusinessMonitor.MailTools.Dns;
using BusinessMonitor.MailTools.Exceptions;

namespace BusinessMonitor.MailTools.Dmarc
{
    /// <summary>
    /// Parses, checks and lookups DMARC (Domain-based Message Authentication, Reporting, and Conformance) records on domain names
    /// </summary>
    public class DmarcCheck
    {
        private readonly IResolver _resolver;

        /// <summary>
        /// Initializes a new DMARC check instance with the provided DNS resolver
        /// </summary>
        /// <param name="resolver">The DNS resolver to use</param>
        public DmarcCheck(IResolver resolver)
        {
            if (resolver == null)
            {
                throw new ArgumentNullException(nameof(resolver));
            }

            _resolver = resolver;
        }

        /// <summary>
        /// Gets a DMARC record from a domain
        /// </summary>
        /// <param name="domain">The domain of the sender</param>
        /// <returns>The parsed DMARC record</returns>
        /// <exception cref="DmarcNotFoundException">No DMARC record was found for the domain</exception>
        /// <exception cref="DmarcInvalidException">The DMARC record was invalid</exception>
        public DmarcRecord GetDmarcRecord(string domain)
        {
            if (domain == null)
            {
                throw new ArgumentNullException(nameof(domain));
            }

            if (domain.Length > 253)
            {
                throw new ArgumentException("Domain must not exceed 253 characters", nameof(domain));
            }

            var name = "_dmarc." + domain;
            var records = _resolver.GetTextRecords(name);

            // Find the DMARC record
            var record = records.FirstOrDefault(x => x.StartsWith("v=DMARC1"));

            if (record == default)
            {
                throw new DmarcNotFoundException("No DMARC record found on domain");
            }

            // Parse and validate the record and return it
            return ParseDmarcRecord(record);
        }

        /// <summary>
        /// Parses and validates a DMARC record and return the record
        /// </summary>
        /// <param name="value">The record content</param>
        /// <returns>The parsed DMARC record</returns>
        /// <exception cref="DmarcInvalidException">The DMARC record was invalid</exception>
        public static DmarcRecord ParseDmarcRecord(string value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            // Check if the record starts with DMARC version 1
            if (!value.StartsWith("v=DMARC1"))
            {
                throw new DmarcInvalidException("Not a valid DMARC record, does not contain a version");
            }

            // Split all tags
            var tags = value.Split(';').Skip(1);
            var record = new DmarcRecord();

            int i = 0;
            foreach (var t in tags)
            {
                i++;

                var pos = t.IndexOf('=');
                if (pos == -1) continue;

                var tag = t.Substring(0, pos).Trim();
                var val = t.Substring(pos + 1).Trim();

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

                    // Failure reporting options
                    case "fo":
                        record.FailureOptions = GetFailureOptions(val);

                        break;

                    // Mail Receiver policy
                    case "p":
                        // "p" tag must appear directly after version
                        if (i != 1)
                        {
                            throw new DmarcInvalidException("The policy tag must appear directly after the version tag");
                        }

                        record.Policy = GetReceiverPolicy(val);

                        break;

                    // Percentage tag
                    case "pct":
                        var percentage = int.Parse(val);

                        if (percentage < 0 || percentage > 100)
                        {
                            throw new DmarcInvalidException("Invalid percentage tag, must be between 0 and 100");
                        }

                        record.PercentageTag = percentage;

                        break;

                    // Report format
                    case "rf":
                        record.ReportFormat = val.Split(':');

                        break;

                    // Interval requested between aggregate reports
                    case "ri":
                        record.ReportInterval = uint.Parse(val);

                        break;

                    // Addresses to which aggregate feedback is to be sent
                    case "rua":
                        record.AggregatedReportAddresses = val.Split(',');

                        break;

                    // Addresses to which message-specific failure information is to be reported
                    case "ruf":
                        record.ForensicReportAddresses = val.Split(',');

                        break;

                    // Mail Receiver policy for all subdomains
                    case "sp":
                        record.SubdomainPolicy = GetReceiverPolicy(val);

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
                throw new DmarcInvalidException("Invalid alignment mode, must be relaxed or strict");
            }

            return value == "r" ? AlignmentMode.Relaxed : AlignmentMode.Strict;
        }

        private static FailureOptions GetFailureOptions(string value)
        {
            var characters = value.Split(':');
            var options = FailureOptions.None;

            foreach (var option in characters)
            {
                if (option == "0") options |= FailureOptions.All;
                if (option == "1") options |= FailureOptions.Any;
                if (option == "d") options |= FailureOptions.DkimFailure;
                if (option == "s") options |= FailureOptions.SpfFailure;
            }

            return options;
        }

        private static ReceiverPolicy GetReceiverPolicy(string value)
        {
            if (value != "none" && value != "quarantine" && value != "reject")
            {
                throw new DmarcInvalidException("Invalid receiver policy, must be none, quarantine or reject");
            }

            return (ReceiverPolicy)Enum.Parse(typeof(ReceiverPolicy), value, true);
        }
    }
}
