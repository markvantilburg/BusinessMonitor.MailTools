namespace BusinessMonitor.MailTools.Dmarc
{
    /// <summary>
    /// Represents a DMARC record (RFC 9989)
    /// </summary>
    public record DmarcRecord
    {
        internal DmarcRecord()
        {
            DkimMode = AlignmentMode.Relaxed;
            SpfMode = AlignmentMode.Relaxed;
            FailureOptions = FailureOptions.All;
            Policy = ReceiverPolicy.None;
            PolicySpecified = false;
            SubdomainPolicy = ReceiverPolicy.None;
            NonExistentSubdomainPolicy = ReceiverPolicy.None;
            TestMode = false;
            PublicSuffixDomain = PublicSuffixDomain.Unknown;
#pragma warning disable CS0618 // Obsolete members, still populated for receivers following RFC 7489
            PercentageTag = 100;
            ReportFormat = new string[] { "afrf" };
            ReportInterval = 86400;
#pragma warning restore CS0618
            AggregatedReportAddresses = new string[0];
            ForensicReportAddresses = new string[0];
        }

        /// <summary>
        /// Gets the DKIM Identifier Alignment mode (adkim), relaxed when absent
        /// </summary>
        public AlignmentMode DkimMode { get; internal set; }

        /// <summary>
        /// Gets the SPF Identifier Alignment mode (aspf), relaxed when absent
        /// </summary>
        public AlignmentMode SpfMode { get; internal set; }

        /// <summary>
        /// Gets the failure reporting options (fo), only applied when the record has a ruf tag,
        /// otherwise the default of reporting when all mechanisms fail
        /// </summary>
        public FailureOptions FailureOptions { get; internal set; }

        /// <summary>
        /// Gets the Domain Owner Assessment Policy (p), an absent tag is treated as none (RFC 9989 section 4.7)
        /// </summary>
        public ReceiverPolicy Policy { get; internal set; }

        /// <summary>
        /// Gets whether the record contains a p tag, when false the <see cref="Policy"/> is the implied none
        /// </summary>
        public bool PolicySpecified { get; internal set; }

        /// <summary>
        /// Gets the policy for subdomains (sp), inherits <see cref="Policy"/> when absent
        /// </summary>
        public ReceiverPolicy SubdomainPolicy { get; internal set; }

        /// <summary>
        /// Gets the policy for non-existent subdomains (np), inherits <see cref="SubdomainPolicy"/> when absent
        /// </summary>
        public ReceiverPolicy NonExistentSubdomainPolicy { get; internal set; }

        /// <summary>
        /// Gets whether the domain owner requests the policy not to be applied (t=y), false when absent
        /// </summary>
        public bool TestMode { get; internal set; }

        /// <summary>
        /// Gets the Public Suffix Domain flag (psd), unknown when absent
        /// </summary>
        public PublicSuffixDomain PublicSuffixDomain { get; internal set; }

        /// <summary>
        /// Gets the report addresses for aggregate feedback data (rua), without the obsolete size suffix
        /// </summary>
        public string[] AggregatedReportAddresses { get; internal set; }

        /// <summary>
        /// Gets the report addresses for message-specific failure information (ruf), without the obsolete size suffix
        /// </summary>
        public string[] ForensicReportAddresses { get; internal set; }

        /// <summary>
        /// Gets the percentage tag (pct), 100 when absent
        /// </summary>
        [Obsolete("The pct tag was removed in RFC 9989 and is ignored by receivers following it, use the t tag to test a policy")]
        public int PercentageTag { get; internal set; }

        /// <summary>
        /// Gets the requested report formats (rf), afrf when absent
        /// </summary>
        [Obsolete("The rf tag was removed in RFC 9989 and is ignored by receivers following it")]
        public string[] ReportFormat { get; internal set; }

        /// <summary>
        /// Gets the aggregate reporting interval (ri), 86400 when absent
        /// </summary>
        [Obsolete("The ri tag was removed in RFC 9989 and is ignored by receivers following it")]
        public uint ReportInterval { get; internal set; }
    }
}
