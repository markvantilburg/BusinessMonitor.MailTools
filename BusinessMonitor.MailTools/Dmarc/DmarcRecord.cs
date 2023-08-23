namespace BusinessMonitor.MailTools.Dmarc
{
    /// <summary>
    /// Represents a DMARC record
    /// </summary>
    public record DmarcRecord
    {
        internal DmarcRecord()
        {
            DkimMode = AlignmentMode.Relaxed;
            SpfMode = AlignmentMode.Relaxed;
            FailureOptions = FailureOptions.All;
            Policy = ReceiverPolicy.None;
            PercentageTag = 100;
            ReportFormat = new string[] { "afrf" };
            ReportInterval = 86400;
            AggregatedReportAddresses = new string[0];
            ForensicReportAddresses = new string[0];
        }

        /// <summary>
        /// Gets the DKIM Identifier Alignment mode
        /// </summary>
        public AlignmentMode DkimMode { get; internal set; }

        /// <summary>
        /// Gets the SPF Identifier Alignment mode
        /// </summary>
        public AlignmentMode SpfMode { get; internal set; }

        /// <summary>
        /// Gets the failure reporting options
        /// </summary>
        public FailureOptions FailureOptions { get; internal set; }

        /// <summary>
        /// Gets the mail receiver policy
        /// </summary>
        public ReceiverPolicy Policy { get; internal set; }

        /// <summary>
        /// Gets the percentage tag
        /// </summary>
        public int PercentageTag { get; internal set; }

        /// <summary>
        /// Gets the requested report formats
        /// </summary>
        public string[] ReportFormat { get; internal set; }

        /// <summary>
        /// Gets the aggregate reporting interval
        /// </summary>
        public uint ReportInterval { get; internal set; }

        /// <summary>
        /// Gets the report addresses for aggregate feedback data
        /// </summary>
        public string[] AggregatedReportAddresses { get; internal set; }

        /// <summary>
        /// Gets the report address for message-specific failure information
        /// </summary>
        public string[] ForensicReportAddresses { get; internal set; }

        /// <summary>
        /// Gets the mail receiver policy for all subdomains
        /// </summary>
        public ReceiverPolicy SubdomainPolicy { get; internal set; }
    }
}
