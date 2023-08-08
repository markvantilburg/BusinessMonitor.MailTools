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
        }

        /// <summary>
        /// Gets the DKIM Identifier Alignment mode
        /// </summary>
        public AlignmentMode DkimMode {  get; internal set; }

        /// <summary>
        /// Gets the SPF Identifier Alignment mode
        /// </summary>
        public AlignmentMode SpfMode { get; internal set; } 
    }
}
