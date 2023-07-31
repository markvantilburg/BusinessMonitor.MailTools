namespace BusinessMonitor.MailTools.Spf
{
    /// <summary>
    /// Represents a SPF record
    /// </summary>
    public record SpfRecord
    {
        internal SpfRecord(IReadOnlyList<SpfDirective> directives)
        {
            Directives = directives;
        }

        /// <summary>
        /// Gets all record directives
        /// </summary>
        public IReadOnlyList<SpfDirective> Directives { get; set; }
    }
}
