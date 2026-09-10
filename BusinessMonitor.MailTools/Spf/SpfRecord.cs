namespace BusinessMonitor.MailTools.Spf
{
    /// <summary>
    /// Represents a SPF record
    /// </summary>
    public record SpfRecord
    {
        internal SpfRecord(List<SpfDirective> directives, List<SpfModifier> modifiers)
        {
            Directives = directives;
            Modifiers = modifiers;
        }

        /// <summary>
        /// Gets all record directives
        /// </summary>
        public IReadOnlyList<SpfDirective> Directives { get; set; }

        /// <summary>
        /// Gets all record modifiers
        /// </summary>
        public IReadOnlyList<SpfModifier> Modifiers { get; set; }

        /// <summary>
        /// Gets the number of DNS lookups the record's terms count toward the limit of 10 (RFC 7208 section 4.6.4),
        /// including the lookups of included and redirected records. The record of a domain must stay
        /// at or below 10. Zero for a record that was parsed without lookups.
        /// </summary>
        public int Lookups { get; internal set; }
    }
}
