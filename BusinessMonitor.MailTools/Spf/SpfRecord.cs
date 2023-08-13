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
    }
}
