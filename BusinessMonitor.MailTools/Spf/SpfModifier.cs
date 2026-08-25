namespace BusinessMonitor.MailTools.Spf
{
    /// <summary>
    /// Represents a SPF modifier
    /// </summary>
    public record SpfModifier
    {
        internal SpfModifier(string name, string value)
        {
            Name = name;
            Value = value;
        }

        /// <summary>
        /// Gets the modifier name
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets the modifier value
        /// </summary>
        public string Value { get; set; }

        /// <summary>
        /// Gets the record a redirect modifier points to, this will be null if no lookup was done
        /// or when the redirect was ignored because the record contains an all mechanism
        /// </summary>
        public SpfRecord? Included { get; set; }
    }
}
