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
    }
}
