namespace BusinessMonitor.MailTools.Dkim
{
    /// <summary>
    /// Represents a DKIM record
    /// </summary>
    public record DkimRecord
    {
        internal DkimRecord()
        {
            Algorithms = new string[0];
            KeyType = "rsa";
            Notes = string.Empty;
            PublicKey = null;
            ServiceType = new string[0];
            Flags = DkimFlags.None;
        }

        /// <summary>
        /// Gets a list of acceptable hash algorithms
        /// </summary>
        public string[] Algorithms { get; internal set; }

        /// <summary>
        /// Gets the Key type
        /// </summary>
        public string KeyType { get; internal set; }

        /// <summary>
        /// Gets the record notes
        /// </summary>
        public string Notes { get; internal set; }

        /// <summary>
        /// Gets the public key data encoded in base64
        /// </summary>
        public string? PublicKey { get; internal set; }

        /// <summary>
        /// Gets a list of service types
        /// </summary>
        public string[] ServiceType { get; internal set; }

        /// <summary>
        /// Gets the record flags
        /// </summary>
        public DkimFlags Flags { get; internal set; }
    }
}
