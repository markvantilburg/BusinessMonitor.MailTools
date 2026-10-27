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
            ServiceType = new string[] { "*" }; // Absent s= tag defaults to all service types
            Flags = DkimFlags.None;
        }

        /// <summary>
        /// Gets the acceptable hash algorithms (h), as listed in the record, empty when absent which allows
        /// all algorithms. Unrecognized algorithms are kept so a record can be reported as it is published,
        /// verifiers ignore them (RFC 6376 section 3.6.1), a record always allows sha256
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

        /// <summary>
        /// Gets whether this DKIM key is revoked or disabled (empty public key)
        /// </summary>
        public bool IsRevoked { get; internal set; }

        /// <summary>
        /// Gets the public key size in bits, the RSA modulus size or 256 for ed25519 keys, 0 when the key is revoked
        /// </summary>
        public int KeySize { get; internal set; }

    }
}
