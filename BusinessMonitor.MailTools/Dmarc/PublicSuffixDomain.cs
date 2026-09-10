namespace BusinessMonitor.MailTools.Dmarc
{
    /// <summary>
    /// The Public Suffix Domain flag of a DMARC record (psd, RFC 9989 section 4.7)
    /// </summary>
    public enum PublicSuffixDomain
    {
        /// <summary>
        /// Not specified, the standard discovery mechanism applies (u)
        /// </summary>
        Unknown,

        /// <summary>
        /// The domain is a Public Suffix Domain (y)
        /// </summary>
        Yes,

        /// <summary>
        /// The domain is not a Public Suffix Domain but is its own Organizational Domain (n)
        /// </summary>
        No
    }
}
