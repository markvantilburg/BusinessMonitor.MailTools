using System.Net;

namespace BusinessMonitor.MailTools.Dns
{
    /// <summary>
    /// To be implemented by DNS resolvers
    /// </summary>
    /// <remarks>
    /// An empty array means the name has no records of the requested type or does not exist (NODATA,
    /// NXDOMAIN). A transient failure (SERVFAIL, timeout, network error) must be reported by throwing, not
    /// by returning an empty array, the checks would otherwise treat the failure as a definitive answer,
    /// for example by falling back to the implicit MX of a domain whose MX lookup failed.
    /// Aliases (CNAME) are expected to be followed by the resolver, the checks only see the final records
    /// and cannot detect an MX exchange that points to an alias (RFC 2181 section 10.3).
    /// Arrays must not contain null entries, a null array is tolerated and treated as empty.
    /// </remarks>
    public interface IResolver
    {
        /// <summary>
        /// Gets all text (TXT) records from a domain
        /// </summary>
        /// <remarks>
        /// Implementations must return exactly one string per TXT record. A single TXT record may consist of
        /// multiple character-strings of at most 255 bytes each, these must be concatenated in order without
        /// separators into one string, as required by RFC 7208 section 3.3 and RFC 6376 section 3.6.2.2.
        /// DKIM public keys routinely exceed 255 bytes, returning one string per character-string will break
        /// record parsing.
        /// </remarks>
        /// <param name="domain">The domain</param>
        /// <returns>List of text records, one string per record</returns>
        public string[] GetTextRecords(string domain);

        /// <summary>
        /// Gets all address (A and AAAA) records from a domain
        /// </summary>
        /// <remarks>
        /// Implementations should return both A and AAAA records. A resolver that returns A records only
        /// makes an IPv6-only host appear to have no addresses, which the SPF a and mx mechanisms never
        /// match and which <see cref="Mx.MxValidator.MxValidationResult.CanReceiveMail"/> treats as unable
        /// to receive mail.
        /// </remarks>
        /// <param name="domain">The domain</param>
        /// <returns>List of address records</returns>
        public IPAddress[] GetAddressRecords(string domain);

        /// <summary>
        /// Gets all mail exchange (MX) records from a domain
        /// </summary>
        /// <remarks>
        /// Implementations must return the exchange host name only, without the preference. A null MX
        /// (RFC 7505) is returned as "." or an empty string.
        /// </remarks>
        /// <param name="domain">The domain</param>
        /// <returns>List of mail exchange records, one exchange host name per record</returns>
        public string[] GetMailRecords(string domain);
    }
}
