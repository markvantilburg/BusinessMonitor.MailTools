using System.Net;

namespace BusinessMonitor.MailTools.Dns
{
    /// <summary>
    /// To be implemented by DNS resolvers
    /// </summary>
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
        /// <param name="domain">The domain</param>
        /// <returns>List of address records</returns>
        public IPAddress[] GetAddressRecords(string domain);

        /// <summary>
        /// Gets all mail exchange (MX) records from a domain
        /// </summary>
        /// <param name="domain">The domain</param>
        /// <returns>List of mail exchange records</returns>
        public string[] GetMailRecords(string domain);
    }
}
