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
        /// <param name="domain">The domain</param>
        /// <returns>List of text records</returns>
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
