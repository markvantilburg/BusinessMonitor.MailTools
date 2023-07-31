namespace BusinessMonitor.MailTools.Dns
{
    /// <summary>
    /// To be implemented by DNS resolvers
    /// </summary>
    public interface IResolver
    {
        /// <summary>
        /// Gets all Text (TXT) records from a domain
        /// </summary>
        /// <param name="domain">The domain</param>
        /// <returns>List of text records</returns>
        public string[] GetTextRecords(string domain);
    }
}
