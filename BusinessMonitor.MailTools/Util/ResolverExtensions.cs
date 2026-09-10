namespace BusinessMonitor.MailTools.Util
{
    /// <summary>
    /// Normalizes the results of an <see cref="Dns.IResolver"/>
    /// </summary>
    internal static class ResolverExtensions
    {
        /// <summary>
        /// Returns the results without null entries, a null array is treated as no results.
        /// The <see cref="Dns.IResolver"/> contract asks for arrays without nulls, this guards
        /// against implementations that return them anyway.
        /// </summary>
        internal static T[] WithoutNulls<T>(this T[] results) where T : class
        {
            if (results == null)
            {
                return Array.Empty<T>();
            }

            foreach (var result in results)
            {
                if (result == null)
                {
                    return results.Where(x => x != null).ToArray();
                }
            }

            return results;
        }
    }
}
