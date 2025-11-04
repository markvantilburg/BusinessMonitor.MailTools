namespace BusinessMonitor.MailTools.Util
{
    internal static class StringExtensions
    {
        internal static string[] SplitTrim(this string value, char separator)
        {
            return value.Split([separator], StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).ToArray();
        }
    }
}
