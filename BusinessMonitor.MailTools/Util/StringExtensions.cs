namespace BusinessMonitor.MailTools.Util
{
    internal static class StringExtensions
    {
        internal static string[] SplitTrim(this string value, char separator)
        {
            return SplitTrim(value, separator, StringSplitOptions.RemoveEmptyEntries);
        }

        internal static string[] SplitTrim(this string value, char separator, StringSplitOptions options)
        {
            return value.Split([separator], options).Select(x => x.Trim()).ToArray();
        }
    }
}
