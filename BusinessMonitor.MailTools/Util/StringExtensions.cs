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

        /// <summary>
        /// The maximum length of an untrusted value quoted in an exception message
        /// </summary>
        internal const int MaxMessageValueLength = 64;

        /// <summary>
        /// Makes an untrusted value, such as DNS record content, safe to quote in an exception message.
        /// Characters outside visible ASCII are replaced by '?' so the message cannot carry control
        /// characters or look-alike characters into logs, and the value is truncated so a record
        /// cannot flood a message.
        /// The result is not HTML encoded, consumers must still encode messages before rendering them.
        /// </summary>
        internal static string Sanitize(this string value)
        {
            if (value == null)
            {
                return string.Empty;
            }

            var length = Math.Min(value.Length, MaxMessageValueLength);
            var chars = new char[length];

            for (var i = 0; i < length; i++)
            {
                var c = value[i];

                chars[i] = c >= 0x20 && c <= 0x7E ? c : '?';
            }

            var result = new string(chars);

            return value.Length > MaxMessageValueLength ? result + "..." : result;
        }
    }
}
