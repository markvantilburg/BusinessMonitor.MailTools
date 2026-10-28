namespace BusinessMonitor.MailTools.Util
{
    /// <summary>
    /// Helpers for the tag-value record syntax of DKIM (RFC 6376 section 3.2) which DMARC and BIMI records
    /// follow as well, tags are separated by semicolons, a tag is a name and a value separated by an equals
    /// sign, whitespace around the name and value is allowed
    /// </summary>
    internal static class TagValue
    {
        /// <summary>
        /// Checks whether a value is a valid DKIM tag name, a letter followed by letters, digits or
        /// underscores (RFC 6376 section 3.2), used by DKIM and BIMI records
        /// </summary>
        internal static bool IsValidTagName(string value)
        {
            if (value.Length == 0 || !IsAsciiLetter(value[0]))
            {
                return false;
            }

            for (var i = 1; i < value.Length; i++)
            {
                var c = value[i];

                if (!IsAsciiLetter(c) && (c < '0' || c > '9') && c != '_')
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Checks whether a value is a valid DMARC tag name, one or more letters (RFC 9989 section 4.8)
        /// </summary>
        internal static bool IsValidAlphaTagName(string value)
        {
            if (value.Length == 0)
            {
                return false;
            }

            foreach (var c in value)
            {
                if (!IsAsciiLetter(c))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Gets the name and value of the first tag of a record, both trimmed, returns false when the
        /// first segment is not a tag=value pair
        /// </summary>
        internal static bool TryGetFirstTag(string record, out string name, out string value)
        {
            var end = record.IndexOf(';');
            var first = end == -1 ? record : record.Substring(0, end);

            return TryGetTag(first, out name, out value);
        }

        /// <summary>
        /// Gets the name and value of a tag=value segment, both trimmed, returns false when the segment
        /// contains no equals sign
        /// </summary>
        internal static bool TryGetTag(string segment, out string name, out string value)
        {
            var index = segment.IndexOf('=');

            if (index == -1)
            {
                name = string.Empty;
                value = string.Empty;

                return false;
            }

            name = segment.Substring(0, index).Trim();
            value = segment.Substring(index + 1).Trim();

            return true;
        }

        /// <summary>
        /// Checks whether the first tag of a record is a version tag (v) with exactly the given value,
        /// the comparison is case sensitive, whitespace around the equals sign is allowed
        /// </summary>
        internal static bool HasVersion(string record, string version)
        {
            return TryGetFirstTag(record, out var name, out var value)
                && name == "v"
                && string.Equals(value, version, StringComparison.Ordinal);
        }

        /// <summary>
        /// Checks whether a character is an ASCII letter, char.IsLetter is not used as it accepts any
        /// Unicode letter, char.IsAsciiLetter is not available on netstandard2.0
        /// </summary>
        internal static bool IsAsciiLetter(char c)
        {
#if NET7_0_OR_GREATER
            return char.IsAsciiLetter(c);
#else
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
#endif
        }
    }
}
