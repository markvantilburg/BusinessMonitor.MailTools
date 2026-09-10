using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Util;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace BusinessMonitor.MailTools.Spf
{
    public record SpfAddress
    {
        internal SpfAddress(IPAddress address, int? length = null)
        {
            Address = address;
            Length = length;
        }

        internal static SpfAddress Parse(string value, AddressFamily expectedFamily)
        {
            var pos = value.IndexOf('/');

            string ip = value;
            int? length = null;

            if (pos != -1)
            {
                ip = value.Substring(0, pos);
                var prefix = value.Substring(pos + 1);

                // Leading zeros are not allowed (RFC 7208 section 12)
                if (prefix.Length > 1 && prefix[0] == '0')
                {
                    throw new SpfInvalidException($"Invalid CIDR prefix length '{prefix.Sanitize()}' in '{value.Sanitize()}', must not contain leading zeros");
                }

                if (!int.TryParse(prefix, NumberStyles.None, CultureInfo.InvariantCulture, out var parsedLength))
                {
                    throw new SpfInvalidException($"Invalid CIDR prefix length '{prefix.Sanitize()}' in '{value.Sanitize()}'");
                }

                length = parsedLength;
            }

            // Reject IPv6 zone identifiers such as fe80::1%eth0 which .NET accepts
            // but are not part of the SPF grammar (RFC 7208 section 12)
            if (ip.IndexOf('%') != -1)
            {
                throw new SpfInvalidException($"Invalid IP address '{ip.Sanitize()}' in '{value.Sanitize()}'");
            }

            IPAddress address;
            try
            {
                address = IPAddress.Parse(ip);
            }
            catch (FormatException)
            {
                throw new SpfInvalidException($"Invalid IP address '{ip.Sanitize()}' in '{value.Sanitize()}'");
            }

            if (address.AddressFamily != expectedFamily)
            {
                var mechanism = expectedFamily == AddressFamily.InterNetwork ? "ip4" : "ip6";

                throw new SpfInvalidException($"Address '{ip.Sanitize()}' does not match the {mechanism} mechanism in '{value.Sanitize()}'");
            }

            // Reject legacy shorthand such as "1.2.3" which .NET parses as 1.2.0.3, an SPF ip4 must be a full dotted quad
            if (expectedFamily == AddressFamily.InterNetwork)
            {
                var parts = ip.Split('.');

                if (parts.Length != 4)
                {
                    throw new SpfInvalidException($"IPv4 address must be a full dotted quad, got '{ip.Sanitize()}' in '{value.Sanitize()}'");
                }

                // Octets must be plain decimal numbers without leading zeros (RFC 7208
                // section 12), this also rejects the hex and octal forms .NET accepts
                // such as 0x7F.0.0.1 and 015.1.1.1 which all start with a zero
                foreach (var part in parts)
                {
                    if (part.Length > 1 && part[0] == '0')
                    {
                        throw new SpfInvalidException($"Invalid IPv4 octet '{part.Sanitize()}' in '{value.Sanitize()}'");
                    }
                }
            }

            if (length != null)
            {
                var maxLength = expectedFamily == AddressFamily.InterNetwork ? 32 : 128;

                if (length < 0 || length > maxLength)
                {
                    throw new SpfInvalidException($"CIDR prefix length must be between 0 and {maxLength}, got '{length}' in '{value.Sanitize()}'");
                }
            }

            return new SpfAddress(address, length);
        }

        /// <summary>
        /// Gets the IP address
        /// </summary>
        public IPAddress Address { get; set; }

        /// <summary>
        /// Gets the CIDR prefix length, null when the mechanism has none which means a single address
        /// </summary>
        public int? Length { get; set; }

        /// <summary>
        /// Gets the prefix length that applies, a mechanism without one covers the single address
        /// so it equals the full length of 32 or 128 (RFC 7208 section 5.6)
        /// </summary>
        private int EffectiveLength => Length ?? (Address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);

        /// <summary>
        /// Two addresses are equal when they cover the same network, ip4:192.0.2.1 and ip4:192.0.2.1/32
        /// are the same mechanism
        /// </summary>
        public virtual bool Equals(SpfAddress? other)
        {
            return other is not null && Address.Equals(other.Address) && EffectiveLength == other.EffectiveLength;
        }

        public override int GetHashCode()
        {
            return Address.GetHashCode() * 397 ^ EffectiveLength;
        }

        /// <summary>
        /// Checks whether the IP address is part of the network
        /// </summary>
        /// <param name="address">The IP address to check</param>
        /// <returns>Whether the IP address is part of the network</returns>
        public bool Contains(IPAddress address)
        {
            if (Length == null)
            {
                return Address.Equals(address);
            }

            return IPAddressHelper.IsInRange(address, Address, Length.Value);
        }

        public override string ToString()
        {
            return Address + (Length != null ? "/" + Length : "");
        }
    }
}
