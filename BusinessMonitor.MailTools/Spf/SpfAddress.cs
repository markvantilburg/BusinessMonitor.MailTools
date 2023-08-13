using System.Net;

namespace BusinessMonitor.MailTools.Spf
{
    public record SpfAddress
    {
        internal SpfAddress(IPAddress address, int? length = null)
        {
            Address = address;
            Length = length;
        }

        internal static SpfAddress Parse(string value)
        {
            var pos = value.IndexOf('/');

            string ip = value;
            int? length = null;

            if (pos != -1)
            {
                ip = value.Substring(0, pos);
                length = int.Parse(value.Substring(pos + 1));
            }

            var address = IPAddress.Parse(ip);
            return new SpfAddress(address, length);
        }

        /// <summary>
        /// Gets the IP address
        /// </summary>
        public IPAddress Address { get; set; }

        /// <summary>
        /// Gets the CIDR prefix length
        /// </summary>
        public int? Length { get; set; }

        /// <summary>
        /// Checks whether the IP address is part of the network
        /// </summary>
        /// <param name="address">The IP address to check</param>
        /// <returns>Whether the IP address is part of the network</returns>
        public bool Contains(IPAddress address)
        {
            if (Length == null)
            {
                return Address == address;
            }

            throw new NotImplementedException();
        }

        public override string ToString()
        {
            return Address.ToString() + (Length != null ? "/" + Length : "");
        }
    }
}
