using System.Net;

namespace BusinessMonitor.MailTools.Util
{
    internal static class IPAddressHelper
    {
        /// <summary>
        /// Is the ip address in the range
        /// </summary>
        /// <param name="address">The address to check</param>
        /// <param name="network">The network the address should be a part of</param>
        /// <param name="length">Total range of the network</param>
        /// <returns></returns>
        internal static bool IsInRange(IPAddress address, IPAddress network, int length)
        {
            if (address.AddressFamily != network.AddressFamily)
            {
                return false;
            }

            var addressBytes = address.GetAddressBytes();
            var networkBytes = network.GetAddressBytes();

            if (length < 0 || length > addressBytes.Length * 8)
            {
                return false;
            }

            // Compare the whole bytes of the prefix, the host bits are ignored so an
            // unaligned base like 192.168.0.1/24 behaves as 192.168.0.0/24
            var bytes = length / 8;

            for (var i = 0; i < bytes; i++)
            {
                if (addressBytes[i] != networkBytes[i])
                {
                    return false;
                }
            }

            // Compare the remaining bits of the prefix
            var bits = length % 8;

            if (bits == 0)
            {
                return true;
            }

            var mask = (byte)(0xFF << (8 - bits));

            return (addressBytes[bytes] & mask) == (networkBytes[bytes] & mask);
        }
    }
}
