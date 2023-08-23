using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace BusinessMonitor.MailTools.Util
{
    internal static class IPAddressHelper
    {
        internal static bool IsInRange(IPAddress address, IPAddress network, int length)
        {
            var mask = GetMask(address.AddressFamily, out var bytes);
            var start = ToBigInteger(network.GetAddressBytes());
            var end = start + ~(mask << (bytes * 8 - length));

            var addressBytes = ToBigInteger(address.GetAddressBytes());

            return IsInRange(addressBytes, start, end);
        }

        private static bool IsInRange(BigInteger address, BigInteger start, BigInteger end)
        {
            return address >= start && address <= end;
        }

        private static BigInteger GetMask(AddressFamily family, out int length)
        {
            length = family == AddressFamily.InterNetwork ? 4 : 16;

#if NET6_0_OR_GREATER
            Span<byte> bytes = stackalloc byte[length];
#else
            var bytes = new byte[length];
#endif

            for (int i = 0; i < length; i++)
            {
                bytes[i] = 0xff;
            }

            return new BigInteger(bytes);
        }

        private static BigInteger ToBigInteger(byte[] data)
        {
#if NET6_0_OR_GREATER
            return new BigInteger(data, true, true);
#else
            // Make big endian and unsigned by adding a trailing 0 byte
            Array.Reverse(data);
            data = data.Concat(new byte[] { 0x00 }).ToArray();

            return new BigInteger(data);
#endif
        }
    }
}
