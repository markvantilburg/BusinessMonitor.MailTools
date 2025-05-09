using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace ConsoleApp2
{
    public enum DnsRecordType : ushort
    {
        A = 1,       // Address record (IPv4 address)
        NS = 2,      // Name server
        CNAME = 5,   // Canonical name
        SOA = 6,     // Start of authority
        PTR = 12,    // Pointer record
        MX = 15,     // Mail exchange
        TXT = 16,    // Text record
        AAAA = 28,   // IPv6 address
        SRV = 33,    // Service location
        OPT = 41,    // EDNS (Extension mechanisms for DNS)
        ANY = 255    // Any type of record
    }

    public class DoHResolverDNS
    {
        private string DoHEndpoint;
        private static readonly List<string> DefaultDoHEndpoints = new List<string>
        {
            "https://cloudflare-dns.com/dns-query",
            "https://dns.google/dns-query",
            "https://dns.quad9.net/dns-query",
            "https://doh.opendns.com/dns-query",
        };

        /// <summary>
        /// Initializes a new DNS resolver with a random DoH endpoint from the default list.
        /// </summary>
        public DoHResolverDNS()
        {
            var random = new Random();
            DoHEndpoint = DefaultDoHEndpoints[random.Next(DefaultDoHEndpoints.Count)];
        }

        /// <summary>
        /// Initializes a new DNS resolver for a specified DoH endpoint.
        /// </summary>
        /// <param name="DoHEndPoint">The DoH endpoint URL</param>
        public DoHResolverDNS(Uri DoHEndPoint)
        {
            DoHEndpoint = DoHEndPoint.ToString();
        }

        /// <summary>
        /// Initializes a new DNS resolver for a specific IP address.
        /// </summary>
        /// <param name="address">The IP address of the DNS server.</param>
        [System.Obsolete("This constructor is obsolete. Use the parameterless constructor or the one that accepts a DoH endpoint.")]
        public DoHResolverDNS(IPAddress address = null)
        {
            if (address != null)
            {
                if (address.Equals(IPAddress.Parse("1.1.1.1")) || address.Equals(IPAddress.Parse("1.0.0.1")))
                {
                    DoHEndpoint = "https://cloudflare-dns.com/dns-query";
                }
                else if (address.Equals(IPAddress.Parse("8.8.8.8")) || address.Equals(IPAddress.Parse("8.8.4.4")))
                {
                    DoHEndpoint = "https://dns.google/dns-query";
                }
                else
                {
                    var random = new Random();
                    DoHEndpoint = DefaultDoHEndpoints[random.Next(DefaultDoHEndpoints.Count)];
                }
            }
            else
            {
                var random = new Random();
                DoHEndpoint = DefaultDoHEndpoints[random.Next(DefaultDoHEndpoints.Count)];
            }
        }

        public async Task<string[]> GetTextRecordsAsync(string domain)
        {
            var response = await QueryDnsAsync(domain, (ushort)DnsRecordType.TXT);
            return response ?? Array.Empty<string>();
        }

        public async Task<IPAddress[]> GetAddressRecordsAsync(string domain)
        {
            var response = await QueryDnsAsync(domain, (ushort)DnsRecordType.A);

            List<IPAddress> _ip = new List<IPAddress>();
            foreach (string x in response)
            {
                _ip.Add(IPAddress.Parse(x));
            }

            return _ip.ToArray();
        }

        public async Task<IPAddress[]> GetAAAddressRecordsAsync(string domain)
        {
            var response = await QueryDnsAsync(domain, (ushort)DnsRecordType.AAAA);

            List<IPAddress> _ip = new List<IPAddress>();
            foreach (string x in response)
            {
                _ip.Add(IPAddress.Parse(x));
            }

            return _ip.ToArray();
        }

        public async Task<string[]> GetMailRecordsAsync(string domain)
        {
            var response = await QueryDnsAsync(domain, (ushort)DnsRecordType.MX);
            return response ?? Array.Empty<string>();
        }

        private async Task<String[]> QueryDnsAsync(string domain, ushort queryType)
        {
            var dnsQuery = DnsMessageBuilder.BuildQuery(domain, queryType);

            using var httpClient = new HttpClient();
            var content = new ByteArrayContent(dnsQuery);
            content.Headers.Add("Content-Type", "application/dns-message");

            var response = await httpClient.PostAsync(DoHEndpoint, content);
            response.EnsureSuccessStatusCode();

            var responseBytes = await response.Content.ReadAsByteArrayAsync();
            return DnsMessageParser.ParseResponse(responseBytes);
        }

        // Helper classes for building and parsing DNS messages
        private static class DnsMessageBuilder
        {
            public static byte[] BuildQuery(string domain, ushort queryType)
            {
                var random = new Random();
                var transactionId = (ushort)random.Next(0, ushort.MaxValue);

                var header = new byte[12];
                header[0] = (byte)(transactionId >> 8);
                header[1] = (byte)(transactionId & 0xFF);
                header[2] = 0x01; // Recursion Desired (RD) flag
                header[5] = 0x01; // QDCOUNT = 1

                var question = BuildQuestion(domain, queryType);

                return header.Concat(question).ToArray();
            }

            private static byte[] BuildQuestion(string domain, ushort queryType)
            {
                var question = new List<byte>();

                foreach (var label in domain.Split('.'))
                {
                    question.Add((byte)label.Length);
                    question.AddRange(Encoding.UTF8.GetBytes(label));
                }

                question.Add(0); // End of domain name
                question.Add((byte)(queryType >> 8));
                question.Add((byte)(queryType & 0xFF)); // QTYPE
                question.Add(0x00);
                question.Add(0x01); // QCLASS = IN (Internet)

                return question.ToArray();
            }
        }

        private static class DnsMessageParser
        {
            public static string[] ParseResponse(byte[] responseBytes)
            {
                // Ensure the response is large enough to contain a DNS header (12 bytes)
                if (responseBytes.Length < 12)
                {
                    throw new ArgumentException("Invalid DNS response: Header is too short.");
                }

                // Skip the DNS header (first 12 bytes)
                int currentIndex = 12;

                // Skip the Question section (variable length)
                while (responseBytes[currentIndex] != 0)
                {
                    currentIndex++; // Skip the question name
                }
                currentIndex += 5; // Skip the null byte, QTYPE (2 bytes), and QCLASS (2 bytes)

                // Parse the Answer section
                var answers = new List<string>();

                while (currentIndex < responseBytes.Length)
                {
                    // Skip the name (compressed, starts with 0xC0 followed by pointer)
                    if ((responseBytes[currentIndex] & 0xC0) == 0xC0)
                    {
                        currentIndex += 2; // Compressed name pointer is 2 bytes
                    }
                    else
                    {
                        throw new ArgumentException("Invalid DNS response: Unexpected name format.");
                    }

                    // Read the TYPE (2 bytes)
                    ushort type = (ushort)((responseBytes[currentIndex] << 8) | responseBytes[currentIndex + 1]);
                    currentIndex += 2;

                    // Skip the CLASS (2 bytes) and TTL (4 bytes)
                    currentIndex += 6;

                    // Read the RDLENGTH (2 bytes)
                    ushort rdLength = (ushort)((responseBytes[currentIndex] << 8) | responseBytes[currentIndex + 1]);
                    currentIndex += 2;

                    // Read the RDATA (variable length)
                    string rdata = ParseRData(responseBytes, currentIndex, rdLength, type);
                    answers.Add(rdata);

                    // Move to the next record
                    currentIndex += rdLength;
                }

                return answers.ToArray();
            }

            private static string ParseRData(byte[] responseBytes, int startIndex, int length, ushort type)
            {
                switch (type)
                {
                    case (ushort)DnsRecordType.A: // A (IPv4 address)
                        return string.Join(".", responseBytes.Skip(startIndex).Take(length));

                    case (ushort)DnsRecordType.TXT: // TXT
                        return Encoding.UTF8.GetString(responseBytes, startIndex + 1, length - 1);

                    case (ushort)DnsRecordType.MX: // MX
                        ushort preference = (ushort)((responseBytes[startIndex] << 8) | responseBytes[startIndex + 1]);
                        string exchange = Encoding.UTF8.GetString(responseBytes, startIndex + 2, length - 2);
                        return $"{preference} {exchange}";

                    case (ushort)DnsRecordType.AAAA: // AAAA (IPv6 address)
                        // Parse 16 bytes for IPv6 and format into colon-separated hexadecimal
                        return string.Join(":",
                            Enumerable.Range(0, length / 2)
                                .Select(i => $"{responseBytes[startIndex + i * 2]:X2}{responseBytes[startIndex + i * 2 + 1]:X2}")
                                .Select(part => part.TrimStart('0')) // Optionally remove leading zeros for each segment
                        );


                    default:
                        // Return raw hex for unsupported types
                        return BitConverter.ToString(responseBytes, startIndex, length).Replace("-", "");
                }
            }
        }

        public class DnsResponse
        {
            public AnswerRecord[] Answer { get; set; }
        }

        public class AnswerRecord
        {
            public ushort Type { get; set; }
            public string Data { get; set; }
        }
    }
}
