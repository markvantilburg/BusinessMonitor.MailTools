using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace BusinessMonitor.MailTools.Dns
{
    public class DoHResolver : IResolver
    {
        private string DoHEndpoint;

        /// <summary>
        /// Initializes a new DNS resolver
        /// </summary>
        /// <param name="address">The IP address of the DNS server, null will use the default</param>
        [System.Obsolete("Please use the call that includes the DoHEndPoint")]
        public DoHResolver(IPAddress address = null)
        {
            // We default to Cloudflare
            DoHEndpoint = "https://cloudflare-dns.com/dns-query";

            if (address != null)
            {
                if (address.Equals(IPAddress.Parse("1.1.1.1")) || address.Equals(IPAddress.Parse("1.0.0.1")))
                {
                    DoHEndpoint = "https://cloudflare-dns.com/dns-query";
                }
                else if (address.Equals(IPAddress.Parse("8.8.8.8")) || address.Equals(IPAddress.Parse("8.8.4.4")))
                {
                    DoHEndpoint = "https://dns.google/resolve";
                }
                else if (address.Equals(IPAddress.Parse("9.9.9.9")) || address.Equals(IPAddress.Parse("9.9.9.11")))
                {
                    DoHEndpoint = "https://dns.quad9.net:5053/dns-query";
                }
            }
        }

        /// <summary>
        /// Initializes a new DNS resolver for dns over https
        /// </summary>
        /// <param name="DoHEndPoint">The DoH json dns endpoint url</param>
        /// <example>
        /// https://dns.google/resolve
        /// https://dns.quad9.net:5053/dns-query
        /// https://cloudflare-dns.com/dns-query
        /// </example>
        public DoHResolver(Uri DoHEndPoint)
        {
            DoHEndpoint = DoHEndPoint.ToString();
        }

        public string[] GetTextRecords(string domain)
        {
            // TXT 16 text strings [rfc1035], we make sure to remove " around the text value
            var response = QueryDns(domain, "TXT");

            if (response.Answer != null)
            {
                var records = response.Answer
                    .Where(record => record.type == 16)
                    .Select(record => record.data.Trim('"').Replace("\" \"","").Replace("\"\"",""));

                return records.ToArray();
            }

            return new string[] { };
        }

        public IPAddress[] GetAddressRecords(string domain)
        {
            // A 1 a host address [rfc1035]
            var response = QueryDns(domain, "A");
            var records = response.Answer
                .Where(record => record.type == 1)
                .Select(record => IPAddress.Parse(record.data));

            return records.ToArray();
        }
        public string[] GetMailRecords(string domain)
        {
            // MX 15 mail exchange [rfc1035]
            var response = QueryDns(domain, "MX");

            if (response.Answer == null)
            {
                return Array.Empty<string>();
            }

            // if the record looks like 110 srv.example.nl returns srv.example.nl
            var records = response.Answer
                .Where(record => record.type == 15)
                .Select(record => record.data.Contains(" ") ? record.data.Split(' ')[1] : record.data);

            return records.ToArray();
        }

        private Rootobject QueryDns(string domain, string type)
        {
            using (WebClient _webClient = new WebClient())
            {
                var requestUri = $"{DoHEndpoint}?name={domain}&type={type}";
                _webClient.Headers.Add("accept", "application/dns-json");
                var request = _webClient.DownloadData(requestUri);

                var jsonResponse = Encoding.UTF8.GetString(request);

                return JsonSerializer.Deserialize<Rootobject>(jsonResponse, new JsonSerializerOptions() { PropertyNameCaseInsensitive = true });
            }
        }

        public async Task<string[]> GetTextRecordsAsync(string domain)
        {
            // TXT 16 text strings [rfc1035], we make sure to remove " around the text value
            var response = await QueryDnsAsync(domain, "TXT");
            if (response.Answer != null)
            {
                var records = response.Answer
                    .Where(record => record.type == 16)
                    .Select(record => record.data.Trim('"'));

                return records.ToArray();
            }

            return new string[] { };
        }

        public async Task<IPAddress[]> GetAddressRecordsAsync(string domain)
        {
            // A 1 a host address [rfc1035]
            var response = await QueryDnsAsync(domain, "A");
            var records = response.Answer
                .Where(record => record.type == 1)
                .Select(record => IPAddress.Parse(record.data));

            return records.ToArray();
        }

        public async Task<string[]> GetMailRecordsAsync(string domain)
        {
            // MX 15 mail exchange [rfc1035]
            var response = await QueryDnsAsync(domain, "MX");

            if (response.Answer == null)
            {
                return Array.Empty<string>();
            }

            // if the record looks like 110 srv.example.nl returns srv.example.nl
            var records = response.Answer
                .Where(record => record.type == 15)
                .Select(record => record.data.Contains(" ") ? record.data.Split(' ')[1] : record.data);

            return records.ToArray();
        }

        private async Task<Rootobject> QueryDnsAsync(string domain, string type)
        {
            var requestUri = $"{DoHEndpoint}?name={domain}&type={type}";
            var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
            request.Headers.Add("accept", "application/dns-json");

            using (HttpClient _httpClient = new HttpClient())
            {
                var response = await _httpClient.SendAsync(request);
                response.EnsureSuccessStatusCode();

                var jsonResponse = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<Rootobject>(jsonResponse, new JsonSerializerOptions() { PropertyNameCaseInsensitive = true });
            }
        }

        public class Rootobject
        {
            public int Status { get; set; }
            public bool TC { get; set; }
            public bool RD { get; set; }
            public bool RA { get; set; }
            public bool AD { get; set; }
            public bool CD { get; set; }
            public Question[] Question { get; set; }
            public Answer[] Answer { get; set; }
        }

        public class Question
        {
            public string name { get; set; }
            public int type { get; set; }
        }

        public class Answer
        {
            public string name { get; set; }
            public int type { get; set; }
            public int TTL { get; set; }
            public string data { get; set; }
        }
    }
}
