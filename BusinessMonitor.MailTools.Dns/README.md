# BusinessMonitor.MailTools.Dns

Default DNS resolver implementing `IResolver`, uses Bdev.Net.Dns as backing DNS library.

```cs
var resolver = new DnsResolver();
var check = new DkimCheck(resolver);

check.GetDkimRecord(domain, selector);
```

An example DoH resolver (using DNS over https, JSON protocol):

```cs
var resolver = new DoHResolver("https://cloudflare-dns.com/dns-query");
var check = new DkimCheck(resolver);

check.GetDkimRecord(domain, selector);
```
