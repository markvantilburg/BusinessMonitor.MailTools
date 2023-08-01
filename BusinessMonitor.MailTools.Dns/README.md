# BusinessMonitor.MailTools.Dns

Default DNS resolver implementing `IResolver`, uses Bdev.Net.Dns as backing DNS library.

```cs
var resolver = new DnsResolver();
var check = new DkimCheck(resolver);

check.GetDkimRecord(domain, selector);
```