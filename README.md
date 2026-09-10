# BusinessMonitor.MailTools

[![Test status](https://github.com/markvantilburg/BusinessMonitor.MailTools/actions/workflows/test.yml/badge.svg)](https://github.com/markvantilburg/BusinessMonitor.MailTools/actions/workflows/test.yml)
[![Nuget](https://img.shields.io/nuget/v/BusinessMonitor.MailTools)](https://www.nuget.org/packages/BusinessMonitor.MailTools/)

A .NET library providing utilities for mail such as DKIM, SPF and DMARC.

## Usage

```bash
dotnet add package BusinessMonitor.MailTools
```

If you are using ASP.NET targeting .NET Framework you may need netstandard as reference in your `web.config`.

```xml
<assemblies>
    <add assembly="netstandard, Version=2.0.0.0, Culture=neutral, PublicKeyToken=cc7b13ffcd2ddd51" />
</assemblies>
```

### Resolver

To make this library independent of any DNS resolver implementation, we instead provide a `IResolver` interface.
Each check class which needs to do lookups will require an instance of this interface, the user can then implement this interface with their own DNS library of choice.

```cs
public class DnsResolver : IResolver
{
    public string[] GetTextRecords(string domain)
    {
        // Your DNS resolve implementation goes here
    }
}
```

For an example implementation see [BusinessMonitor.MailTools.Dns](https://github.com/markvantilburg/BusinessMonitor.MailTools/tree/main/BusinessMonitor.MailTools.Dns)

### Exception messages

Validation exceptions quote the offending part of the DNS record in their message, for example
`Not a valid SPF record, 'bogus' is not a valid mechanism`. That content comes from DNS and is
controlled by whoever controls the domain. The library replaces control and non-ASCII characters
and truncates long values, but it does **not** HTML encode. Always encode `ex.Message` before
rendering it in a web page and treat it as untrusted text in logs.

### BIMI locations

The `l=` and `a=` locations of a BIMI record are URIs a consumer is expected to fetch. Besides
requiring HTTPS, the library rejects locations with credentials in the URI and locations that
point to localhost or to a non-routable IP address (loopback, private, link-local, cloud metadata
ranges and so on). A host name that *resolves* to such an address can only be detected when the
location is fetched, so code that downloads these files must still apply its own egress checks.

### Examples

Validate the DKIM record on a domain and return the public key:

```cs
var check = new DkimCheck(resolver);
var record = check.GetDkimRecord(domain, selector);

Console.WriteLine(record.PublicKey);
```

Parse a DMARC record:

```cs
var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject; adkim=s; aspf=s");

Console.WriteLine(record.DkimMode);
```

DMARC records are validated against RFC 9989 (DMARCbis). A few things to know:

- `GetDmarcRecord` only queries `_dmarc.<domain>`. When a subdomain has no record, receivers continue
  with the organizational domain (RFC 9989 section 4.10.1); that step needs the public suffix list and
  is left to the caller.
- A domain publishing more than one DMARC record is reported as invalid, receivers discard all of them.
- An absent `p` tag is treated as `p=none`, `PolicySpecified` tells whether the tag was present.
  `sp` inherits `p` and `np` inherits `sp` when absent, the properties return the effective policy.
- `pct`, `rf` and `ri` were removed in RFC 9989 and are ignored by receivers following it. They are
  still parsed for older receivers but the properties are marked obsolete.
- The parser is stricter than a receiver: RFC 9989 lets receivers ignore syntax errors, this library
  reports them as `DmarcInvalidException` so they can be fixed.

Get a SPF record and return all includes:

```cs
var check = new SpfCheck(resolver);
var record = check.GetSpfRecord(domain);

foreach (var directive in record.Directives)
{
    if (directive.Mechanism == SpfMechanism.Include)
    {
        Console.WriteLine(directive.Include); // The include domain
        Console.WriteLine(directive.Included); // The included SPF record
    }
}
```

Validate MX records for a domain:

```cs
var validator = new MxValidator(resolver);
var result = validator.ValidateMxRecords("example.com");

if (!result.HasMxRecords)
{
    Console.WriteLine("No MX records found.");
}
else if (result.InvalidMxRecords.Count > 0)
{
    Console.WriteLine("Invalid MX records:");
    foreach (var mx in result.InvalidMxRecords)
    {
        Console.WriteLine(mx);
    }
}
else
{
    Console.WriteLine("All MX records are valid.");
}
```
