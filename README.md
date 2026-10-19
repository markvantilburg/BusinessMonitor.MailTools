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

An `IResolver` implementation is expected to:

- Return an empty array when the name has no records of the requested type or does not exist (NODATA, NXDOMAIN), and **throw** on a transient failure (SERVFAIL, timeout, network error). An empty array is taken as a definitive answer, for example the MX validator then falls back to the implicit MX.
- Return both A and AAAA records from `GetAddressRecords`. With A records only, an IPv6-only mail host appears to have no addresses and is treated as unable to receive mail.
- Return the exchange host name only from `GetMailRecords`, without the preference. A null MX (RFC 7505) is returned as `.` or an empty string.
- Return one string per TXT record from `GetTextRecords`, with the character-strings of a record concatenated (see the remarks on the interface).
- Follow aliases (CNAME) itself. The checks only see the final records and cannot detect an MX exchange that points to an alias (RFC 2181 section 10.3).

### Internationalized domain names

Domains and selectors passed to the checks may be given in their Unicode form, `bücher.de` is looked up as `xn--bcher-kva.de`. The conversion uses the IDNA implementation of the runtime: .NET Framework (and .NET with NLS) applies IDNA2003, which maps `ß` to `ss`, while .NET with ICU applies UTS #46 / IDNA2008, which keeps `ß` as `xn--zca`. These are different registered domains, pass the A-label form yourself when that distinction matters. Record content is never converted, a domain inside an SPF, DMARC or BIMI record must already be in A-label form as required by those specifications.

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

if (!result.CanReceiveMail)
{
    Console.WriteLine("The domain cannot receive mail.");
}
else if (result.HasImplicitMx)
{
    Console.WriteLine("No MX records, mail is delivered to the domain itself (implicit MX, RFC 5321 section 5.1).");
}

if (result.InvalidMxRecords.Count > 0)
{
    Console.WriteLine("Invalid MX records:");
    foreach (var mx in result.InvalidMxRecords)
    {
        Console.WriteLine(mx);
    }
}
```

`HasNullMx` is set when the domain publishes a null MX (RFC 7505, `0 .`), the domain then states it accepts no mail. A null MX must be the only MX record, when other MX records are present it is reported in `InvalidMxRecords`.

`InvalidMxRecords` lists the MX hosts that are not a valid host name, have no address records or resolve to a non-routable address.

`CanReceiveMail` is the DNS-level conclusion: at least one MX host, or the implicit MX host, is a valid name that resolves to address records none of which is non-routable, in other words at least one MX host is not in `InvalidMxRecords`. It is `false` for a domain without MX and address records, for a null MX (RFC 7505, `0 .`), and when every mail host is invalid. No SMTP connection is made, a server that exists may still refuse mail.

A domain without MX records is not without mail, RFC 5321 section 5.1 treats it as having an implicit MX record with preference 0 pointing to the domain itself. `ValidateMxRecords` then validates the address records of the domain and sets `HasImplicitMx`, a non-routable address is reported in `InvalidMxRecords` as the domain name. A null MX is an MX record and does not fall back to the implicit MX.
