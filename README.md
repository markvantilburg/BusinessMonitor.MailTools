# BusinessMonitor.MailTools

![Test status](https://github.com/markvantilburg/BusinessMonitor.MailTools/actions/workflows/test.yml/badge.svg)
![Nuget](https://img.shields.io/nuget/v/BusinessMonitor.MailTools)

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

For an example implementation see [BusinessMonitor.MailTools.Dns](BusinessMonitor.MailTools.Dns/).

### Examples

Validate the DKIM record on a domain and return the public key:

```cs
var check = new DkimCheck(resolver);
var record = check.GetDkimRecord(domain, selector);

Console.WriteLine(record.PublicKey)
```

Parse a DMARC record:

```cs
var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; p=reject; adkim=s; aspf=s");

Console.WriteLine(record.DkimMode);
```

Get a SPF record and return all includes:

```cs
var check = new SpfCheck(resolver);
var record = check.GetSpfRecord(domain);

foreach (var directive in record.Directives)
{
    if (directive.Mechanism == SpfMechanism.Include)
    {
        Console.WriteLine(directive.Include) // The include domain
        Console.WriteLine(directive.Included) // The included SPF record
    }
}
```
