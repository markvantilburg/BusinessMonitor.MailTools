# BusinessMonitor.MailTools

A .NET library providing utilities for mail such as DKIM, SPF and DMARC.

## Usage

```bash
dotnet add package BusinessMonitor.MailTools
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
var record = DmarcCheck.ParseDmarcRecord("v=DMARC1; adkim=s; aspf=s; p=reject");

Console.WriteLine(record.DkimMode);
```