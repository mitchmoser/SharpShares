# SharpShares
Multithreaded C# .NET Assembly to enumerate accessible network shares in a domain

Built upon [djhohnstein's SharpShares](https://github.com/djhohnstein/SharpShares) project

```
> .\SharpShares.exe help

█▀ █ █ ▄▀█ █▀█ █▀█ █▀ █ █ ▄▀█ █▀█ █▀▀ █▀
▄█ █▀█ █▀█ █▀▄ █▀▀ ▄█ █▀█ █▀█ █▀▄ ██▄ ▄█

Usage:
    SharpShares.exe
    or w/ optional arguments:
    SharpShares.exe /threads:50 /ldap:servers /ou:"OU=Special Servers,DC=example,DC=local" /filter /verbose /outfile:C:\path\to\file.txt

Optional Arguments:
    /threads  - specify maximum number of parallel threads  (default=25)
    /ldap     - query hosts from the following LDAP filters (default=all)
         :all - All enabled computers with 'primary' group 'Domain Computers'
         :dc  - All enabled Domain Controllers
         :exclude-dc - All enabled computers that are not Domain Controllers
         :servers - All enabled servers
         :servers-exclude-dc - All enabled servers excluding DCs
    /ou       - specify LDAP OU to query enabled computer objects from
                ex: "OU=Special Servers,DC=example,DC=local"
    /filter   - exclude SYSVOL, NETLOGON, and print$ shares
    /outfile  - specify file for shares to be appended to instead of printing to std out
    /verbose  - return unauthorized shares
```

## Execute Assembly
```
execute-assembly /path/to/SharpShares.exe
```
## Example Output
```
[+] Parsed Aguments:
        threads: 25
        ldap: all
        ou: none
        filter: False
        verbose: False
        outfile:
[+] LDAP Search Description: All enabled computers with primary group 'Domain Computers'
[+] LDAP Search Results: 10
[*] Collected 10 enabled computer objects.
[*] Starting share enumeration with thread limit of 25
[r] = Readable Share
[w] = Writeable Share
[-] = Unauthorized Share (requires /verbose flag)

[r] \\DC-01\CertEnroll
[r] \\DC-01\File History Backups
[r] \\DC-01\Folder Redirection
[r] \\DC-01\NETLOGON
[r] \\DC-01\Shared Folders
[r] \\DC-01\SYSVOL
[r] \\DC-01\Users
[w] \\WEB-01\wwwroot
[r] \\DESKTOP\ADMIN$
[r] \\DESKTOP\C$
[+] Finished Enumerating Shares
```
