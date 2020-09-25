# SharpShares
Multithreaded C# .NET Assembly to enumerate accessible network shares in the current domain

Built upon [djhohnstein's SharpShares](https://github.com/djhohnstein/SharpShares) project

```
> .\SharpShares.exe help

█▀ █░█ ▄▀█ █▀█ █▀█ █▀ █░█ ▄▀█ █▀█ █▀▀ █▀
▄█ █▀█ █▀█ █▀▄ █▀▀ ▄█ █▀█ █▀█ █▀▄ ██▄ ▄█

Usage:
    SharpShares.exe
    or w/ optional arguments:
    SharpShares.exe /threads:50 /filter /verbose

Optional Arguments:
    /threads  - specify maximum number of parallel threads (default=25)
    /filter   - exclude SYSVOL & NETLOGON shares
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
        filter: False
        verbose: False
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
[r] \\DESKTOP\ADMIN$
[r] \\DESKTOP\C$
[+] Finished Enumerating Shares
```
