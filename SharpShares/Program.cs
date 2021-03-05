using System;
using System.Collections.Generic;
using System.Linq;


namespace SharpShares
{
    class Program
    {
        
        static void Main(string[] args)
        {
            List<string> hosts = new List<string>();
            var parsedArgs = Utilities.Options.ParseArgs(args);
            Utilities.Options.Arguments arguments = Utilities.Options.ArgumentValues(parsedArgs);
            Utilities.Options.PrintOptions(arguments.threads, arguments.ldap, arguments.ou, arguments.filter, arguments.stealth, arguments.verbose, arguments.outfile);
            if (arguments.filter != null) { Console.WriteLine("[*] Excluding {0} shares", String.Join(",", arguments.filter)); }
            if (arguments.verbose) { Console.WriteLine("[*] Including unreadable shares"); }
            Console.WriteLine("[*] Starting share enumeration with thread limit of {0}", arguments.threads.ToString());
            Console.WriteLine("[r] = Readable Share\n[w] = Writeable Share\n[-] = Unauthorized Share (requires /verbose flag)\n[?] = Unchecked Share (requires /stealth flag)\n");
            List<string> ldap = Utilities.LDAP.SearchLDAP(arguments.ldap, arguments.verbose);
            hosts = hosts.Concat(ldap).ToList();
            //remove duplicate hosts
            hosts = hosts.Distinct().ToList();
            Enums.Shares.GetAllShares(hosts, arguments.threads, arguments.verbose, arguments.filter, arguments.stealth, arguments.outfile);
        }
    }
}