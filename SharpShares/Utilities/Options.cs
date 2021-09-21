using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;


namespace SharpShares.Utilities
{
    class Options
    {
        //default values off all arguments
        public class Arguments
        {
            public bool help = false;
            public bool stealth = false;
            public bool validate = false;
            public bool verbose = false;
            public int threads = 25;
            public List<string> filter = new List<string> { "SYSVOL", "NETLOGON", "IPC$", "PRINT$" };
            public string dc = null;
            public string domain = null;
            public string ldap = null;
            public string ou = null;
            public string outfile = null;
            public string targets = null;
        }
        public static Dictionary<string, string[]> ParseArgs(string[] args)
        {
            Dictionary<string, string[]> result = new Dictionary<string, string[]>();
            //these boolean variables aren't passed w/ values. If passed, they are "true"
            string[] booleans = new string[] { "/stealth", "/validate", "/verbose" };
            var argList = new List<string>();
            foreach (string arg in args)
            {
                //delimit key/value of arguments by ":"
                string[] parts = arg.Split(":".ToCharArray(), 2);
                argList.Add(parts[0]);

                //boolean variables
                if (parts.Length == 1)
                {
                    result[parts[0]] = new string[] { "true" };
                }
                if (parts.Length == 2)
                {
                    result[parts[0]] = new string[] { parts[1] };
                }
            }
            return result;
        }
        public static Arguments ArgumentValues(Dictionary<string, string[]> parsedArgs)
        {
            Arguments arguments = new Arguments();
            if (parsedArgs.ContainsKey("/dc"))
            {
                arguments.dc = parsedArgs["/dc"][0];
            }
            if (parsedArgs.ContainsKey("/domain"))
            {
                arguments.domain = parsedArgs["/domain"][0];
            }
            if (parsedArgs.ContainsKey("/filter"))
            {
                arguments.filter = parsedArgs["/filter"][0].ToUpper().Split(',').ToList();
            }
            if (parsedArgs.ContainsKey("/ldap"))
            {
                arguments.ldap = parsedArgs["/ldap"][0];
            }
            if (parsedArgs.ContainsKey("/ou"))
            {
                arguments.ou = parsedArgs["/ou"][0];
            }
            if (parsedArgs.ContainsKey("/outfile"))
            {
                arguments.outfile = parsedArgs["/outfile"][0];
            }
            if (parsedArgs.ContainsKey("/stealth"))
            {
                arguments.stealth = Convert.ToBoolean(parsedArgs["/stealth"][0]);
            }
            if (parsedArgs.ContainsKey("/targets"))
            {
                arguments.targets = parsedArgs["/targets"][0];
            }
            if (parsedArgs.ContainsKey("/threads"))
            {
                arguments.threads = Convert.ToInt32(parsedArgs["/threads"][0]);
            }
            if (parsedArgs.ContainsKey("/validate"))
            {
                arguments.validate = Convert.ToBoolean(parsedArgs["/validate"][0]);
            }
            if (parsedArgs.ContainsKey("/verbose"))
            {
                arguments.verbose = Convert.ToBoolean(parsedArgs["/verbose"][0]);
            }
            if (parsedArgs.ContainsKey("help"))
            {
                Usage();
                //Environment.Exit(0);
                arguments = null;
            }
            // if no ldap or ou filter specified, search all enabled computer objects
            if (!(parsedArgs.ContainsKey("/ldap")) && !(parsedArgs.ContainsKey("/ou")) && !(parsedArgs.ContainsKey("/targets")))
            {
                Console.WriteLine("[!] Must specify hosts using one of the following arguments: /ldap /ou");
                Utilities.Options.Usage();
                //Environment.Exit(0);
                arguments = null;
            }
            return arguments;
        }
        public static bool PrintOptions(Utilities.Options.Arguments arguments)
        {
            bool success = true;
            Console.WriteLine("[+] Parsed Arguments:");
            Console.WriteLine("\tfilter: none");
            if (arguments.filter != null)
                Console.WriteLine($"\tfilter: {String.Join(",", arguments.filter)}");
            else
                Console.WriteLine($"\tfilter: none");
            Console.WriteLine($"\tdc: {arguments.dc}");
            Console.WriteLine($"\tdomain: {arguments.domain}");
            Console.WriteLine($"\tldap: {arguments.ldap}");
            Console.WriteLine($"\tou: {arguments.ou}");
            Console.WriteLine($"\tstealth: {arguments.stealth.ToString()}");
            Console.WriteLine($"\tthreads: {arguments.threads.ToString()}");
            Console.WriteLine($"\tverbose: {arguments.verbose.ToString()}");
            if (String.IsNullOrEmpty(arguments.outfile))
            { 
                Console.WriteLine("\toutfile: none");
            }
            else
            {
                Console.WriteLine($"\toutfile: {arguments.outfile}");
                if (!File.Exists(arguments.outfile))
                {
                    try
                    {
                        // Create a file to write to if it doesn't exist
                        using (StreamWriter sw = File.CreateText(arguments.outfile)) { };
                        Console.WriteLine($"[+] {arguments.outfile} Created");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] Outfile Error: {0}", ex.Message);
                        //Environment.Exit(0);
                        success = false;
                    }
                }
                else
                {
                    Console.WriteLine($"[!] {arguments.outfile} already esists. Appending to file");
                }
            }
            if (arguments.filter != null) { Console.WriteLine("[*] Excluding {0} shares", String.Join(",", arguments.filter)); }
            if (arguments.verbose) { Console.WriteLine("[*] Including unreadable shares"); }
            Console.WriteLine("[*] Starting share enumeration with thread limit of {0}", arguments.threads.ToString());
            Console.WriteLine("[r] = Readable Share\n[w] = Writeable Share\n[-] = Unauthorized Share (requires /verbose flag)\n[?] = Unchecked Share (requires /stealth flag)\n");
            
            return success;
        }
        public static void Usage()
        {
            string usageString = @"

█▀ █ █ ▄▀█ █▀█ █▀█ █▀ █ █ ▄▀█ █▀█ █▀▀ █▀
▄█ █▀█ █▀█ █▀▄ █▀▀ ▄█ █▀█ █▀█ █▀▄ ██▄ ▄█

Usage:
    SharpShares.exe /threads:50 /ldap:servers /ou:""OU=Special Servers,DC=example,DC=local"" /filter:SYSVOL,NETLOGON,IPC$,PRINT$ /verbose /outfile:C:\path\to\file.txt

Optional Arguments:
    /threads  - specify maximum number of parallel threads  (default=25)
    /dc       - specify domain controller to query (if not ran on a domain-joined host)
    /domain   - specify domain name (if not ran on a domain-joined host)
    /ldap     - query hosts from the following LDAP filters (default=all)
         :all - All enabled computers with 'primary' group 'Domain Computers'
         :dc  - All enabled Domain Controllers (not read-only DCs)
         :exclude-dc - All enabled computers that are not Domain Controllers or read-only DCs
         :servers - All enabled servers
         :servers-exclude-dc - All enabled servers excluding Domain Controllers or read-only DCs
    /ou       - specify LDAP OU to query enabled computer objects from
                ex: ""OU=Special Servers,DC=example,DC=local""
    /targets  - target range provided in CIDR notation (e.g. 192.168.100.0/24) or in the format 192.168.0-255.0-255.
    /stealth  - list share names without performing read/write access checks
    /filter   - list of comma-separated shares to exclude from enumeration
                default: SYSVOL,NETLOGON,IPC$,PRINT$
    /outfile  - specify file for shares to be appended to instead of printing to std out 
    /verbose  - return unauthorized shares
";
            Console.WriteLine(usageString);
        }
    } 
}
