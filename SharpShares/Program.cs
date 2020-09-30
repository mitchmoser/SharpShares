using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace SharpShares
{
    class Program
    {
        [DllImport("Netapi32.dll", SetLastError = true)]
        public static extern int NetWkstaGetInfo(string servername, int level, out IntPtr bufptr);

        [DllImport("Netapi32.dll", SetLastError = true)]
        static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetShareEnum(
            StringBuilder ServerName,
            int level,
            ref IntPtr bufPtr,
            uint prefmaxlen,
            ref int entriesread,
            ref int totalentries,
            ref int resume_handle
        );

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WKSTA_INFO_100
        {
            public int platform_id;
            public string computer_name;
            public string lan_group;
            public int ver_major;
            public int ver_minor;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_0
        {
            public string shi0_netname;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_1
        {
            public string shi1_netname;
            public uint shi1_type;
            public string shi1_remark;
            public SHARE_INFO_1(string sharename, uint sharetype, string remark)
            {
                this.shi1_netname = sharename;
                this.shi1_type = sharetype;
                this.shi1_remark = remark;
            }
            public override string ToString()
            {
                return shi1_netname;
            }
        }

        const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;
        const int NERR_Success = 0;

        private enum NetError : uint
        {
            NERR_Success = 0,
            NERR_BASE = 2100,
            NERR_UnknownDevDir = (NERR_BASE + 16),
            NERR_DuplicateShare = (NERR_BASE + 18),
            NERR_BufTooSmall = (NERR_BASE + 23),
        }

        private enum SHARE_TYPE : uint
        {
            STYPE_DISKTREE = 0,
            STYPE_PRINTQ = 1,
            STYPE_DEVICE = 2,
            STYPE_IPC = 3,
            STYPE_SPECIAL = 0x80000000,
        }

        public static SHARE_INFO_1[] EnumNetShares(string Server)
        {
            List<SHARE_INFO_1> ShareInfos = new List<SHARE_INFO_1>();
            int entriesread = 0;
            int totalentries = 0;
            int resume_handle = 0;
            int nStructSize = Marshal.SizeOf(typeof(SHARE_INFO_1));
            IntPtr bufPtr = IntPtr.Zero;
            StringBuilder server = new StringBuilder(Server);
            int ret = NetShareEnum(server, 1, ref bufPtr, MAX_PREFERRED_LENGTH, ref entriesread, ref totalentries, ref resume_handle);
            if (ret == NERR_Success)
            {
                IntPtr currentPtr = bufPtr;
                for (int i = 0; i < entriesread; i++)
                {
                    SHARE_INFO_1 shi1 = (SHARE_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(SHARE_INFO_1));
                    ShareInfos.Add(shi1);
                    currentPtr += nStructSize;
                }
                NetApiBufferFree(bufPtr);
                return ShareInfos.ToArray();
            }
            else
            {
                ShareInfos.Add(new SHARE_INFO_1("ERROR=" + ret.ToString(), 10, string.Empty));
                return ShareInfos.ToArray();
            }
        }
        
        public static List<DomainController> GetDomainControllers()
        {
            List<DomainController> domainControllers = new List<DomainController>();
            try
            {
                Domain domain = Domain.GetCurrentDomain();
                foreach (DomainController dc in domain.DomainControllers)
                {
                    domainControllers.Add(dc);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Error collecting Domain Controllers: {0}", ex.Message);
            }
            return domainControllers;
        }

        public static List<string> SearchLDAP(string filter, bool verbose)
        {
            try
            {
                List<string> ComputerNames = new List<string>();

                DirectoryEntry entry = new DirectoryEntry();
                DirectorySearcher mySearcher = new DirectorySearcher(entry);

                //https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
                //https://ldapwiki.com/wiki/Active%20Directory%20Computer%20Related%20LDAP%20Query
                switch (filter)
                {
                    case "all":
                        //All enabled computers with "primary" group "Domain Computers"
                        mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
                        break;
                    case "dc":
                        //All enabled Domain Controllers
                        mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=8192))");
                        break;
                    case "exclude-dc":
                        //All enabled computers that are not Domain Controllers
                        mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))");
                        break;
                    case "servers":
                        //All enabled servers
                        mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*))");
                        break;
                    case "servers-exclude-dc":
                        //All enabled servers excluding DCs
                        mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))");
                        break;
                    default:
                        Console.WriteLine("[!] Invalid LDAP filter: {0}", filter);
                        Usage();
                        Environment.Exit(0);
                        break;
                }

                mySearcher.SizeLimit = int.MaxValue;
                mySearcher.PageSize = int.MaxValue;
                int counter = 0;
                foreach (SearchResult resEnt in mySearcher.FindAll())
                {
                    string ComputerName = resEnt.GetDirectoryEntry().Name;
                    if (ComputerName.StartsWith("CN="))
                        ComputerName = ComputerName.Remove(0, "CN=".Length);
                    ComputerNames.Add(ComputerName);
                    counter += 1;
                }
                Console.WriteLine("[+] LDAP Search Results: {0}", counter.ToString());
                mySearcher.Dispose();
                entry.Dispose();

                return ComputerNames;
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                }
                Environment.Exit(0);
                return null;
            }
        }
        public static List<string> SearchOU(string ou, bool verbose)
        {
            try
            {
                List<string> ComputerNames = new List<string>();
                string searchbase = "LDAP://" + ou;//OU=Domain Controllers,DC=example,DC=local";
                DirectoryEntry entry = new DirectoryEntry(searchbase);
                DirectorySearcher mySearcher = new DirectorySearcher(entry);
                // filter for all enabled computers
                mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
                mySearcher.SizeLimit = int.MaxValue;
                mySearcher.PageSize = int.MaxValue;
                int counter = 0;
                foreach (SearchResult resEnt in mySearcher.FindAll())
                {
                    string ComputerName = resEnt.GetDirectoryEntry().Name;
                    if (ComputerName.StartsWith("CN="))
                        ComputerName = ComputerName.Remove(0, "CN=".Length);
                    ComputerNames.Add(ComputerName);
                    counter += 1;
                }
                Console.WriteLine("[+] OU Search Results: {0}", counter.ToString());
                mySearcher.Dispose();
                entry.Dispose();

                return ComputerNames;
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                }
                Environment.Exit(0);
                return null;
            }
        }

        public static void GetComputerShares(string computer, bool verbose, bool filter, string outfile)
        {
            string[] errors = { "ERROR=53", "ERROR=5" };
            List<string> exclusions = new List<string>();
            if (filter)
            {
                exclusions.Add("NETLOGON");
                exclusions.Add("SYSVOL");
                exclusions.Add("PRINT$");
            }
            SHARE_INFO_1[] computerShares = EnumNetShares(computer);
            if (computerShares.Length > 0)
            {
                List<string> readableShares = new List<string>();
                List<string> writeableShares = new List<string>();
                List<string> unauthorizedShares = new List<string>();
                // get current user's identity to compare against ACL of shares
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                string userSID = identity.User.Value;
                foreach (SHARE_INFO_1 share in computerShares)// <-- go to next share --+
                {                                                                    // |
                    if (exclusions.Contains(share.shi1_netname.ToString().ToUpper()))// |
                    {                                                                // |
                        continue; // Skip the remainder of this iteration. -------------+
                    }
                    try
                    {
                        string path = String.Format("\\\\{0}\\{1}", computer, share.shi1_netname);
                        var files = Directory.GetFiles(path);
                        readableShares.Add(share.shi1_netname);
                        AuthorizationRuleCollection rules = Directory.GetAccessControl(path).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                        foreach (FileSystemAccessRule rule in rules)
                        {
                            //https://stackoverflow.com/questions/130617/how-do-you-check-for-permissions-to-write-to-a-directory-or-file
                            // compare SID of group referenced in ACL to groups the current user is a member of
                            if (rule.IdentityReference.ToString() == userSID || identity.Groups.Contains(rule.IdentityReference))
                            {
                                // plenty of other FileSystem Rights to look for
                                // https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights
                                if ((//rule.FileSystemRights.HasFlag(FileSystemRights.CreateFiles) ||
                                     //rule.FileSystemRights.HasFlag(FileSystemRights.WriteAttributes) ||
                                     //rule.FileSystemRights.HasFlag(FileSystemRights.WriteData) ||
                                     //rule.FileSystemRights.HasFlag(FileSystemRights.WriteExtendedAttributes) ||
                                     //rule.FileSystemRights.HasFlag(FileSystemRights.CreateDirectories) ||
                                    rule.FileSystemRights.HasFlag(FileSystemRights.Write)) && rule.AccessControlType == AccessControlType.Allow)
                                {
                                    writeableShares.Add(share.shi1_netname);
                                    break;
                                }
                            }
                        }
                    }
                    catch
                    {
                        if (!errors.Contains(share.shi1_netname))
                        {
                            unauthorizedShares.Add(share.shi1_netname);
                        }
                    }
                }
                if (readableShares.Count > 0)
                {
                    foreach (string share in readableShares)
                    {
                        string output = String.Format("[r] \\\\{0}\\{1}", computer, share);
                        if (!String.IsNullOrEmpty(outfile))
                        {
                            using (StreamWriter sw = File.AppendText(outfile))
                            {
                                sw.WriteLine(output);
                            }
                        }
                        else
                        {
                            Console.WriteLine(output);
                        }
                    }
                }
                if (writeableShares.Count > 0)
                {
                    foreach (string share in writeableShares)
                    {
                        string output = String.Format("[w] \\\\{0}\\{1}", computer, share);
                        if (!String.IsNullOrEmpty(outfile))
                        {
                            using (StreamWriter sw = File.AppendText(outfile))
                            {
                                sw.WriteLine(output);
                            }
                        }
                        else
                        {
                            Console.WriteLine(output);
                        }
                    }
                }
                if (verbose && unauthorizedShares.Count > 0)
                {
                    foreach (string share in unauthorizedShares)
                    {
                        string output = String.Format("[-] \\\\{0}\\{1}", computer, share);
                        if (!String.IsNullOrEmpty(outfile))
                        {
                            using (StreamWriter sw = File.AppendText(outfile))
                            {
                                sw.WriteLine(output);
                            }
                        }
                        else
                        {
                            Console.WriteLine(output);
                        }
                    }
                }
            }
        }
        public static void GetAllShares(List<string> computers, int threads, bool verbose, bool filter, string outfile)
        {
            //https://blog.danskingdom.com/limit-the-number-of-c-tasks-that-run-in-parallel/
            var threadList = new List<Action>();
            foreach (string computer in computers)
            {
                threadList.Add(() => GetComputerShares(computer, verbose, filter, outfile));
            }
            var options = new ParallelOptions { MaxDegreeOfParallelism = threads };
            Parallel.Invoke(options, threadList.ToArray());
            Console.WriteLine("[+] Finished Enumerating Shares");
        }
        static Dictionary<string, string[]> ParseArgs(string[] args)
        {
            Dictionary<string, string[]> result = new Dictionary<string, string[]>();
            //these boolean variables aren't passed w/ values. If passed, they are "true"
            string[] booleans = new string[] { "/verbose", "/filter" };
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
        static void Usage()
        {
            string usageString = @"

█▀ █ █ ▄▀█ █▀█ █▀█ █▀ █ █ ▄▀█ █▀█ █▀▀ █▀
▄█ █▀█ █▀█ █▀▄ █▀▀ ▄█ █▀█ █▀█ █▀▄ ██▄ ▄█

Usage:
    SharpShares.exe
    or w/ optional arguments:
    SharpShares.exe /threads:50 /ldap:servers /ou:""OU=Special Servers,DC=example,DC=local"" /filter /verbose /outfile:C:\path\to\file.txt

Optional Arguments:
    /threads  - specify maximum number of parallel threads (default=25)
    /ldap     - query hosts from the following LDAP filters: (default=all)
         :all - All enabled computers with 'primary' group 'Domain Computers'
         :dc  - All enabled Domain Controllers
         :exclude-dc - All enabled computers that are not Domain Controllers
         :servers - All enabled servers
         :servers-exclude-dc - All enabled servers excluding DCs
    /ou       - specify LDAP OU to query enabled computer objects from
                ex: ""OU=Special Servers,DC=example,DC=local""
    /filter   - exclude SYSVOL, NETLOGON, and print$ shares
    /outfile  - specify file for shares to be appended to instead of printing to std out 
    /verbose  - return unauthorized shares
";
            Console.WriteLine(usageString);
        }
        static void PrintOptions(int threads, string ldapFilter, string ou, bool filter, bool verbose, string outfile)
        {
            Console.WriteLine("[+] Parsed Aguments:");
            Console.WriteLine("\tthreads: {0}", threads.ToString());
            Console.WriteLine("\tldap: {0}", ldapFilter);
            Console.WriteLine("\tou: {0}", ou);
            Console.WriteLine("\tfilter: {0}", filter.ToString());
            Console.WriteLine("\tverbose: {0}", filter.ToString());
            Console.WriteLine("\toutfile: {0}", outfile);
        }

        static void Main(string[] args)
        {
            List<string> hosts = new List<string>();
            var parsedArgs = ParseArgs(args);
            bool filter = false;
            if (parsedArgs.ContainsKey("/filter"))
            {
                filter = Convert.ToBoolean(parsedArgs["/filter"][0]);
            }
            bool verbose = false;
            if (parsedArgs.ContainsKey("/verbose"))
            {
                verbose = Convert.ToBoolean(parsedArgs["/verbose"][0]);
            }
            string ldapFilter = null;
            if (parsedArgs.ContainsKey("/ldap"))
            {
                ldapFilter = parsedArgs["/ldap"][0].ToLower();
                List<string> ldap = SearchLDAP(ldapFilter, verbose);
                hosts = hosts.Concat(ldap).ToList();
            }
            string outfile = null;
            if (parsedArgs.ContainsKey("/outfile"))
            {
                outfile = parsedArgs["/outfile"][0].ToLower();
            }
            string ou = null;
            if (parsedArgs.ContainsKey("/ou"))
            {
                ou = parsedArgs["/ou"][0].ToLower();
                List<string> results = SearchOU(ou, verbose);
                hosts = hosts.Concat(results).ToList();
            }
            // if no ldap or ou filter specified, search all enabled computer objects
            if (!(parsedArgs.ContainsKey("/ldap")) && !(parsedArgs.ContainsKey("/ou")))
            {
                ldapFilter = "all";
                List<string> ldap = SearchLDAP(ldapFilter, verbose);
                hosts = hosts.Concat(ldap).ToList();
            }
            int threads = 25;
            if (parsedArgs.ContainsKey("/threads"))
            {
                threads = Convert.ToInt32(parsedArgs["/threads"][0]);
            }
            if (parsedArgs.ContainsKey("help"))
            {
                Usage();
                Environment.Exit(0);
            }
            //remove duplicate hosts
            hosts = hosts.Distinct().ToList();
            PrintOptions(threads, ldapFilter, ou, filter, verbose, outfile);
            if (!String.IsNullOrEmpty(outfile))
            {
                if (!File.Exists(outfile))
                {
                    // Create a file to write to if it doesn't exist
                    using (StreamWriter sw = File.CreateText(outfile)) { };
                    Console.WriteLine("[+] {0} Created", outfile);
                }
                else
                {
                    Console.WriteLine("[!] {0} already esists. Appending to file", outfile);
                }
            }
            Console.WriteLine("[*] Collected {0} enabled computer objects.", hosts.Count);
            Console.WriteLine("[*] Starting share enumeration with thread limit of {0}", threads.ToString());
            Console.WriteLine("[r] = Readable Share\n[w] = Writeable Share\n[-] = Unauthorized Share (requires /verbose flag)\n");
            GetAllShares(hosts, threads, verbose, filter, outfile);
        }
    }
}