using System;
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

        public static List<string> GetComputers()
        {
            List<string> computerNames = new List<string>();
            List<DomainController> dcs = GetDomainControllers();
            if (dcs.Count > 0)
            {
                try
                {
                    Domain domain = Domain.GetCurrentDomain();
                    //domain.
                    string currentUser = WindowsIdentity.GetCurrent().Name.Split('\\')[1];


                    using (DirectoryEntry entry = new DirectoryEntry(String.Format("LDAP://{0}", dcs[0])))
                    {
                        using (DirectorySearcher mySearcher = new DirectorySearcher(entry))
                        {
                            //https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
                            //https://ldapwiki.com/wiki/Active%20Directory%20Computer%20Related%20LDAP%20Query
                            //All enabled computers with "primary" group "Domain Computers"
                            mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");

                            // No size limit, reads all objects
                            mySearcher.SizeLimit = 0;

                            // Read data in pages of 250 objects. Make sure this value is below the limit configured in your AD domain (if there is a limit)
                            mySearcher.PageSize = 250;

                            // Let searcher know which properties are going to be used, and only load those
                            mySearcher.PropertiesToLoad.Add("name");

                            foreach (SearchResult resEnt in mySearcher.FindAll())
                            {
                                // Note: Properties can contain multiple values.
                                if (resEnt.Properties["name"].Count > 0)
                                {
                                    string computerName = (string)resEnt.Properties["name"][0];
                                    computerNames.Add(computerName);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                }
            }
            return computerNames;
        }

        public static void GetComputerShares(string computer, bool verbose, bool filter)
        {
            string[] errors = { "ERROR=53", "ERROR=5" };
            List<string> exclusions = new List<string>();
            if (filter)
            {
                exclusions.Add("NETLOGON");
                exclusions.Add("SYSVOL");
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
                foreach (SHARE_INFO_1 share in computerShares)
                {
                    if (exclusions.Contains(share.shi1_netname.ToString().ToUpper()))
                    {
                        break;
                    }
                    try
                    {
                        string path = String.Format("\\\\{0}\\{1}", computer, share.shi1_netname);
                        var files = System.IO.Directory.GetFiles(path);
                        readableShares.Add(share.shi1_netname);
                        AuthorizationRuleCollection rules = System.IO.Directory.GetAccessControl(path).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
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
                        Console.WriteLine("[r] \\\\{0}\\{1}", computer, share);
                    }
                }
                if (writeableShares.Count > 0)
                {
                    foreach (string share in writeableShares)
                    {
                        Console.WriteLine("[w] \\\\{0}\\{1}", computer, share);
                    }
                }
                if (verbose && unauthorizedShares.Count > 0)
                {
                    foreach (string share in unauthorizedShares)
                    {
                        Console.WriteLine("[-] \\\\{0}\\{1}", computer, share);
                    }
                }
            }
        }

        public static void GetAllShares(List<string> computers, int threads, bool verbose, bool filter)
        {
            //https://blog.danskingdom.com/limit-the-number-of-c-tasks-that-run-in-parallel/
            var threadList = new List<Action>();
            foreach (string computer in computers)
            {
                threadList.Add(() => GetComputerShares(computer, verbose, filter));
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
";
            Console.WriteLine(usageString);
        }

        static void PrintOptions(int threads, bool filter, bool verbose)
        {
            Console.WriteLine("[+] Parsed Aguments:");
            Console.WriteLine("\tthreads: {0}", threads.ToString());
            Console.WriteLine("\tfilter: {0}", filter.ToString());
            Console.WriteLine("\tverbose: {0}", filter.ToString());
        }

        static void Main(string[] args)
        {
            var parsedArgs = ParseArgs(args);
            int threads = 25;
            if (parsedArgs.ContainsKey("/threads"))
            {
                threads = Convert.ToInt32(parsedArgs["/threads"][0]);
            }
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
            if (parsedArgs.ContainsKey("help"))
            {
                Usage();
                Environment.Exit(0);
            }
            PrintOptions(threads, filter, verbose);
            var computers = GetComputers();
            Console.WriteLine("[*] Collected {0} enabled computer objects.", computers.Count);
            Console.WriteLine("[*] Starting share enumeration with thread limit of {0}", threads.ToString());
            Console.WriteLine("[r] = Readable Share\n[w] = Writeable Share\n[-] = Unauthorized Share (requires /verbose flag)\n");
            GetAllShares(computers, threads, verbose, filter);
        }
    }
}