using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;

namespace SharpShares.Utilities
{
    class LDAP
    {
        public static List<string> SearchLDAP(string filter, bool verbose)
        {
            try
            {
                List<string> ComputerNames = new List<string>();
                string description = "";

                Forest currentForest = Forest.GetCurrentForest();
                GlobalCatalog globalCatalog = currentForest.FindGlobalCatalog();
                DirectorySearcher globalCatalogSearcher = globalCatalog.GetDirectorySearcher();

                //DirectoryEntry entry = new DirectoryEntry();
                //DirectorySearcher mySearcher = new DirectorySearcher(entry);

                globalCatalogSearcher.PropertiesToLoad.Add("dnshostname");
                //https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
                //https://ldapwiki.com/wiki/Active%20Directory%20Computer%20Related%20LDAP%20Query
                switch (filter)
                {
                    case "all":
                        description = "all enabled computers with \"primary\" group \"Domain Computers\"";
                        globalCatalogSearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
                        break;
                    case "dc":
                        description = "all enabled Domain Controllers (not read-only DCs)";
                        globalCatalogSearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=8192))");
                        break;
                    case "exclude-dc":
                        description = "all enabled computers that are not Domain Controllers or read-only DCs";
                        globalCatalogSearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))");
                        break;
                    case "servers":
                        description = "all enabled servers";
                        globalCatalogSearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*))");
                        break;
                    case "servers-exclude-dc":
                        description = "all enabled servers excluding Domain Controllers or read-only DCs";
                        globalCatalogSearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))");
                        break;
                    default:
                        Console.WriteLine("[!] Invalid LDAP filter: {0}", filter);
                        Utilities.Options.Usage();
                        Environment.Exit(0);
                        break;
                }

                globalCatalogSearcher.SizeLimit = int.MaxValue;
                globalCatalogSearcher.PageSize = int.MaxValue;
                Console.WriteLine("[+] Performing LDAP query for {0}...", description);
                Console.WriteLine("[+] This may take some time depending on the size of the environment");
                foreach (SearchResult resEnt in globalCatalogSearcher.FindAll())
                {
                    string ComputerName = resEnt.Properties["dnshostname"][0].ToString();
                    ComputerNames.Add(ComputerName);
                }
                //localhost returns false positives
                ComputerNames.RemoveAll(u => u.Contains(System.Environment.MachineName));
                Console.WriteLine("[+] LDAP Search Results: {0}", ComputerNames.Count.ToString());
                globalCatalogSearcher.Dispose();

                return ComputerNames;
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                }
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
                mySearcher.PropertiesToLoad.Add("dnshostname");
                // filter for all enabled computers
                mySearcher.Filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
                mySearcher.SizeLimit = int.MaxValue;
                mySearcher.PageSize = int.MaxValue;
                foreach (SearchResult resEnt in mySearcher.FindAll())
                {
                    string ComputerName = resEnt.Properties["dnshostname"][0].ToString();
                    ComputerNames.Add(ComputerName);
                }
                Console.WriteLine("[+] OU Search Results: {0}", ComputerNames.Count().ToString());
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
    }
}
