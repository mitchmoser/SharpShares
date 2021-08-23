using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;

namespace SharpShares.Utilities
{
    class LDAP
    {
        public static List<string> SearchLDAP(Utilities.Options.Arguments arguments)
        {
            try
            {
                bool searchGlobalCatalog = true;
                List<string> ComputerNames = new List<string>();
                string description = null;
                string filter = null;

                //https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx
                //https://ldapwiki.com/wiki/Active%20Directory%20Computer%20Related%20LDAP%20Query
                switch (arguments.ldap)
                {
                    case "all":
                        description = "all enabled computers with \"primary\" group \"Domain Computers\"";
                        filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))");
                        break;
                    case "dc":
                        description = "all enabled Domain Controllers (not read-only DCs)";
                        filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=8192))");
                        break;
                    case "exclude-dc":
                        description = "all enabled computers that are not Domain Controllers or read-only DCs";
                        filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))");
                        break;
                    case "servers":
                        searchGlobalCatalog = false; //operatingSystem attribute is not replicated in Global Catalog
                        description = "all enabled servers";
                        filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*))");
                        break;
                    case "servers-exclude-dc":
                        searchGlobalCatalog = false; //operatingSystem attribute is not replicated in Global Catalog
                        description = "all enabled servers excluding Domain Controllers or read-only DCs";
                        filter = ("(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))");
                        break;
                    default:
                        Console.WriteLine("[!] Invalid LDAP filter: {0}", filter);
                        Utilities.Options.Usage();
                        //Environment.Exit(0);
                        return null;
                }

                if (searchGlobalCatalog)
                {
                    try
                    {
                        DirectoryEntry entry = null;
                        DirectorySearcher globalCatalogSearcher = null;
                        if (!String.IsNullOrEmpty(arguments.dc) && !String.IsNullOrEmpty(arguments.domain))
                            try
                            {
                                string directoryEntry = $"GC://{arguments.dc}/DC={arguments.domain.Replace(".", ",DC=")}";
                                Console.WriteLine($"[+] Attempting to connect to Global Catalog: {directoryEntry}");
                                entry = new DirectoryEntry(directoryEntry);
                                globalCatalogSearcher = new DirectorySearcher(entry);
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"[!] LDAP Error connecting to Global Catalog: {ex.Message.Trim()}");
                                string directoryEntry = $"LDAP://{arguments.dc}/DC={arguments.domain.Replace(".", ",DC=")}";
                                Console.WriteLine($"[+] Querying DC without Global Catalog: {directoryEntry}");
                                entry = new DirectoryEntry(directoryEntry);
                                globalCatalogSearcher = new DirectorySearcher(entry);
                            }
                        else
                        {
                            Forest currentForest = Forest.GetCurrentForest();
                            GlobalCatalog globalCatalog = currentForest.FindGlobalCatalog();
                            globalCatalogSearcher = globalCatalog.GetDirectorySearcher();
                        }
                        globalCatalogSearcher.PropertiesToLoad.Add("dnshostname");
                        globalCatalogSearcher.Filter = filter;
                        globalCatalogSearcher.SizeLimit = int.MaxValue;
                        globalCatalogSearcher.PageSize = int.MaxValue;
                        Console.WriteLine("[+] Performing LDAP query against Global Catalog for {0}...", description);
                        Console.WriteLine("[+] This may take some time depending on the size of the environment");
                        foreach (SearchResult resEnt in globalCatalogSearcher.FindAll())
                        {
                            //sometimes objects with empty attributes throw errors
                            try
                            {
                                string ComputerName = resEnt.Properties["dnshostname"][0].ToString().ToUpper();
                                ComputerNames.Add(ComputerName);
                            }
                            catch { /*nothing*/ }
                        }
                        globalCatalogSearcher.Dispose();
                    }
                    catch (Exception ex)
                    {
                        if (arguments.verbose)
                        {
                            Console.WriteLine("[!] LDAP Error searching Global Catalog: {0}", ex.Message);
                        }
                    }
                }
                else
                {
                    try
                    {
                        DirectoryEntry entry = null;
                        DirectorySearcher mySearcher = null;
                        if (!String.IsNullOrEmpty(arguments.dc) && !String.IsNullOrEmpty(arguments.domain))
                        {
                            string directoryEntry = $"LDAP://{arguments.dc}/DC={arguments.domain.Replace(".", ",DC=")}";
                            Console.WriteLine($"[+] Performing LDAP query against {directoryEntry} for {description}...");
                            Console.WriteLine("[+] This may take some time depending on the size of the environment");
                            entry = new DirectoryEntry(directoryEntry);
                            mySearcher = new DirectorySearcher(entry);

                        }
                        else
                        {
                            entry = new DirectoryEntry();
                            mySearcher = new DirectorySearcher(entry);
                        }
                        
                        mySearcher.PropertiesToLoad.Add("dnshostname");
                        mySearcher.Filter = filter;
                        mySearcher.SizeLimit = int.MaxValue;
                        mySearcher.PageSize = int.MaxValue;
                        Console.WriteLine("[+] Performing LDAP query against the current domain for {0}...", description);
                        Console.WriteLine("[+] This may take some time depending on the size of the environment");

                        foreach (SearchResult resEnt in mySearcher.FindAll())
                        {
                            //sometimes objects with empty attributes throw errors
                            try
                            {
                                string ComputerName = resEnt.Properties["dnshostname"][0].ToString().ToUpper();
                                ComputerNames.Add(ComputerName);
                            }
                            catch { /*nothing*/ }
                        }
                        mySearcher.Dispose();
                    }
                    catch (Exception ex)
                    {
                        if (arguments.verbose)
                        {
                            Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                        }
                    }
                }
                //localhost returns false positives
                ComputerNames.RemoveAll(u => u.Contains(System.Environment.MachineName.ToUpper()));
                Console.WriteLine("[+] LDAP Search Results: {0}", ComputerNames.Count.ToString());
                

                return ComputerNames;
            }
            catch (Exception ex)
            {
                if (arguments.verbose)
                {
                    Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                }
                return null;
            }
        }
        public static List<string> SearchOU(Utilities.Options.Arguments arguments)
        {
            try
            {
                List<string> ComputerNames = new List<string>();
                DirectoryEntry entry = null;
                DirectorySearcher mySearcher = null;
                if (!String.IsNullOrEmpty(arguments.dc) && !String.IsNullOrEmpty(arguments.domain))
                {
                    try
                    {
                        string directoryEntry = $"GC://{arguments.dc}/DC={arguments.domain.Replace(".", ",DC=")}";
                        Console.WriteLine($"[+] Attempting to connect to Global Catalog: {directoryEntry}");
                        entry = new DirectoryEntry(directoryEntry);
                        mySearcher = new DirectorySearcher(entry);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[!] LDAP Error connecting to Global Catalog: {ex.Message.Trim()}");
                        string directoryEntry = $"LDAP://{arguments.dc}/DC={arguments.domain.Replace(".", ",DC=")}";
                        Console.WriteLine($"[+] Querying DC without Global Catalog: {directoryEntry}");
                        entry = new DirectoryEntry(directoryEntry);
                        mySearcher = new DirectorySearcher(entry);
                    }
                }
                else
                {
                    string searchbase = "LDAP://" + arguments.ou;//OU=Domain Controllers,DC=example,DC=local";
                    entry = new DirectoryEntry(searchbase);
                    mySearcher = new DirectorySearcher(entry);
                }
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
                if (arguments.verbose)
                {
                    Console.WriteLine("[!] LDAP Error: {0}", ex.Message);
                }
                //Environment.Exit(0);
                return null;
            }
        }
    }
}
