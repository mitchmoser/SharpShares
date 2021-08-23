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
            if (arguments != null)
            {
                bool success = Utilities.Options.PrintOptions(arguments);
                if (success)
                {
                    if (!String.IsNullOrEmpty(arguments.ldap))
                    {
                        List<string> ldap = Utilities.LDAP.SearchLDAP(arguments);
                        if (ldap != null)
                            hosts = hosts.Concat(ldap).ToList();
                    }
                    if (!String.IsNullOrEmpty(arguments.ou))
                    {
                        List<string> ou = Utilities.LDAP.SearchOU(arguments);
                        if (ou != null) 
                            hosts = hosts.Concat(ou).ToList();
                    }
                    //remove duplicate hosts
                    hosts = hosts.Distinct().ToList();
                    Utilities.Status.totalCount = hosts.Count;
                    Utilities.Status.StartOutputTimer();
                    Enums.Shares.GetAllShares(hosts, arguments);
                }
            }
        }
    }
}