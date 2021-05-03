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
            Utilities.Options.PrintOptions(arguments);
            if (!String.IsNullOrEmpty(arguments.ldap))
            {
                List<string> ldap = Utilities.LDAP.SearchLDAP(arguments.ldap, arguments.verbose);
                hosts = hosts.Concat(ldap).ToList();
            }
            if (!String.IsNullOrEmpty(arguments.ou))
            {
                List<string> ou = Utilities.LDAP.SearchOU(arguments.ou, arguments.verbose);
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