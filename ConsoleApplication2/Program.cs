using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using LSAController;
namespace TestRightsApp
{
    class Program
    {
        static void Main(string[] args)
        {
            LocalSecurityAuthorityController obj = new LocalSecurityAuthorityController();
            Console.WriteLine("Users with NT Right 'Interactive Logon'");
            System.Collections.Generic.IList<string> interactivelist = obj.GetAccountsWithRights("SeInteractiveLogonRight");
           for (int x = 0; x < interactivelist.Count; x++)
           {
                Console.WriteLine("{0}", interactivelist[x]);
           }
           Console.ReadKey();
            Console.WriteLine();
            Console.WriteLine("NT Rights for the Local Administrators Group");
           System.Collections.Generic.IList<string> administratorlist = obj.GetRights("Administrators");
           for (int x = 0; x < administratorlist.Count; x++)
           {
                Console.WriteLine("{0}", administratorlist[x]);
           }
           Console.ReadKey();
        }
    }
}
