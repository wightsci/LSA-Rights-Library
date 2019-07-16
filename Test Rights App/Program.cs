using System;
using LSAController;
namespace TestRightsApp
{
    class Program
    {
        static void Main(string[] args)
        {
            LocalSecurityAuthorityController obj = new LocalSecurityAuthorityController();
            Console.WriteLine("Users with NT Right 'Interactive Logon'");
            Console.WriteLine("=======================================");
            Console.WriteLine();
            System.Collections.Generic.IList<string> interactivelist = obj.GetAccountsWithRight("SeInteractiveLogonRight");
            for (int x = 0; x < interactivelist.Count; x++)
                {
                    Console.WriteLine("{0}", interactivelist[x]);
                }
            Console.ReadKey();
            Console.WriteLine();
            Console.WriteLine("NT Rights for the Local Administrators Group");
            Console.WriteLine("============================================");
            Console.WriteLine();
            System.Collections.Generic.IList<string> administratorlist = obj.GetRightsForAccount("Administrators");
            for (int x = 0; x < administratorlist.Count; x++)
                {
                    Console.WriteLine("{0}", administratorlist[x]);
                }
            Console.ReadKey();
        }
    }
}
