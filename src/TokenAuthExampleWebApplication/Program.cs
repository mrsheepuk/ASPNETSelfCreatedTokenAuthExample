using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace TokenAuthExampleWebApplication
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length >= 1)
            {
                if (args[0] == "generateKey")
                {
                    string jsonExportFile = null;
                    if (args.Length >= 2) jsonExportFile = args[1];
                    RSAKeyUtils.GenerateKey(Startup.KeyContainerName, jsonExportFile);
                    Console.WriteLine("Key generated (and saved if requested)");
                    return;
                }
                else if (args[0] == "importKey" && args.Length >= 2 && File.Exists(args[1]))
                {
                    RSAKeyUtils.ImportKeyAndStoreInCSP(Startup.KeyContainerName, args[1]);
                    Console.WriteLine("Key imported.");
                    return;
                }
                else if (args[0] == "clearKeys")
                {
                    RSAKeyUtils.ClearSavedKey(Startup.KeyContainerName);
                    Console.WriteLine("Key exported.");
                    return;
                }
            }
            Console.WriteLine("Usage: dnx key generateKey [optional export key file name]");
            Console.WriteLine("Usage: dnx key importKey [import key file name]");
            Console.WriteLine("Usage: dnx key clearKeys");
        }
    }
}
