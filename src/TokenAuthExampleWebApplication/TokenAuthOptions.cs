using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace TokenAuthExampleWebApplication
{
    public class TokenAuthOptions
    {
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public CspParameters KeyContainerParams { get; set; }
    }
}
