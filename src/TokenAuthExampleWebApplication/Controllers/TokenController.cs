using System;
using System.Linq;
using Microsoft.AspNet.Mvc;
using Microsoft.AspNet.Authentication.OAuthBearer;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.AspNet.Authorization;
using Microsoft.Framework.OptionsModel;
using System.Security.Principal;

namespace TokenAuthExampleWebApplication.Controllers
{
    [Route("api/[controller]")]
    public class TokenController : Controller
    {
        private readonly OAuthBearerAuthenticationOptions bearerOptions;
        private readonly SigningCredentials signingCredentials;

        public TokenController(IOptions<OAuthBearerAuthenticationOptions> options, SigningCredentials signingCredentials)
        {
            this.bearerOptions = options.Options;
            this.signingCredentials = signingCredentials;
        }

        /// <summary>
        /// Check if currently authenticated. Will throw an exception of some sort which shoudl be caught by a general
        /// exception handler and returned to the user as a 401, if not authenticated. Will return a fresh token if
        /// the user is authenticated, which will reset the expiry.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Authorize("Bearer")]
        public dynamic Get()
        {
            bool authenticated = false;
            string user = null;
            int entityId = -1;
            string token = null;
            DateTime? tokenExpires = default(DateTime?);

            var currentUser = Context.User;
            if (currentUser != null)
            {
                authenticated = currentUser.Identity.IsAuthenticated;
                if (authenticated)
                {
                    user = currentUser.Identity.Name;
                    foreach (Claim c in currentUser.Claims) if (c.Type == "EntityID") entityId = Convert.ToInt32(c.Value);
                    tokenExpires = DateTime.UtcNow.AddMinutes(2);
                    token = GetToken(currentUser.Identity.Name, tokenExpires);
                }
            }
            return new { authenticated = authenticated, user = user, entityId = entityId, token = token, tokenExpires = tokenExpires };
        }

        public class AuthRequest
        {
            public string username { get; set; }
            public string password { get; set; }
        }

        /// <summary>
        /// Request a new token for a given username/password pair.
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        [HttpPost]
        public dynamic Post([FromBody] AuthRequest req)
        {
            // Obviously, at this point you need to validate the username and password against whatever system you wish.
            if ((req.username == "TEST" && req.password == "TEST") || (req.username == "TEST2" && req.password == "TEST"))
            {
                DateTime? expires = DateTime.UtcNow.AddMinutes(2);
                var token = GetToken(req.username, expires);
                return new { authenticated = true, entityId = 1, token = token, tokenExpires = expires };
            }
            return new { authenticated = false };
        }

        private string GetToken(string user, DateTime? expires)
        {
            var handler = bearerOptions.SecurityTokenValidators.OfType<System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler>()
                .First();

            // Here, you should create or look up an identity for the user which is being authenticated.
            // For now, just creating a simple generic identity.
            ClaimsIdentity identity = new ClaimsIdentity(new GenericIdentity(user, "TokenAuth"), new[] { new Claim("EntityID", "1", ClaimValueTypes.Integer) });

            var securityToken = handler.CreateToken(
                issuer: bearerOptions.TokenValidationParameters.ValidIssuer,
                audience: bearerOptions.TokenValidationParameters.ValidAudience,
                signingCredentials: signingCredentials,
                subject: identity,
                expires: expires
                );
            return handler.WriteToken(securityToken);
        }
    }
}
