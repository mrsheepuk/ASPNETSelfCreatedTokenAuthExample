using System;
using System.IdentityModel.Tokens;
using Microsoft.AspNet.Authentication.OAuthBearer;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Hosting;
using Microsoft.Framework.DependencyInjection;
using System.Security.Cryptography;
using Microsoft.AspNet.Authorization;
using Microsoft.AspNet.Diagnostics;
using Newtonsoft.Json;
using Microsoft.AspNet.Http;

namespace TokenAuthExampleWebApplication
{
    public class Startup
    {
        const string TokenAudience = "ExampleAudience";
        const string TokenIssuer = "ExampleIssuer";

        public Startup(IHostingEnvironment env)
        {
        }

        public void ConfigureServices(IServiceCollection services)
        {
            RsaSecurityKey key;

            // Obviously, hard coding the private key here is a horrendous idea - this should be passed in from 
            // some sort of configuration file supplied securely to the application. This is just to prove the 
            // concept of the auth strategy.
            RSAParameters p = new RSAParameters()
            {
                Modulus = Convert.FromBase64String("z7eXmrs9z3Xm7VXwYIdziDYzXGfi3XQiozIRa58m3ApeLVDcsDeq6Iv8C5zJ2DHydDyc0x6o5dtTRIb23r5/ZRj4I/UwbgrwMk5iHA0bVsXVPBDSWsrVcPDGafr6YbUNQnNWIF8xOqgpeTwxrqGiCJMUjuKyUx01PBzpBxjpnQ++Ryz6Y7MLqKHxBkDiOw5wk9cxO8/IMspSNJJosOtRXFTR74+bj+pvNBa8IJ+5Jf/UfJEEjk+qC+pohCAryRk0ziXcPdxXEv5KGT4zf3LdtHy1YwsaGLnTb62vgbdqqCJaVyHWOoXsDTQBLjxNl9o9CzP6CrfBGK6JV8pA/xfQlw=="),
                Exponent = Convert.FromBase64String("AQAB"),
                P = Convert.FromBase64String("+VsETS2exORYlg2CxaRMzyG60dTfHSuv0CsfmO3PFv8mcYxglGa6bUV5VGtB6Pd1HdtV/iau1WR/hYXQphCP99Pu803NZvFvVi34alTFbh0LMfZ+2iQ9toGzVfO8Qdbj7go4TWoHNzCpG4UCx/9wicVIWJsNzkppSEcXYigADMM="),
                Q = Convert.FromBase64String("1UCJ2WAHasiCdwJtV2Ep0VCK3Z4rVFLWg3q1v5OoOU1CkX5/QAcrr6bX6zOdHR1bDCPsH1n1E9cCMvwakgi9M4Ch0dYF5CxDKtlx+IGsZJL0gB6HhcEsHat+yXUtOAlS4YB82G1hZqiDw+Q0O8LGyu/gLDPB+bn0HmbkUC2kP50="),
                DP = Convert.FromBase64String("CBqvLxr2eAu73VSfFXFblbfQ7JTwk3AiDK/6HOxNuL+eLj6TvP8BvB9v7BB4WewBAHFqgBIdyI21n09UErGjHDjlIT88F8ZtCe4AjuQmboe/H2aVhN18q/vXKkn7qmAjlE78uXdiuKZ6OIzAJGPm8nNZAJg5gKTmexTka6pFJiU="),
                DQ = Convert.FromBase64String("ND6zhwX3yzmEfROjJh0v2ZAZ9WGiy+3fkCaoEF9kf2VmQa70DgOzuDzv+TeT7mYawEasuqGXYVzztPn+qHhrogqJmpcMqnINopnTSka6rYkzTZAtM5+35yz0yvZiNbBTFdwcuglSK4xte7iU828stNs/2JR1mXDtVeVvWhVUgCE="),
                InverseQ = Convert.FromBase64String("Heo0BHv685rvWreFcI5MXSy3AN0Zs0YbwAYtZZd1K/OzFdYVdOnqw+Dg3wGU9yFD7h4icJFwZUBGOZ0ww/gZX/5ZgJK35/YY/DeV+qfZmywKauUzC6+DPsrDdW1uf1eAety6/huRZTduBFTwIOlPdZ+PY49j6S38DjPFNImn0cU="),
                D = Convert.FromBase64String("IvjMI5cGzxkQqkDf2cC0aOiHOTWccqCM/GD/odkH1+A+/u4wWdLliYWYB/R731R5d6yE0t7EnP6SRGVcxx/XnxPXI2ayorRgwHeF+ScTxUZFonlKkVK5IOzI2ysQYMb01o1IoOamCTQq12iVDMvV1g+9VFlCoM+4GMjdSv6cxn6ELabuD4nWt8tCskPjECThO+WdrknbUTppb2rRgMvNKfsPuF0H7+g+WisbzVS+UVRvJe3U5O5X5j7Z82Uq6hw2NCwv2YhQZRo/XisFZI7yZe0OU2JkXyNG3NCk8CgsM9yqX8Sk5esXMZdJzjwXtEpbR7FiKZXiz9LhPSmzxz/VsQ==")
            };

            key = new RsaSecurityKey(p);

            // Add the signing credentials so we can access them in the controller that doles out the tokens.
            services.AddInstance(new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest));

            // Configure the bearer token validation to use the supplied key, and validate the 
            // lifetime and signature when a key is supplied.
            // *** 
            // NOTE: OAuthBearerAuthentication will be renamed to JwtBearerAuthentication in 
            // ASP.NET 5 Beta 8 - be ready to change this then!! 
            // ***
            services.Configure<OAuthBearerAuthenticationOptions>(bearer =>
            {
                // Basic settings - signing key to validate with, audience and issuer.
                bearer.TokenValidationParameters.IssuerSigningKey = key;
                bearer.TokenValidationParameters.ValidAudience = TokenAudience;
                bearer.TokenValidationParameters.ValidIssuer = TokenIssuer;

                // When receiving a token, check that we've signed it.
                bearer.TokenValidationParameters.ValidateSignature = true;

                // When receiving a token, check that it is still valid.
                bearer.TokenValidationParameters.ValidateLifetime = true;

                // This defines the maximum allowable clock skew - i.e. provides a tolerance on the token expiry time 
                // when validating the lifetime. As we're creating the tokens locally and validating them on the same 
                // machines which should have synchronised time, this can be set to zero. Where external tokens are
                // used, some leeway here could be useful.
                bearer.TokenValidationParameters.ClockSkew = TimeSpan.FromMinutes(0);
            });

            // Enable the use of an [Authorize("Bearer")] attribute on methods and classes to protect.
            services.ConfigureAuthorization(auth =>
            {
                auth.AddPolicy("Bearer", new AuthorizationPolicyBuilder()
                    .AddAuthenticationSchemes(OAuthBearerAuthenticationDefaults.AuthenticationScheme‌​)
                    .RequireAuthenticatedUser().Build());
            });

            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            // Register a simple error handler to catch token expiries and change them to a 401, 
            // and return all other errors as a 500.
            app.UseErrorHandler(appBuilder =>
            {
                appBuilder.Use(new Func<RequestDelegate, RequestDelegate>((RequestDelegate next) =>
                {
                    return async (HttpContext context) =>
                    {
                        var error = context.GetFeature<IErrorHandlerFeature>();
                        // This should be much more intelligent - at the moment only expired 
                        // security tokens are caught - might be worth checking other possible 
                        // exceptions such as an invalid signature.
                        if (error != null && error.Error is SecurityTokenExpiredException)
                        {
                            context.Response.StatusCode = 401;
                            // What you choose to return here is up to you, in this case a simple 
                            // bit of JSON to say you're no longer authenticated.
                            context.Response.ContentType = "application/json";
                            await context.Response.WriteAsync(
                                JsonConvert.SerializeObject(new { authenticated = false, tokenExpired = true }));
                        }
                        else if (error != null && error.Error != null)
                        {
                            context.Response.StatusCode = 500;
                            context.Response.ContentType = "application/json";
                            await context.Response.WriteAsync(
                                JsonConvert.SerializeObject(new { success = false, error = error.Error.Message }));
                        }
                        // We're not trying to handle any other errors so just let the default 
                        // handler handle.
                        else await next(context);
                    };
                }));
            });

            // *** 
            // NOTE: OAuthBearerAuthentication will be renamed to JwtBearerAuthentication in 
            // ASP.NET 5 Beta 8 - be ready to change this then!! 
            // ***
            app.UseOAuthBearerAuthentication();

            // Configure the HTTP request pipeline.
            app.UseStaticFiles();
            
            // Add MVC to the request pipeline.
            app.UseMvc();
        }
    }
}
