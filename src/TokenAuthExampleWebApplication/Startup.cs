using System;
using System.IdentityModel.Tokens;
using Microsoft.AspNet.Authentication.JwtBearer;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Hosting;
using System.Security.Cryptography;
using Microsoft.AspNet.Authorization;
using Microsoft.AspNet.Diagnostics;
using Newtonsoft.Json;
using Microsoft.AspNet.Http;
using Microsoft.Extensions.DependencyInjection;
using System.IdentityModel.Tokens.Jwt;
using System.IO;

namespace TokenAuthExampleWebApplication
{
    public class Startup
    {
        const string TokenAudience = "ExampleAudience";
        const string TokenIssuer = "ExampleIssuer";
        public const string KeyContainerName = "TokenAuthExample";
        private TokenAuthOptions tokenOptions;

        public Startup(IHostingEnvironment env)
        {
        }

        public void ConfigureServices(IServiceCollection services)
        {
            // Prepare some common options that we'll need for both signing and checking
            // the tokens.
            tokenOptions = new TokenAuthOptions()
            {
                Audience = TokenAudience,
                Issuer = TokenIssuer,
                KeyContainerParams = new CspParameters() { KeyContainerName = KeyContainerName }
            };

            // Save the token options into an instance so they're accessible to the 
            // controller.
            services.AddInstance<TokenAuthOptions>(tokenOptions);

            // Enable the use of an [Authorize("Bearer")] attribute on methods and classes to protect.
            services.AddAuthorization(auth =>
            {
                auth.AddPolicy("Bearer", new AuthorizationPolicyBuilder()
                    .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme‌​)
                    .RequireAuthenticatedUser().Build());
            });

            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseIISPlatformHandler();

            // Register a simple error handler to catch token expiries and change them to a 401, 
            // and return all other errors as a 500. This should almost certainly be improved for
            // a real application.
            app.UseExceptionHandler(appBuilder =>
            {
                appBuilder.Use(async (context, next) =>
                {
                    var error = context.Features[typeof(IExceptionHandlerFeature)] as IExceptionHandlerFeature;
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
                            JsonConvert.SerializeObject(
                                new { authenticated = false, tokenExpired = true }));
                    }
                    else if (error != null && error.Error != null)
                    {
                        context.Response.StatusCode = 500;
                        context.Response.ContentType = "application/json";
                        // TODO: Shouldn't pass the exception message straight out, change this.
                        await context.Response.WriteAsync(
                            JsonConvert.SerializeObject
                            (new { success = false, error = error.Error.Message }));
                    }
                    // We're not trying to handle anything else so just let the default 
                    // handler handle.
                    else await next();
                });
            });

            app.UseJwtBearerAuthentication(options =>
            {
                // Basic settings - retrieve the key to validate the data with, and set the expected 
                // audience and issuer.
                options.TokenValidationParameters.IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
                {
                    // Load the key from the RSA crypto service provider using our configured
                    // key container params, so as to retrieve the same key we've used to sign 
                    // the token in TokenController.
                    using (RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider(2048, tokenOptions.KeyContainerParams))
                    {
                        return new SecurityKey[] { new RsaSecurityKey(rsaCsp.ExportParameters(true)) };
                    }
                };
                options.TokenValidationParameters.ValidAudience = tokenOptions.Audience;
                options.TokenValidationParameters.ValidIssuer = tokenOptions.Issuer;

                // When receiving a token, check that we've signed it.
                options.TokenValidationParameters.ValidateSignature = true;

                // When receiving a token, check that it is still valid.
                options.TokenValidationParameters.ValidateLifetime = true;

                // This defines the maximum allowable clock skew - i.e. provides a tolerance on the token expiry time 
                // when validating the lifetime. As we're creating the tokens locally and validating them on the same 
                // machines which should have synchronised time, this can be set to zero. Where external tokens are
                // used, some leeway here could be useful.
                options.TokenValidationParameters.ClockSkew = TimeSpan.FromMinutes(0);
            });

            // Configure the HTTP request pipeline.
            app.UseStaticFiles();
            
            // Add MVC to the request pipeline.
            app.UseMvc();
        }

        public static void Main(string[] args) => WebApplication.Run(args);
    }
}
