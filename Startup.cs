using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Azure.Storage;
using Microsoft.Azure.Storage.Blob;

using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;

namespace WebApp_OpenIDConnect_DotNet
{
    public class Startup
    {
        private ILogger _logger;

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
                .AddMicrosoftIdentityWebApp(Configuration.GetSection("AzureAd"));

            services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                options.Events = new OpenIdConnectEvents
                {

                    OnRedirectToIdentityProvider = (context) =>
                    {
                        if (context.Request.Headers.ContainsKey("X-Forwarded-Host"))
                        {
                            context.ProtocolMessage.RedirectUri = "https://" + context.Request.Headers["X-Forwarded-Host"] + Configuration.GetSection("AzureAd").GetValue<String>("CallbackPath");
                        }
                        return Task.FromResult(0);
                    }
                };
            });

            services.AddControllersWithViews(options =>
            {
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
                options.Filters.Add(new AuthorizeFilter(policy));
            });
           services.AddRazorPages()
                .AddMicrosoftIdentityUI();

            // create a blob storage container to use as the central, cross-node DataProtection key holder
            string AppStorageAccountConnectionString = Configuration.GetSection("DataProtection").GetValue<String>("AppStorageAccountConnectionString");
            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(AppStorageAccountConnectionString);
            CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();            
            CloudBlobContainer blobContainer =
                blobClient.GetContainerReference(Configuration.GetSection("DataProtection").GetValue<String>("BlobContainer"));
            blobContainer.CreateIfNotExistsAsync().GetAwaiter().GetResult();

            // WARNING: keys in keys.xml are not encrypted at rest, by default
            // To make this production ready, add an encryption cert here so they will be, via .ProtectKeysWithCertificate("certthumbprint")
            services.AddDataProtection(options =>
            {
                options.ApplicationDiscriminator = "sahilfrontdoor";
            })
            .PersistKeysToAzureBlobStorage(AppStorageAccountConnectionString, "dataprotection", "keys.xml");

            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders =
                    ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILogger<Startup> logger)
        {
            _logger = logger;
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });

            app.UseForwardedHeaders();

            app.Run(async (context) =>
            {
                context.Response.ContentType = "text/plain";

                // Request method, scheme, and path
                await context.Response.WriteAsync(
                    $"Request Method: {context.Request.Method}{Environment.NewLine}");
                await context.Response.WriteAsync(
                    $"Request Scheme: {context.Request.Scheme}{Environment.NewLine}");
                await context.Response.WriteAsync(
                    $"Request Path: {context.Request.Path}{Environment.NewLine}");

                // Headers
                await context.Response.WriteAsync($"Request Headers:{Environment.NewLine}");

                foreach (var header in context.Request.Headers)
                {
                    await context.Response.WriteAsync($"{header.Key}: " +
                        $"{header.Value}{Environment.NewLine}");
                }

                await context.Response.WriteAsync(Environment.NewLine);

                // Connection: RemoteIp
                await context.Response.WriteAsync(
                    $"Request RemoteIp: {context.Connection.RemoteIpAddress}");
            });
        }
    }
}
