using Lighthouse.Data;
using Lighthouse.Seed;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection()
    .SetApplicationName("Lighthouse")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(builder.Environment.ContentRootPath, "DataProtection-Keys")));

var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException("The 'Default' connection string is missing.");

builder.Services.AddDbContext<LighthouseDbContext>(options =>
{
    options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));

    // Registers the OpenIddict entity sets needed by the EF Core stores.
    options.UseOpenIddict();
});

builder.Services
    .AddIdentity<IdentityUser, IdentityRole>(options =>
    {
        options.Password.RequiredLength = 8;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequireUppercase = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireDigit = true;
        options.User.RequireUniqueEmail = true;
    })
    .AddEntityFrameworkStores<LighthouseDbContext>()
    .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
});

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore().UseDbContext<LighthouseDbContext>();
    })
    .AddServer(options =>
    {
        options
            .SetAuthorizationEndpointUris("connect/authorize")
            .SetTokenEndpointUris("connect/token")
            .SetUserInfoEndpointUris("connect/userinfo");

        options
            .AllowAuthorizationCodeFlow()
                .RequireProofKeyForCodeExchange()
            .AllowRefreshTokenFlow();

        options.RegisterScopes(
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.Roles,
            OpenIddictConstants.Scopes.OfflineAccess,
            "product_a_api");

        // Ephemeral in-memory signing/encryption keys: regenerated on every restart (so
        // tokens issued before a restart stop validating), and avoid touching the macOS
        // Keychain/X509 store the way AddDevelopmentEncryptionCertificate() does. Replace
        // with a persisted certificate before this runs anywhere but a laptop.
        options
            .AddEphemeralEncryptionKey()
            .AddEphemeralSigningKey();

        // Access tokens are consumed directly (as JWTs, verified against the JWKS endpoint)
        // by Product A's Express backend, which isn't a .NET/OpenIddict resource server, so
        // we keep them as unencrypted, self-contained JWTs instead of encrypted references.
        options.DisableAccessTokenEncryption();

        options
            .UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableUserInfoEndpointPassthrough();

        if (builder.Environment.IsDevelopment())
        {
            // This experiment runs Lighthouse over plain HTTP locally so the Express/React
            // client doesn't need to trust a local dev HTTPS certificate. Never do this
            // outside local development.
            options.UseAspNetCore().DisableTransportSecurityRequirement();
        }
    })
    .AddValidation(options =>
    {
        // Reuses the local server's signing configuration instead of calling an
        // introspection endpoint, since the server lives in this same app.
        options.UseLocalServer();
        options.UseAspNetCore();
    });

builder.Services.AddRazorPages();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();

using (var scope = app.Services.CreateScope())
{
    await DatabaseSeeder.SeedAsync(scope.ServiceProvider, app.Configuration);
}

app.Run();
