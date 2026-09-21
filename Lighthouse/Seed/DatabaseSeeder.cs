using Lighthouse.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

namespace Lighthouse.Seed;

public static class DatabaseSeeder
{
    public static async Task SeedAsync(IServiceProvider services, IConfiguration configuration)
    {
        var dbContext = services.GetRequiredService<LighthouseDbContext>();
        await dbContext.Database.MigrateAsync();

        await SeedProductAApiScopeAsync(services);
        await SeedProductAClientAsync(services, configuration);
        await SeedTestUserAsync(services);
    }

    private static async Task SeedProductAApiScopeAsync(IServiceProvider services)
    {
        var scopeManager = services.GetRequiredService<IOpenIddictScopeManager>();

        const string scopeName = "product_a_api";

        if (await scopeManager.FindByNameAsync(scopeName) is not null)
        {
            return;
        }

        // The scope's Resources value is what ends up as the "aud" claim on access tokens
        // that include this scope -- it's what Product A's Express backend checks when it
        // verifies a token was actually meant for it.
        await scopeManager.CreateAsync(new OpenIddictScopeDescriptor
        {
            Name = scopeName,
            DisplayName = "Product A API",
            Resources = { scopeName },
        });
    }

    private static async Task SeedProductAClientAsync(IServiceProvider services, IConfiguration configuration)
    {
        var applicationManager = services.GetRequiredService<IOpenIddictApplicationManager>();

        var clientId = configuration["ProductAClient:ClientId"]!;
        var clientSecret = configuration["ProductAClient:ClientSecret"]!;
        var redirectUri = configuration["ProductAClient:RedirectUri"]!;
        var postLogoutRedirectUri = configuration["ProductAClient:PostLogoutRedirectUri"]!;

        if (await applicationManager.FindByClientIdAsync(clientId) is not null)
        {
            return;
        }

        await applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            DisplayName = "Product A (Express backend)",
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            RedirectUris = { new Uri(redirectUri) },
            PostLogoutRedirectUris = { new Uri(postLogoutRedirectUri) },
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.Prefixes.Scope + "product_a_api",
            },
            Requirements =
            {
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange,
            },
        });
    }

    private static async Task SeedTestUserAsync(IServiceProvider services)
    {
        var userManager = services.GetRequiredService<UserManager<IdentityUser>>();

        const string email = "test@lighthouse.local";
        const string password = "Passw0rd!";

        if (await userManager.FindByEmailAsync(email) is not null)
        {
            return;
        }

        var user = new IdentityUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
        };

        var result = await userManager.CreateAsync(user, password);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                $"Failed to seed test user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
        }
    }
}
