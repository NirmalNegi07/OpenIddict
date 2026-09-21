using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Lighthouse.Controllers;

public class AuthorizationController : Controller
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IOpenIddictScopeManager _scopeManager;

    public AuthorizationController(
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        IOpenIddictScopeManager scopeManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _scopeManager = scopeManager;
    }

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // If the user isn't authenticated with the cookie login scheme, redirect them to the
        // Lighthouse login page. After a successful login they are bounced back here.
        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (result is not { Succeeded: true })
        {
            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                        Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList()),
                });
        }

        var user = await _userManager.GetUserAsync(result.Principal) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");

        // This is a single trusted first-party client (Product A), so we skip the interactive
        // consent screen and issue the authorization code right away.
        var principal = await _signInManager.CreateUserPrincipalAsync(user);

        // CreateUserPrincipalAsync() populates claims using ASP.NET Core Identity's default
        // (long-form XML schema) claim types. OpenIddict requires its own short claim types
        // instead -- "sub" in particular is mandatory on every principal it signs in.
        principal.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user));
        principal.SetClaim(Claims.Email, await _userManager.GetEmailAsync(user));
        principal.SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user));
        principal.SetClaim(Claims.PreferredUsername, await _userManager.GetUserNameAsync(user));

        principal.SetScopes(request.GetScopes());

        var resources = new List<string>();
        await foreach (var resource in _scopeManager.ListResourcesAsync(request.GetScopes()))
        {
            resources.Add(resource);
        }
        principal.SetResources(resources);

        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(GetDestinations(claim, principal));
        }

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // The authorization code / refresh token is validated by the OpenIddict server
            // middleware before this action is even reached, and the resulting principal is
            // exactly what we attached to it in the Authorize action above -- scopes and
            // resources (i.e. the "aud" claim) included. Re-using it (rather than building a
            // fresh one) is what keeps those intact across the exchange.
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var principal = result.Principal!;

            var user = await _userManager.GetUserAsync(principal);
            if (user is null || !await _signInManager.CanSignInAsync(user))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The token is no longer valid.",
                    }));
            }

            foreach (var claim in principal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim, principal));
            }

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new NotImplementedException("The specified grant type is not implemented.");
    }

    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo")]
    [HttpPost("~/connect/userinfo")]
    public async Task<IActionResult> Userinfo()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return Challenge(
                authenticationSchemes: OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictValidationAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                }));
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.Subject] = user.Id,
        };

        if (User.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = user.Email!;
            claims[Claims.EmailVerified] = user.EmailConfirmed;
        }

        if (User.HasScope(Scopes.Profile))
        {
            claims[Claims.PreferredUsername] = user.UserName!;
        }

        return Ok(claims);
    }

    private static IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
    {
        // Access tokens are consumed directly by Product A's Express backend (a resource
        // server outside this app), so the claims it needs must be pushed into the access
        // token, not just the identity token that only Lighthouse itself would see.
        switch (claim.Type)
        {
            case Claims.Name or Claims.PreferredUsername:
                yield return Destinations.AccessToken;
                if (principal.HasScope(Scopes.Profile))
                {
                    yield return Destinations.IdentityToken;
                }
                yield break;

            case Claims.Email:
                yield return Destinations.AccessToken;
                if (principal.HasScope(Scopes.Email))
                {
                    yield return Destinations.IdentityToken;
                }
                yield break;

            case Claims.Role:
                yield return Destinations.AccessToken;
                if (principal.HasScope(Scopes.Roles))
                {
                    yield return Destinations.IdentityToken;
                }
                yield break;

            // Never include the security stamp in the access or identity tokens, as it's a
            // secret value.
            case "AspNet.Identity.SecurityStamp":
                yield break;

            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }
}
