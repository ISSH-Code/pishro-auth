using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Pishro.Auth.Application.Services;
using Pishro.Auth.Infrastructure.Persistence;

namespace Pishro.Auth.Server.Endpoints;

public static class ConnectEndpoints
{
    private const string RolesScope = "roles";
    private const string VettingStatusScope = "vetting_status";

    public static void MapConnectEndpoints(this WebApplication app)
    {
        app.MapMethods("/connect/authorize", [HttpMethods.Get, HttpMethods.Post],
            (Delegate)(async (HttpContext httpContext, AuthDbContext db, IClaimsEnrichmentService enrichment) =>
                await HandleAuthorize(httpContext, db, enrichment)));
        app.MapPost("/connect/token",
            (Delegate)(async (HttpContext httpContext) => await HandleToken(httpContext)));
        app.MapMethods("/connect/userinfo", [HttpMethods.Get, HttpMethods.Post],
            (Delegate)((HttpContext httpContext) => HandleUserInfo(httpContext)));
        app.MapMethods("/connect/logout", [HttpMethods.Get, HttpMethods.Post],
            (Delegate)(async (HttpContext httpContext) => await HandleLogout(httpContext)));
    }

    private static async Task<IResult> HandleAuthorize(
        HttpContext httpContext, AuthDbContext db, IClaimsEnrichmentService enrichment)
    {
        var request = httpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Check if user is authenticated via cookie
        var cookieResult = await httpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (!cookieResult.Succeeded || cookieResult.Principal is null)
        {
            // Redirect to login page with returnUrl
            var returnUrl = httpContext.Request.PathBase + httpContext.Request.Path + httpContext.Request.QueryString;
            return Results.Redirect($"/login.html?returnUrl={Uri.EscapeDataString(returnUrl)}");
        }

        var userId = cookieResult.Principal.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? cookieResult.Principal.FindFirstValue("sub");

        if (string.IsNullOrEmpty(userId))
            return Results.Redirect("/login.html");

        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == Guid.Parse(userId));
        if (user is null)
            return Results.Redirect("/login.html");

        // Build standard claims from the User entity
        var claims = new List<Claim>
        {
            new(OpenIddictConstants.Claims.Subject, user.Id.ToString())
        };

        if (!string.IsNullOrEmpty(user.DisplayName))
            claims.Add(new Claim(OpenIddictConstants.Claims.Name, user.DisplayName));
        if (!string.IsNullOrEmpty(user.Nickname))
            claims.Add(new Claim(OpenIddictConstants.Claims.Nickname, user.Nickname));
        if (!string.IsNullOrEmpty(user.Email))
        {
            claims.Add(new Claim(OpenIddictConstants.Claims.Email, user.Email));
            claims.Add(new Claim(OpenIddictConstants.Claims.EmailVerified, user.EmailVerified.ToString().ToLower()));
        }
        if (!string.IsNullOrEmpty(user.Phone))
        {
            claims.Add(new Claim(OpenIddictConstants.Claims.PhoneNumber, user.Phone));
            claims.Add(new Claim(OpenIddictConstants.Claims.PhoneNumberVerified, user.PhoneVerified.ToString().ToLower()));
        }
        if (!string.IsNullOrEmpty(user.FirstName))
            claims.Add(new Claim(OpenIddictConstants.Claims.GivenName, user.FirstName));
        if (!string.IsNullOrEmpty(user.LastName))
            claims.Add(new Claim(OpenIddictConstants.Claims.FamilyName, user.LastName));
        if (!string.IsNullOrEmpty(user.AvatarUrl))
            claims.Add(new Claim(OpenIddictConstants.Claims.Picture, user.AvatarUrl));

        // Enrich with HRMS roles/vetting_status when those scopes are requested
        if (request.HasScope(RolesScope) || request.HasScope(VettingStatusScope))
        {
            var enrichedClaims = await enrichment.GetEnrichedClaimsAsync(user.Id, httpContext.RequestAborted);
            claims.AddRange(enrichedClaims);
        }

        var identity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        // Carry the granted scopes on the principal so HandleToken can compute
        // destinations correctly. The token endpoint request has no `scope`
        // parameter, so reading scopes off `request` there returns nothing and
        // the id_token would only contain `sub`.
        principal.SetScopes(request.GetScopes());

        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(GetDestinations(claim, principal));
        }

        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static async Task<IResult> HandleToken(HttpContext httpContext)
    {
        var request = httpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsAuthorizationCodeGrantType())
        {
            var result = await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var principal = result.Principal
                ?? throw new InvalidOperationException("The authorization code is no longer valid.");

            // Recompute destinations from the principal's granted scopes
            // (carried from HandleAuthorize via the authorization code).
            foreach (var claim in principal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim, principal));
            }

            return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }

    private static IResult HandleUserInfo(HttpContext httpContext)
    {
        var claimsPrincipal = httpContext.User;

        var claims = new Dictionary<string, object>();

        var subject = claimsPrincipal.FindFirstValue(OpenIddictConstants.Claims.Subject);
        if (subject is not null) claims["sub"] = subject;

        var name = claimsPrincipal.FindFirstValue(OpenIddictConstants.Claims.Name);
        if (name is not null) claims["name"] = name;

        var nickname = claimsPrincipal.FindFirstValue(OpenIddictConstants.Claims.Nickname);
        if (nickname is not null) claims["nickname"] = nickname;

        var givenName = claimsPrincipal.FindFirstValue(OpenIddictConstants.Claims.GivenName);
        if (givenName is not null) claims["given_name"] = givenName;

        var familyName = claimsPrincipal.FindFirstValue(OpenIddictConstants.Claims.FamilyName);
        if (familyName is not null) claims["family_name"] = familyName;

        var picture = claimsPrincipal.FindFirstValue(OpenIddictConstants.Claims.Picture);
        if (picture is not null) claims["picture"] = picture;

        var email = claimsPrincipal.FindFirstValue(OpenIddictConstants.Claims.Email);
        if (email is not null) claims["email"] = email;

        var emailVerified = claimsPrincipal.FindFirstValue(OpenIddictConstants.Claims.EmailVerified);
        if (emailVerified is not null) claims["email_verified"] = emailVerified == "true";

        var phone = claimsPrincipal.FindFirstValue(OpenIddictConstants.Claims.PhoneNumber);
        if (phone is not null) claims["phone_number"] = phone;

        var phoneVerified = claimsPrincipal.FindFirstValue(OpenIddictConstants.Claims.PhoneNumberVerified);
        if (phoneVerified is not null) claims["phone_number_verified"] = phoneVerified == "true";

        // Include enriched claims (roles, vetting_status)
        var roles = claimsPrincipal.FindAll("role").Select(c => c.Value).ToArray();
        if (roles.Length > 0) claims["roles"] = roles;

        var vettingStatus = claimsPrincipal.FindFirstValue("vetting_status");
        if (vettingStatus is not null) claims["vetting_status"] = vettingStatus;

        var tenantId = claimsPrincipal.FindFirstValue("tenant_id");
        if (tenantId is not null) claims["tenant_id"] = tenantId;

        return Results.Ok(claims);
    }

    private static async Task<IResult> HandleLogout(HttpContext httpContext)
    {
        await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Results.SignOut(
            null,
            [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }

    private static ImmutableArray<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
    {
        return claim.Type switch
        {
            OpenIddictConstants.Claims.Subject => [
                OpenIddictConstants.Destinations.AccessToken,
                OpenIddictConstants.Destinations.IdentityToken
            ],

            OpenIddictConstants.Claims.Name or
            OpenIddictConstants.Claims.Nickname or
            OpenIddictConstants.Claims.GivenName or
            OpenIddictConstants.Claims.FamilyName or
            OpenIddictConstants.Claims.Picture
                when principal.HasScope(OpenIddictConstants.Scopes.Profile) => [
                    OpenIddictConstants.Destinations.AccessToken,
                    OpenIddictConstants.Destinations.IdentityToken
                ],

            OpenIddictConstants.Claims.Email or
            OpenIddictConstants.Claims.EmailVerified
                when principal.HasScope(OpenIddictConstants.Scopes.Email) => [
                    OpenIddictConstants.Destinations.AccessToken,
                    OpenIddictConstants.Destinations.IdentityToken
                ],

            OpenIddictConstants.Claims.PhoneNumber or
            OpenIddictConstants.Claims.PhoneNumberVerified
                when principal.HasScope(OpenIddictConstants.Scopes.Phone) => [
                    OpenIddictConstants.Destinations.AccessToken,
                    OpenIddictConstants.Destinations.IdentityToken
                ],

            // HRMS-specific claims: roles, permissions, vetting_status, tenant_id
            "role" when principal.HasScope(RolesScope) => [
                OpenIddictConstants.Destinations.AccessToken,
                OpenIddictConstants.Destinations.IdentityToken
            ],

            "hrms_access" when principal.HasScope(RolesScope) => [
                OpenIddictConstants.Destinations.AccessToken,
                OpenIddictConstants.Destinations.IdentityToken
            ],

            "has_sensitive_access" when principal.HasScope(RolesScope) => [
                OpenIddictConstants.Destinations.AccessToken,
                OpenIddictConstants.Destinations.IdentityToken
            ],

            "vetting_status" when principal.HasScope(VettingStatusScope) || principal.HasScope(RolesScope) => [
                OpenIddictConstants.Destinations.AccessToken,
                OpenIddictConstants.Destinations.IdentityToken
            ],

            "tenant_id" when principal.HasScope(RolesScope) => [
                OpenIddictConstants.Destinations.AccessToken,
                OpenIddictConstants.Destinations.IdentityToken
            ],

            _ => []
        };
    }
}
