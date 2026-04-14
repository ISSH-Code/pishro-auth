using OpenIddict.Abstractions;

namespace Pishro.Auth.Infrastructure.Seed;

public class ClientSeeder(
    IOpenIddictApplicationManager manager,
    IOpenIddictScopeManager scopes)
{
    public async Task SeedAsync(CancellationToken ct = default)
    {
        // Custom scopes used by the HRMS client — must exist before a client
        // can request them, otherwise OpenIddict rejects the authorize call
        // with ID2051 ("client not allowed to use the specified scope").
        if (await scopes.FindByNameAsync("roles", ct) is null)
        {
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "roles",
                DisplayName = "Roles",
                Description = "HRMS roles and permissions"
            }, ct);
        }

        if (await scopes.FindByNameAsync("vetting_status", ct) is null)
        {
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "vetting_status",
                DisplayName = "Vetting status",
                Description = "HRMS vetting lifecycle state"
            }, ct);
        }

        // Portal client
        if (await manager.FindByClientIdAsync("portal", ct) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "portal",
                DisplayName = "Civic Compass Portal",
                ClientType = OpenIddictConstants.ClientTypes.Public,
                RedirectUris =
                {
                    new Uri("https://portal.pishro.party/api/auth/callback"),
                    new Uri("http://localhost:3100/api/auth/callback")
                },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.Endpoints.EndSession,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                    OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OpenId,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Phone
                },
                Requirements =
                {
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                }
            }, ct);
        }

        // HRMS client (includes roles + vetting_status scopes for authorization).
        // The client descriptor is rewritten on every startup so permission/scope
        // edits in source actually take effect — the original FindByClientIdAsync
        // guard left old clients stuck with the seed-time permission set.
        var hrmsDescriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "hrms",
            DisplayName = "HRMS ERP",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            RedirectUris =
            {
                new Uri("https://erp.pishro.party/api/auth/callback"),
                new Uri("http://localhost:3000/api/auth/callback")
            },
            PostLogoutRedirectUris =
            {
                new Uri("https://erp.pishro.party/"),
                new Uri("http://localhost:3000/")
            },
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OpenId,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Phone,
                OpenIddictConstants.Permissions.Prefixes.Scope + "roles",
                OpenIddictConstants.Permissions.Prefixes.Scope + "vetting_status"
            },
            Requirements =
            {
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
            }
        };

        var existingHrms = await manager.FindByClientIdAsync("hrms", ct);
        if (existingHrms is null)
            await manager.CreateAsync(hrmsDescriptor, ct);
        else
            await manager.UpdateAsync(existingHrms, hrmsDescriptor, ct);
    }
}
