using OpenIddict.Abstractions;

namespace Pishro.Auth.Infrastructure.Seed;

public class ClientSeeder(IOpenIddictApplicationManager manager)
{
    public async Task SeedAsync(CancellationToken ct = default)
    {
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

        // HRMS client
        if (await manager.FindByClientIdAsync("hrms", ct) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "hrms",
                DisplayName = "HRMS ERP",
                ClientType = OpenIddictConstants.ClientTypes.Public,
                RedirectUris =
                {
                    new Uri("https://erp.pishro.party/api/auth/callback"),
                    new Uri("http://localhost:3000/api/auth/callback")
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
    }
}
