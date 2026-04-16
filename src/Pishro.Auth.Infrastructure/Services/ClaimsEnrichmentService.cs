using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Pishro.Auth.Application.Services;

namespace Pishro.Auth.Infrastructure.Services;

/// <summary>
/// Enriches OIDC tokens by fetching roles and vetting status from HRMS
/// internal API endpoints at token issuance time.
/// pishro-auth does NOT store roles/permissions — HRMS IAM is the source of truth.
/// </summary>
public class ClaimsEnrichmentService(
    IHttpClientFactory httpClientFactory,
    IConfiguration configuration,
    ILogger<ClaimsEnrichmentService> logger) : IClaimsEnrichmentService
{
    private record RolesResponse(string[] Roles, string? VettingStatus, Guid? TenantId, string[]? Permissions);
    private record VettingStatusResponse(string VettingStatus);

    public async Task<IReadOnlyList<Claim>> GetEnrichedClaimsAsync(Guid userId, CancellationToken ct = default)
    {
        var claims = new List<Claim>();

        var iamBaseUrl = configuration["Hrms:IamBaseUrl"];
        var identityBaseUrl = configuration["Hrms:IdentityBaseUrl"];

        // If HRMS endpoints are not configured, return empty (portal-only mode)
        if (string.IsNullOrEmpty(iamBaseUrl) && string.IsNullOrEmpty(identityBaseUrl))
            return claims;

        var client = httpClientFactory.CreateClient("hrms-internal");

        // Fetch roles from HRMS IAM
        if (!string.IsNullOrEmpty(iamBaseUrl))
        {
            try
            {
                var rolesResponse = await client.GetFromJsonAsync<RolesResponse>(
                    $"{iamBaseUrl}/api/iam/internal/roles/{userId}", ct);

                if (rolesResponse is not null)
                {
                    foreach (var role in rolesResponse.Roles)
                    {
                        claims.Add(new Claim("role", role));
                    }

                    // Emit a single boolean `hrms_access` claim rather than the
                    // full permission list. The super-admin role has ~160 permissions
                    // which bloats the id_token past nginx's 4 KB upstream buffer
                    // (causing 502 on the callback). Fine-grained checks should
                    // query /api/iam/internal/roles server-side when needed.
                    var hasBackofficeAccess = rolesResponse.Permissions is { Length: > 0 } &&
                        rolesResponse.Permissions.Any(p =>
                            string.Equals(p, "hrms.backoffice:access", StringComparison.OrdinalIgnoreCase));
                    if (hasBackofficeAccess)
                    {
                        claims.Add(new Claim("hrms_access", "true"));
                    }

                    // Second boolean claim: surfaces members.sensitive-data:read so
                    // Hrms.SharedKernel.ICurrentUser.HasSensitiveAccess can drive the
                    // MemberSerializer full-vs-masked projection. Same shrinkage rationale
                    // as hrms_access — no per-permission claim explosion.
                    var hasSensitiveAccess = rolesResponse.Permissions is { Length: > 0 } &&
                        rolesResponse.Permissions.Any(p =>
                            string.Equals(p, "members.sensitive-data:read", StringComparison.OrdinalIgnoreCase));
                    if (hasSensitiveAccess)
                    {
                        claims.Add(new Claim("has_sensitive_access", "true"));
                    }

                    if (rolesResponse.TenantId is not null)
                        claims.Add(new Claim("tenant_id", rolesResponse.TenantId.Value.ToString()));

                    if (!string.IsNullOrEmpty(rolesResponse.VettingStatus))
                        claims.Add(new Claim("vetting_status", rolesResponse.VettingStatus));
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to fetch roles from HRMS IAM for user {UserId}", userId);
            }
        }

        // Fetch vetting status from HRMS Identity (fallback if IAM didn't provide it)
        if (!claims.Exists(c => c.Type == "vetting_status") && !string.IsNullOrEmpty(identityBaseUrl))
        {
            try
            {
                var vettingResponse = await client.GetFromJsonAsync<VettingStatusResponse>(
                    $"{identityBaseUrl}/api/identity/internal/vetting-status/{userId}", ct);

                if (vettingResponse is not null && !string.IsNullOrEmpty(vettingResponse.VettingStatus))
                    claims.Add(new Claim("vetting_status", vettingResponse.VettingStatus));
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to fetch vetting status from HRMS Identity for user {UserId}", userId);
            }
        }

        return claims;
    }
}
