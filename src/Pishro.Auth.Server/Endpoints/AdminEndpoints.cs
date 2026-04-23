using Microsoft.EntityFrameworkCore;
using Pishro.Auth.Infrastructure.Persistence;

namespace Pishro.Auth.Server.Endpoints;

/// <summary>
/// Service-to-service administrative endpoints. Called by the HRMS Identity
/// service when a member is hard-deleted so the user + their passkey
/// credentials are removed from the IdP too. Protected by a shared secret
/// header (<c>X-Admin-Key</c>) configured via <c>Admin:Key</c>.
/// </summary>
public static class AdminEndpoints
{
    public static void MapAdminEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/admin")
            .AddEndpointFilter(AdminKeyFilter);

        group.MapDelete("/users/{userId:guid}", async (
            Guid userId,
            AuthDbContext db,
            ILoggerFactory loggerFactory,
            CancellationToken ct) =>
        {
            var logger = loggerFactory.CreateLogger("AdminEndpoints");
            var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
            if (user is null) return Results.NotFound();

            // passkey_credentials FK has ON DELETE CASCADE — removing the user
            // row clears the WebAuthn credentials in the same transaction.
            db.Users.Remove(user);
            await db.SaveChangesAsync(ct);

            logger.LogInformation("Admin-deleted user {UserId} (passkeys cascade-removed)", userId);
            return Results.Ok(new { deleted = true });
        }).WithName("AdminDeleteUser");
    }

    private static async ValueTask<object?> AdminKeyFilter(
        EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var configured = context.HttpContext.RequestServices
            .GetRequiredService<IConfiguration>()["Admin:Key"];

        if (string.IsNullOrWhiteSpace(configured))
        {
            // Misconfigured — fail closed rather than leave the admin surface open.
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }

        var presented = context.HttpContext.Request.Headers["X-Admin-Key"].ToString();
        if (!string.Equals(presented, configured, StringComparison.Ordinal))
        {
            return Results.Unauthorized();
        }

        return await next(context);
    }
}
