using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Pishro.Auth.Application.Services;
using Pishro.Auth.Infrastructure.Persistence;
using Pishro.Auth.Infrastructure.Seed;
using Pishro.Auth.Infrastructure.Services;
using Pishro.Auth.Server.Endpoints;

var builder = WebApplication.CreateBuilder(args);

// EF Core
builder.Services.AddDbContext<AuthDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("AuthDb"));
    options.UseOpenIddict();
});

// OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore().UseDbContext<AuthDbContext>();
    })
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token")
               .SetUserInfoEndpointUris("/connect/userinfo")
               .SetEndSessionEndpointUris("/connect/logout");

        options.AllowAuthorizationCodeFlow()
               .RequireProofKeyForCodeExchange();

        options.RegisterScopes("openid", "profile", "email", "phone");

        // Dev signing credentials (replace with proper certs in production)
        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login.html";
    });

builder.Services.AddDistributedMemoryCache();
builder.Services.AddFido2(options =>
{
    options.ServerDomain = builder.Configuration["Fido2:ServerDomain"] ?? "localhost";
    options.ServerName = "Pishro Auth";
    options.Origins = new HashSet<string>(
        builder.Configuration.GetSection("Fido2:Origins").Get<string[]>() ?? ["http://localhost:5300"]);
});

builder.Services.AddAuthorization();

builder.Services.AddScoped<IPasskeyService, PasskeyService>();
builder.Services.AddScoped<ClientSeeder>();

var app = builder.Build();

// Auto-migrate + seed
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    await db.Database.MigrateAsync();
    var seeder = scope.ServiceProvider.GetRequiredService<ClientSeeder>();
    await seeder.SeedAsync();
}

// Trust reverse proxy headers (X-Forwarded-Proto, X-Forwarded-For)
app.UseForwardedHeaders(new Microsoft.AspNetCore.HttpOverrides.ForwardedHeadersOptions
{
    ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor
                     | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto,
});

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

// Map endpoints
app.MapAuthEndpoints();
app.MapConnectEndpoints();

app.MapGet("/health", () => Results.Ok(new { status = "healthy", service = "pishro-auth" }));

app.Run();
