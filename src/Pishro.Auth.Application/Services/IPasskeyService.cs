using System.Text.Json;
using Pishro.Auth.Application.DTOs;

namespace Pishro.Auth.Application.Services;

public interface IPasskeyService
{
    Task<object> BeginRegisterAsync(string displayName, CancellationToken ct = default);
    Task<AuthResult> CompleteRegisterAsync(JsonElement request, CancellationToken ct = default);
    Task<object> BeginLoginAsync(CancellationToken ct = default);
    Task<AuthResult> CompleteLoginAsync(JsonElement request, CancellationToken ct = default);
}
