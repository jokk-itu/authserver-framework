using AuthServer.Authorization.Models;

namespace AuthServer.Repositories.Models;

internal class AuthorizationGrantConsentDto
{
    public required string AuthorizationGrantId { get; init; }
    public required IReadOnlyCollection<string> Scope { get; init; }
    public required IReadOnlyCollection<string> Resource { get; init; }
    public required IReadOnlyCollection<AuthorizationDetailDto> AuthorizationDetails { get; init; }
}