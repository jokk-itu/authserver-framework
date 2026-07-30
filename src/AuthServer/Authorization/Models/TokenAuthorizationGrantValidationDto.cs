namespace AuthServer.Authorization.Models;

internal class TokenAuthorizationGrantValidationDto : TokenAuthorizationValidationDto
{
    public required string AuthorizationGrantId { get; init; }
}