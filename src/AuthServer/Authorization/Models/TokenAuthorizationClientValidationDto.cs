namespace AuthServer.Authorization.Models;

internal class TokenAuthorizationClientValidationDto : TokenAuthorizationValidationDto
{
    public required string ClientId { get; init; }
}