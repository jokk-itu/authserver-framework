namespace AuthServer.Repositories.Abstractions;

internal interface IAuthorizationCodeRepository
{
    Task<bool> IsActiveAuthorizationCode(string authorizationCodeId, CancellationToken cancellationToken);
}