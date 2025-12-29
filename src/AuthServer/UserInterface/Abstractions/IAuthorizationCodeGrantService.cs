using AuthServer.Authorization.Models;

namespace AuthServer.UserInterface.Abstractions;

public interface IAuthorizationCodeGrantService
{
    Task<string> HandleAuthorizationCodeGrant(string subjectIdentifier, AuthorizeRequestDto request, IReadOnlyCollection<string> amr, CancellationToken cancellationToken);
}