using AuthServer.Authorization.Models;
using AuthServer.Entities;

namespace AuthServer.Repositories.Abstractions;
internal interface IClientRepository
{
    /// <summary>
    /// Returns the ClientUri from all clients authorized to use the given scopes.
    /// </summary>
    /// <param name="scopes"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IReadOnlyCollection<string>> GetResources(IReadOnlyCollection<string> scopes, CancellationToken cancellationToken);

    /// <summary>
    /// Returns the Claims that are authorized by the client from scopes.
    /// </summary>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IReadOnlyCollection<string>> GetAuthorizedClaims(string clientId, CancellationToken cancellationToken);

    /// <summary>
    /// Returns whether resources are authorized for scopes.
    /// </summary>
    /// <param name="resources"></param>
    /// <param name="scopes"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<bool> AreResourcesAuthorizedForScope(IReadOnlyCollection<string> resources, IReadOnlyCollection<string> scopes, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="reference"></param>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<AuthorizeRequestDto?> GetAuthorizeDto(string reference, string clientId, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizeDto"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<AuthorizeMessage> AddAuthorizeMessage(AuthorizeRequestDto authorizeDto, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="reference"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task RedeemAuthorizeMessage(string reference, CancellationToken cancellationToken);
}