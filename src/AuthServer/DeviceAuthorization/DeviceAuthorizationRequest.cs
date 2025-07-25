using AuthServer.Authentication.Models;
using AuthServer.Authorization.Models;

namespace AuthServer.DeviceAuthorization;

internal class DeviceAuthorizationRequest
{
    public DeviceAuthorizationRequest(){}
    
    public DeviceAuthorizationRequest(AuthorizeRequestDto authorizeRequestDto, IReadOnlyCollection<ClientAuthentication> clientAuthentications, string? dPoP)
    {
        CodeChallenge = authorizeRequestDto.CodeChallenge;
        CodeChallengeMethod = authorizeRequestDto.CodeChallengeMethod;
        Nonce = authorizeRequestDto.Nonce;
        GrantId = authorizeRequestDto.GrantId;
        GrantManagementAction = authorizeRequestDto.GrantManagementAction;
        Scope = authorizeRequestDto.Scope;
        AcrValues = authorizeRequestDto.AcrValues;
        Resource = authorizeRequestDto.Resource;
        DPoP = dPoP;
        ClientAuthentications = clientAuthentications;
    }
    
    public string? CodeChallenge { get; init; }
    public string? CodeChallengeMethod { get; init; }
    public string? Nonce { get; init; }
    public string? RequestObject { get; init; }
    public string? GrantId { get; init; }
    public string? GrantManagementAction { get; init; }
    public string? DPoP { get; init; }
    public IReadOnlyCollection<string> Scope { get; init; } = [];
    public IReadOnlyCollection<string> AcrValues { get; init; } = [];
    public IReadOnlyCollection<string> Resource { get; init; } = [];
    public IReadOnlyCollection<ClientAuthentication> ClientAuthentications { get; init; } = [];
}