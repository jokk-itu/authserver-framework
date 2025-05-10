using AuthServer.Authentication.Models;
using AuthServer.Authorization;

namespace AuthServer.PushedAuthorization;
internal class PushedAuthorizationRequest
{
    public PushedAuthorizationRequest()
    {
    }

    public PushedAuthorizationRequest(AuthorizeRequestDto authorizeRequestDto, IReadOnlyCollection<ClientAuthentication> clientAuthentications)
    {
        IdTokenHint = authorizeRequestDto.IdTokenHint;
        LoginHint = authorizeRequestDto.LoginHint;
        Prompt = authorizeRequestDto.Prompt;
        Display = authorizeRequestDto.Display;
        RedirectUri = authorizeRequestDto.RedirectUri;
        CodeChallenge = authorizeRequestDto.CodeChallenge;
        CodeChallengeMethod = authorizeRequestDto.CodeChallengeMethod;
        ResponseType = authorizeRequestDto.ResponseType;
        Nonce = authorizeRequestDto.Nonce;
        MaxAge = authorizeRequestDto.MaxAge;
        State = authorizeRequestDto.State;
        ResponseMode = authorizeRequestDto.ResponseMode;
        GrantId = authorizeRequestDto.GrantId;
        GrantManagementAction = authorizeRequestDto.GrantManagementAction;
        Scope = authorizeRequestDto.Scope;
        AcrValues = authorizeRequestDto.AcrValues;
        Resource = authorizeRequestDto.Resource;
        ClientAuthentications = clientAuthentications;
    }

    public string? IdTokenHint { get; init; }
    public string? LoginHint { get; init; }
    public string? Prompt { get; init; }
    public string? Display { get; init; }
    public string? RedirectUri { get; init; }
    public string? CodeChallenge { get; init; }
    public string? CodeChallengeMethod { get; init; }
    public string? ResponseType { get; init; }
    public string? Nonce { get; init; }
    public string? MaxAge { get; init; }
    public string? State { get; init; }
    public string? ResponseMode { get; init; }
    public string? GrantId { get; init; }
    public string? GrantManagementAction { get; init; }
    public string? RequestObject { get; init; }
    public IReadOnlyCollection<string> Scope { get; init; } = [];
    public IReadOnlyCollection<string> AcrValues { get; init; } = [];
    public IReadOnlyCollection<string> Resource { get; init; } = [];
    public IReadOnlyCollection<ClientAuthentication> ClientAuthentications { get; init; } = [];
}