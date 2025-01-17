using AuthServer.Authorization;

namespace AuthServer.RequestAccessors.Authorize;

internal class AuthorizeRequest
{
    public AuthorizeRequest()
    {
    }

    public AuthorizeRequest(AuthorizeRequestDto authorizeRequestDto, string? requestUri = null)
    {
        IdTokenHint = authorizeRequestDto.IdTokenHint;
        LoginHint = authorizeRequestDto.LoginHint;
        Prompt = authorizeRequestDto.Prompt;
        Display = authorizeRequestDto.Display;
        ClientId = authorizeRequestDto.ClientId;
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
        RequestUri = requestUri;
        Scope = authorizeRequestDto.Scope;
        AcrValues = authorizeRequestDto.AcrValues;
    }

    public string? IdTokenHint { get; init; }
    public string? LoginHint { get; init; }
    public string? Prompt { get; init; }
    public string? Display { get; init; }
    public string? ClientId { get; init; }
    public string? RedirectUri { get; init; }
    public string? CodeChallenge { get; init; }
    public string? CodeChallengeMethod { get; init; }
    public string? ResponseType { get; init; }
    public string? Nonce { get; init; }
    public string? MaxAge { get; init; }
    public string? State { get; init; }
    public string? ResponseMode { get; init; }
    public string? RequestObject { get; init; }
    public string? RequestUri { get ; init; }
    public string? GrantId { get; init; }
    public string? GrantManagementAction { get; init; }
    public IReadOnlyCollection<string> Scope { get; init; } = [];
    public IReadOnlyCollection<string> AcrValues { get; init; } = [];
}