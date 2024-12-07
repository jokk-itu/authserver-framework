using AuthServer.RequestAccessors.Authorize;

namespace AuthServer.Authorization;
public class AuthorizeRequestDto
{
    public AuthorizeRequestDto()
    {
    }

    internal AuthorizeRequestDto(AuthorizeRequest authorizeRequest)
    {
        IdTokenHint = authorizeRequest.IdTokenHint;
        LoginHint = authorizeRequest.LoginHint;
        Prompt = authorizeRequest.Prompt;
        Display = authorizeRequest.Display;
        ClientId = authorizeRequest.ClientId;
        RedirectUri = authorizeRequest.RedirectUri;
        CodeChallenge = authorizeRequest.CodeChallenge;
        CodeChallengeMethod = authorizeRequest.CodeChallengeMethod;
        ResponseType = authorizeRequest.ResponseType;
        Nonce = authorizeRequest.Nonce;
        MaxAge = authorizeRequest.MaxAge;
        State = authorizeRequest.State;
        ResponseMode = authorizeRequest.ResponseMode;
        Scope = authorizeRequest.Scope;
        AcrValues = authorizeRequest.AcrValues;
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
    public IReadOnlyCollection<string> Scope { get; init; } = [];
    public IReadOnlyCollection<string> AcrValues { get; init; } = [];
}
