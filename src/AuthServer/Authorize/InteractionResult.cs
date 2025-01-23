using AuthServer.Constants;
using AuthServer.Core.Request;

namespace AuthServer.Authorize;
internal class InteractionResult
{
    public static readonly InteractionResult LoginErrorResult = new(AuthorizeError.LoginRequired, false);
    public static readonly InteractionResult ConsentErrorResult = new(AuthorizeError.ConsentRequired, false);
    public static readonly InteractionResult SelectAccountErrorResult = new(AuthorizeError.AccountSelectionRequired, false);

    public static readonly InteractionResult LoginRedirectResult = new(AuthorizeError.LoginRequired, true);
    public static readonly InteractionResult ConsentRedirectResult = new(AuthorizeError.ConsentRequired, true);
    public static readonly InteractionResult SelectAccountRedirectResult = new(AuthorizeError.AccountSelectionRequired, true);

    public static readonly InteractionResult UnmetAuthenticationRequirementResult = new(AuthorizeError.UnmetAuthenticationRequirement, false);
    public static readonly InteractionResult InvalidGrantId = new(AuthorizeError.InvalidGrantId, false);

    private InteractionResult(ProcessError error, bool redirectToInteraction)
    {
        Error = error;
        RedirectToInteraction = redirectToInteraction;
    }

    private InteractionResult(string subjectIdentifier, string authorizationGrantId)
    {
        SubjectIdentifier = subjectIdentifier;
    }

    public ProcessError? Error { get; private init; }
    public bool RedirectToInteraction { get; private init; }
    public string? SubjectIdentifier { get; private init; }
    public string? AuthorizationGrantId { get; private init; }

    public bool IsSuccessful => Error is null && !string.IsNullOrEmpty(SubjectIdentifier);

    public static InteractionResult Success(string subjectIdentifier, string authorizationGrantId)
    {
        return new InteractionResult(subjectIdentifier, authorizationGrantId);
    }

    public static InteractionResult LoginResult(string? prompt) => prompt == PromptConstants.None ? LoginErrorResult : LoginRedirectResult;
    public static InteractionResult ConsentResult(string? prompt) => prompt == PromptConstants.None ? ConsentErrorResult : ConsentRedirectResult;
    public static InteractionResult SelectAccountResult(string? prompt) => prompt == PromptConstants.None ? SelectAccountErrorResult : SelectAccountRedirectResult;
}