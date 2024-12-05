using AuthServer.Core.Request;

namespace AuthServer.Authorize;
internal class InteractionResult
{
    public static readonly InteractionResult LoginResult = new(AuthorizeError.LoginRequired);
    public static readonly InteractionResult ConsentResult = new(AuthorizeError.ConsentRequired);
    public static readonly InteractionResult SelectAccountResult = new(AuthorizeError.AccountSelectionRequired);
    public static readonly InteractionResult UnmetAuthenticationRequirementResult = new(AuthorizeError.UnmetAuthenticationRequirement);

    private InteractionResult(ProcessError error)
    {
        Error = error;
    }

    private InteractionResult(string subjectIdentifier)
    {
        SubjectIdentifier = subjectIdentifier;
    }

    public ProcessError? Error { get; private init; }
    public string? SubjectIdentifier { get; private init; }

    public bool IsSuccessful => Error is null && !string.IsNullOrEmpty(SubjectIdentifier);

    public static InteractionResult Success(string subjectIdentifier)
    {
        return new InteractionResult(subjectIdentifier);
    }
}
