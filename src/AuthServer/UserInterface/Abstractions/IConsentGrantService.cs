namespace AuthServer.UserInterface.Abstractions;

public interface IConsentGrantService
{
    /// <summary>
    /// Processes and records user consent for a client application, including the scopes and claims the user has
    /// approved.
    /// </summary>
    /// <param name="subjectIdentifier">The unique identifier of the user whose consent is being handled. Cannot be null or empty.</param>
    /// <param name="clientId">The identifier of the client application requesting consent. Cannot be null or empty.</param>
    /// <param name="consentedScopes">A read-only collection of scope names that the user has consented to. Must not be null; may be empty if no
    /// scopes are approved.</param>
    /// <param name="consentedClaims">A read-only collection of claim names that the user has consented to share. Must not be null; may be empty if no
    /// claims are approved.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the operation.</param>
    /// <returns>A task that represents the asynchronous operation of handling user consent.</returns>
    Task HandleConsent(string subjectIdentifier, string clientId, IReadOnlyCollection<string> consentedScopes, IReadOnlyCollection<string> consentedClaims, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the consent grant details for a specified subject and client.
    /// </summary>
    /// <param name="subjectIdentifier">The unique identifier of the subject (user) whose consent grant information is to be retrieved. Cannot be null
    /// or empty.</param>
    /// <param name="clientId">The identifier of the client application for which the consent grant is requested. Cannot be null or empty.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the operation.</param>
    /// <returns>ConsentGrantDto with the consent grant details for the specified subject and client, or null if no consent grant exists.</returns>
    Task<ConsentGrantDto> GetConsentGrantDto(string subjectIdentifier, string clientId, CancellationToken cancellationToken);
}