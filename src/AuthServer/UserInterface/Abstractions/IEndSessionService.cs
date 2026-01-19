namespace AuthServer.UserInterface.Abstractions;

public interface IEndSessionService
{
    /// <summary>
    /// Sets the current user context using the specified subject identifier and determines whether to log out at the
    /// identity provider.
    /// </summary>
    /// <param name="subjectIdentifier">The unique identifier of the user to set as the current context. Cannot be null or empty.</param>
    /// <param name="logoutAtIdentityProvider">Specifies whether the user should be logged out at the identity provider. Set to <see langword="true"/> to
    /// initiate logout at the identity provider; otherwise, <see langword="false"/>.</param>
    void SetUser(string subjectIdentifier, bool logoutAtIdentityProvider);
}