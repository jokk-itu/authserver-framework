namespace AuthServer.EndSession.UserInterface.Abstractions;

public interface IEndSessionService
{
    void SetUser(string subjectIdentifier, bool logoutAtIdentityProvider);
}