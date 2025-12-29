using AuthServer.Authentication.Abstractions;
using AuthServer.EndSession;
using AuthServer.UserInterface.Abstractions;

namespace AuthServer.UserInterface;

internal class EndSessionService : IEndSessionService
{
    private readonly IUserAccessor<EndSessionUser> _endSessionUserAccessor;

    public EndSessionService(IUserAccessor<EndSessionUser> endSessionUserAccessor)
    {
        _endSessionUserAccessor = endSessionUserAccessor;
    }

    public void SetUser(string subjectIdentifier, bool logoutAtIdentityProvider)
    {
        _endSessionUserAccessor.SetUser(new EndSessionUser(subjectIdentifier, logoutAtIdentityProvider));
    }
}