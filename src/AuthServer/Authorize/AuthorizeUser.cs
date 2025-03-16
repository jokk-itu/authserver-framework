namespace AuthServer.Authorize;

internal record AuthorizeUser(string SubjectIdentifier, bool IsFreshGrant, string AuthorizationGrantId);