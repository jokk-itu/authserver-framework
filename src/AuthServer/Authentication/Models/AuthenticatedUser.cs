namespace AuthServer.Authentication.Models;

public record AuthenticatedUser(string SubjectIdentifier, string AuthorizationGrantId);