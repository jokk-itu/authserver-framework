namespace AuthServer.Authorization.Models;

internal enum AuthorizationDetailsError
{
    NotSupported,
    Invalid,
    NotAuthorizedForClient,
    NotAuthorizedForResource
}