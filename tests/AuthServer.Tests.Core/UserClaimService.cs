using System.Security.Claims;
using System.Text.Json;
using AuthServer.Authentication.Abstractions;
using AuthServer.Constants;
using Microsoft.IdentityModel.JsonWebTokens;

namespace AuthServer.Tests.Core;
public class UserClaimService : IUserClaimService
{
    public Task<IEnumerable<Claim>> GetClaims(string subjectIdentifier, CancellationToken cancellationToken)
    {
        return Task.FromResult<IEnumerable<Claim>>(
        [
            new Claim(ClaimNameConstants.Name, UserConstants.Name),
            new Claim(ClaimNameConstants.GivenName, UserConstants.GivenName),
            new Claim(ClaimNameConstants.MiddleName, UserConstants.MiddleName),
            new Claim(ClaimNameConstants.FamilyName, UserConstants.FamilyName),
            new Claim(ClaimNameConstants.Address, UserConstants.Address),
            new Claim(ClaimNameConstants.NickName, UserConstants.NickName),
            new Claim(ClaimNameConstants.PreferredUsername, UserConstants.PreferredUsername),
            new Claim(ClaimNameConstants.Profile, UserConstants.Profile),
            new Claim(ClaimNameConstants.Picture, UserConstants.Picture),
            new Claim(ClaimNameConstants.Website, UserConstants.Website),
            new Claim(ClaimNameConstants.Email, UserConstants.Email, ClaimValueTypes.Email),
            new Claim(ClaimNameConstants.EmailVerified, UserConstants.EmailVerified, ClaimValueTypes.Boolean),
            new Claim(ClaimNameConstants.Gender, UserConstants.Gender),
            new Claim(ClaimNameConstants.Birthdate, UserConstants.Birthdate, ClaimValueTypes.DateTime),
            new Claim(ClaimNameConstants.ZoneInfo, UserConstants.ZoneInfo),
            new Claim(ClaimNameConstants.Locale, UserConstants.Locale),
            new Claim(ClaimNameConstants.PhoneNumber, UserConstants.PhoneNumber),
            new Claim(ClaimNameConstants.PhoneNumberVerified, UserConstants.PhoneNumberVerified, ClaimValueTypes.Boolean),
            new Claim(ClaimNameConstants.UpdatedAt, UserConstants.UpdatedAt, ClaimValueTypes.DateTime),
            new Claim(ClaimNameConstants.Roles, JsonSerializer.Serialize(UserConstants.Roles), JsonClaimValueTypes.JsonArray)
        ]);
    }

    public Task<string> GetUsername(string subjectIdentifier, CancellationToken cancellationToken)
    {
        return Task.FromResult(UserConstants.Username);
    }

    public Task<IEnumerable<Claim>> GetAccessClaims(string subjectIdentifier, CancellationToken cancellationToken)
    {
        return Task.FromResult<IEnumerable<Claim>>(
        [
            new Claim(ClaimNameConstants.Roles, JsonSerializer.Serialize(UserConstants.Roles), JsonClaimValueTypes.JsonArray)
        ]);
    }
}