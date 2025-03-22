using AuthServer.Constants;
using AuthServer.Helpers;

namespace AuthServer.Tests.UnitTest.Helpers;

public class ClaimsHelperTest
{
    [Fact]
    public void MapToClaims_Profile_ExpectProfileClaims()
    {
        // Arrange
        var scopes = new[] { ScopeConstants.Profile };
        var expectedClaims = new[]
        {
            ClaimNameConstants.Name,
            ClaimNameConstants.FamilyName,
            ClaimNameConstants.GivenName,
            ClaimNameConstants.Birthdate,
            ClaimNameConstants.Locale,
            ClaimNameConstants.Roles
        };

        // Act
        var claims = ClaimsHelper.MapToClaims(scopes);

        // Assert
        Assert.Equal(expectedClaims, claims);
    }

    [Fact]
    public void MapToClaims_Address_ExpectAddressClaims()
    {
        // Arrange
        var scopes = new[] { ScopeConstants.Address };
        var expectedClaims = new[]
        {
            ClaimNameConstants.Address
        };

        // Act
        var claims = ClaimsHelper.MapToClaims(scopes);

        // Assert
        Assert.Equal(expectedClaims, claims);
    }

    [Fact]
    public void MapToClaims_Phone_ExpectPhoneClaims()
    {
        // Arrange
        var scopes = new[] { ScopeConstants.Phone };
        var expectedClaims = new[]
        {
            ClaimNameConstants.PhoneNumber,
            ClaimNameConstants.PhoneNumberVerified
        };

        // Act
        var claims = ClaimsHelper.MapToClaims(scopes);

        // Assert
        Assert.Equal(expectedClaims, claims);
    }

    [Fact]
    public void MapToClaims_Email_ExpectEmailClaims()
    {
        // Arrange
        var scopes = new[] { ScopeConstants.Email };
        var expectedClaims = new[]
        {
            ClaimNameConstants.Email,
            ClaimNameConstants.EmailVerified
        };

        // Act
        var claims = ClaimsHelper.MapToClaims(scopes);

        // Assert
        Assert.Equal(expectedClaims, claims);
    }
}