using System.Security;
using AuthServer.Constants;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Helpers;
public class ProofKeyHelperTest : BaseUnitTest
{
    public ProofKeyHelperTest(ITestOutputHelper outputHelper) : base(outputHelper)
    {
    }

    [Theory]
    [InlineData("invalid_value")]
    [InlineData("")]
    [InlineData(null)]
    public void IsCodeChallengeMethodValid_InvalidValue_ExpectFalse(string? value)
    {
        // Arrange && Act
        var isValid = ProofKeyHelper.IsCodeChallengeMethodValid(value);

        // Assert
        Assert.False(isValid);
    }

    [Theory]
    [InlineData(CodeChallengeMethodConstants.S256)]
    [InlineData(CodeChallengeMethodConstants.S384)]
    [InlineData(CodeChallengeMethodConstants.S512)]
    public void IsCodeChallengeMethodValid_KnownValue_ExpectTrue(string value)
    {
        // Arrange && Act
        var isValid = ProofKeyHelper.IsCodeChallengeMethodValid(value);

        // Assert
        Assert.True(isValid);
    }

    [Theory]
    [InlineData("isvdfvdfbvis~039u56y85ubrib~ubn_npfnb-vu457667innbiyu567nlskvm-sjkhbvj23rhbvr-sr7i8k90vbnruikvbn-_vnireunbv6587768g567823gntryn3457")]
    [InlineData("isvdfvdfbvis~039u56y85ubrib~ubn_npfnb-vu45")]
    [InlineData("isvdfvdfbvis~039u56yæøå5urib~ubn_npfnb-vu457skjbhgu&!krbguiert")]
    [InlineData("")]
    [InlineData(null)]
    public void IsCodeChallengeValid_InvalidValue_ExpectFalse(string? value)
    {
        // Arrange && Act
        var isValid = ProofKeyHelper.IsCodeChallengeValid(value);

        // Assert
        Assert.False(isValid);
    }

    [Theory]
    [InlineData("isvdfvdfbvis~039u56y85ubrib~ubn_npfnb-vu457667innbiyu567nlskvm-sjkhbvj23rhbvr-sr7i8k90vbnruikvbn-_vnireunbv6587768g567823gntryn3")]
    [InlineData("isvdfvdfbvis~039u56y85ubrib~ubn_npfnb-vu457")]
    [InlineData("isvdfvdfbvis~039u56y85ubrib~ubn_npfnb-vu457skjbhguiekrbguiert")]
    public void IsCodeChallengeValid_InvalidValue_ExpectTrue(string? value)
    {
        // Arrange && Act
        var isValid = ProofKeyHelper.IsCodeChallengeValid(value);

        // Assert
        Assert.True(isValid);
    }

    [Theory]
    [InlineData("", "isvdfvdfbvis~039u56y85ubrib~ubn_npfnb-vu457", CodeChallengeMethodConstants.S256)]
    [InlineData(null, "isvdfvdfbvis~039u56y85ubrib~ubn_npfnb-vu457", CodeChallengeMethodConstants.S256)]
    [InlineData("isvdfvdfbvis~039u56y85ubrib~ubn_npfnb-vu457", "", CodeChallengeMethodConstants.S256)]
    [InlineData("isvdfvdfbvis~039u56y85ubrib~ubn_npfnb-vu457", null, CodeChallengeMethodConstants.S256)]
    [InlineData("isvdfvdfbvis~039u56y85ubrib~ubn_npfnb-vu457", "isvdfvdfbvis~039u56y85ubrib~ubn_npfnb-vu457", "")]
    [InlineData("isvdfvdfbvis~039u56y85ubrib~ubn_npfnb-vu457", "isvdfvdfbvis~039u56y85ubrib~ubn_npfnb-vu457", null)]
    public void IsCodeVerifierValid_InvalidCodeParameters_ExpectFalse(string? codeVerifier, string? codeChallenge, string? codeChallengeMethod)
    {
        // Arrange & Act
        var isValid = ProofKeyHelper.IsCodeVerifierValid(codeVerifier, codeChallenge, codeChallengeMethod);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void IsCodeVerifierValid_InvalidCodeChallengeMethod_ExpectSecurityException()
    {
        // Arrange && Act && Assert
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        Assert.Throws<SecurityException>(() => ProofKeyHelper.IsCodeVerifierValid(
            proofKey.CodeVerifier,
            proofKey.CodeChallenge,
            "invalid_code_challenge_method"));
    }

    [Fact]
    public void IsCodeVerifierValid_CodeChallengeAndCodeVerifierMismatch_ExpectFalse()
    {
        // Arrange
        const string codeVerifier = "isvdfvdfbvis~039u56y85ubrib~ubn_npfnb-vu457";
        const string codeChallenge = "isvdfvdfbvis~_39u5-kjbetrubenpfnb-v354678";

        // Act
        var isValid = ProofKeyHelper.IsCodeVerifierValid(codeVerifier, codeChallenge, CodeChallengeMethodConstants.S256);

        // Assert
        Assert.False(isValid);
    }

    [Theory]
    [InlineData(CodeChallengeMethodConstants.S256)]
    [InlineData(CodeChallengeMethodConstants.S384)]
    [InlineData(CodeChallengeMethodConstants.S512)]
    public void IsCodeVerifierValid_ValidCode_ExpectTrue(string codeChallengeMethod)
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange(codeChallengeMethod);

        // Act
        var isValid = ProofKeyHelper.IsCodeVerifierValid(
            proofKey.CodeVerifier,
            proofKey.CodeChallenge,
            proofKey.CodeChallengeMethod);

        // Assert
        Assert.True(isValid);
    }
}
