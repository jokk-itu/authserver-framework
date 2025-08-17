using AuthServer.Authentication.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Extensions;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;

namespace AuthServer.Revocation;
internal class RevocationRequestValidator : IRequestValidator<RevocationRequest, RevocationValidatedRequest>
{
    private readonly IServerTokenDecoder _serverTokenDecoder;
    private readonly IClientAuthenticationService _clientAuthenticationService;

    public RevocationRequestValidator(
        IServerTokenDecoder serverTokenDecoder,
        IClientAuthenticationService clientAuthenticationService)
    {
        _serverTokenDecoder = serverTokenDecoder;
        _clientAuthenticationService = clientAuthenticationService;
    }

    public async Task<ProcessResult<RevocationValidatedRequest, ProcessError>> Validate(RevocationRequest request, CancellationToken cancellationToken)
    {
        var isTokenTypeHintInvalid = !string.IsNullOrWhiteSpace(request.TokenTypeHint)
                                     && !TokenTypeConstants.TokenTypes.Contains(request.TokenTypeHint);

        if (isTokenTypeHintInvalid)
        {
            return RevocationError.UnsupportedTokenType;
        }

        /*
         * the token parameter is required per rf 7009,
         * and if the value itself is allowed to be invalid
         */
        var isTokenInvalid = string.IsNullOrWhiteSpace(request.Token);
        if (isTokenInvalid)
        {
            return RevocationError.EmptyToken;
        }

        var token = request.Token!;

        var isClientAuthenticationMethodInvalid = request.ClientAuthentications.Count != 1;
        if (isClientAuthenticationMethodInvalid)
        {
            return RevocationError.MultipleOrNoneClientMethod;
        }

        var clientAuthentication = request.ClientAuthentications.Single();
        if (!RevocationEndpointAuthMethodConstants.AuthMethods.Contains(clientAuthentication.Method.GetDescription()))
        {
            return RevocationError.InvalidClient;
        }

        var clientAuthenticationResult = await _clientAuthenticationService.AuthenticateClient(clientAuthentication, cancellationToken);
        if (!clientAuthenticationResult.IsAuthenticated || string.IsNullOrWhiteSpace(clientAuthenticationResult.ClientId))
        {
            return RevocationError.InvalidClient;
        }

        var tokenValidationResult = await ValidateToken(token, cancellationToken);
        if (tokenValidationResult is not null && clientAuthenticationResult.ClientId != tokenValidationResult.ClientId)
        {
            return RevocationError.ClientIdDoesNotMatchToken;
        }

        return new RevocationValidatedRequest
        {
            Jti = tokenValidationResult?.Jti
        };
    }

    private async Task<TokenValidationResult?> ValidateToken(string token, CancellationToken cancellationToken)
    {
        var validatedToken = await _serverTokenDecoder.Validate(token, new ServerTokenDecodeArguments
        {
            ValidateLifetime = false,
            Audiences = [],
            TokenTypes = [TokenTypeHeaderConstants.AccessToken, TokenTypeHeaderConstants.RefreshToken]
        }, cancellationToken);

        return validatedToken is null ? null : new TokenValidationResult(validatedToken.Jti, validatedToken.ClientId);
    }

    private record TokenValidationResult(string Jti, string ClientId);
}