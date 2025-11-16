using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Constants;
using AuthServer.Endpoints.Abstractions;
using AuthServer.Extensions;
using AuthServer.Helpers;
using AuthServer.Options;
using AuthServer.Repositories.Abstractions;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthServer.Authorization;
internal class DPoPService : IDPoPService
{
    private readonly IEndpointResolver _endpointResolver;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IClientTokenDecoder _clientTokenDecoder;
    private readonly IOptionsSnapshot<DiscoveryDocument> _discoveryDocumentOptions;
    private readonly ILogger<DPoPService> _logger;
    private readonly INonceRepository _nonceRepository;

    public DPoPService(
        IEndpointResolver endpointResolver,
        IHttpContextAccessor httpContextAccessor,
        IClientTokenDecoder clientTokenDecoder,
        IOptionsSnapshot<DiscoveryDocument> discoveryDocumentOptions,
        ILogger<DPoPService> logger,
        INonceRepository nonceRepository)
    {
        _endpointResolver = endpointResolver;
        _httpContextAccessor = httpContextAccessor;
        _clientTokenDecoder = clientTokenDecoder;
        _discoveryDocumentOptions = discoveryDocumentOptions;
        _logger = logger;
        _nonceRepository = nonceRepository;
    }

    /// <inheritdoc/>
    public async Task<DPoPValidationResult> ValidateDPoP(string dPoP, string clientId, CancellationToken cancellationToken)
    {
        var requestUrl = new Uri(_httpContextAccessor.HttpContext!.Request.GetDisplayUrl()).GetLeftPart(UriPartial.Path);
        var audience = _endpointResolver.Convert(requestUrl);

        var validatedDPoPToken = await _clientTokenDecoder.Validate(
            dPoP,
            new ClientTokenDecodeArguments
            {
                ClientId = clientId,
                Algorithms = _discoveryDocumentOptions.Value.DPoPSigningAlgValuesSupported.ToList(),
                TokenType = TokenTypeHeaderConstants.DPoPToken,
                ValidateLifetime = true,
                UseJwkHeaderSignatureValidation = true,
                Audience = audience
            },
            cancellationToken);

        if (validatedDPoPToken is null)
        {
            return new DPoPValidationResult();
        }

        var requestMethod = HttpMethod.Parse(_httpContextAccessor.HttpContext!.Request.Method);
        if (!validatedDPoPToken.TryGetPayloadValue<string>(ClaimNameConstants.Htm, out var htm)
            || !HttpMethodHelper.TryParse(htm, out var parsedMethod)
            || parsedMethod != requestMethod)
        {
            _logger.LogWarning("DPoP token from client {ClientId} does not contain valid htm {Htm} claim", clientId, htm);
            return new DPoPValidationResult();
        }

        if (!validatedDPoPToken.TryGetPayloadValue<string>(ClaimNameConstants.Htu, out var htu)
            || htu != requestUrl)
        {
            _logger.LogWarning("DPoP token from client {ClientId} does not contain valid htu {Htu} claim", clientId, htu);
            return new DPoPValidationResult();
        }

        /*
         * If the token does not have a nonce claim, then a new dpop nonce must be created.
         */
        if (!validatedDPoPToken.TryGetPayloadValue<string>(ClaimNameConstants.Nonce, out var nonce))
        {
            _logger.LogInformation("DPoP token from client {ClientId} does not contain a nonce claim", clientId);
            return new DPoPValidationResult
            {
                RenewDPoPNonce = true
            };
        }

        /*
         * If the nonce is not an active dpop nonce belonging to the client, then a new dpop nonce must be created.
         */
        if (!await _nonceRepository.IsActiveDPoPNonce(nonce, clientId, cancellationToken))
        {
            _logger.LogWarning("DPoP token from client {ClientId} does not contain valid nonce {Nonce} claim", clientId, nonce);
            return new DPoPValidationResult
            {
                RenewDPoPNonce = true
            };
        }

        var jwkHeaderClaim = validatedDPoPToken.GetHeaderValue<string>(ClaimNameConstants.Jwk);
        var jkt = CryptographyHelper.ComputeJwkThumbprint(jwkHeaderClaim);
        validatedDPoPToken.TryGetPayloadValue<string>(ClaimNameConstants.Ath, out var accessTokenHash);

        return new DPoPValidationResult
        {
            IsValid = true,
            DPoPJkt = jkt,
            AccessTokenHash = accessTokenHash
        };
    }
}
