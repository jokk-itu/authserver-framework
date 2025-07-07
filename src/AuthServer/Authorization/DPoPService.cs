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
    private readonly ITokenDecoder<ClientIssuedTokenDecodeArguments> _clientTokenDecoder;
    private readonly IOptionsSnapshot<DiscoveryDocument> _discoveryDocumentOptions;
    private readonly ILogger<DPoPService> _logger;
    private readonly INonceRepository _nonceRepository;

    public DPoPService(
        IEndpointResolver endpointResolver,
        IHttpContextAccessor httpContextAccessor,
        ITokenDecoder<ClientIssuedTokenDecodeArguments> clientTokenDecoder,
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
            new ClientIssuedTokenDecodeArguments
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
            return new DPoPValidationResult
            {
                IsValid = false
            };
        }

        var requestMethod = HttpMethod.Parse(_httpContextAccessor.HttpContext!.Request.Method);
        if (!validatedDPoPToken.TryGetPayloadValue<string>(ClaimNameConstants.Htm, out var htm)
            || !HttpMethodHelper.TryParse(htm, out var parsedMethod)
            || parsedMethod != requestMethod)
        {
            _logger.LogWarning("DPoP token from client {ClientId} does not contain valid htm {Htm} claim", clientId, htm);
            return new DPoPValidationResult
            {
                IsValid = false
            };
        }

        if (!validatedDPoPToken.TryGetPayloadValue<string>(ClaimNameConstants.Htu, out var htu)
            || htu != requestUrl)
        {
            _logger.LogWarning("DPoP token from client {ClientId} does not contain valid htu {Htu} claim", clientId, htu);
            return new DPoPValidationResult
            {
                IsValid = false
            };
        }

        var activeDPoPNonce = await _nonceRepository.GetActiveDPoPNonce(clientId, cancellationToken);

        /*
         * If there is no active DPoPNonce for the client, then a new must be returned.
         */
        if (activeDPoPNonce is null)
        {
            _logger.LogInformation("DPoPNonce has expired for client {ClientId}", clientId);
            return new DPoPValidationResult
            {
                IsValid = false,
                RenewDPoPNonce = true
            };
        }

        /*
         * If the client does not have a nonce, it is expected that the claim does not exist.
         * then the active DPoPNonce is returned.
         */
        if (!validatedDPoPToken.TryGetPayloadValue<string>(ClaimNameConstants.Nonce, out var nonce))
        {
            _logger.LogInformation("DPoP token from client {ClientId} does not contain a nonce claim", clientId);
            return new DPoPValidationResult
            {
                IsValid = false,
                DPoPNonce = activeDPoPNonce
            };
        }

        /*
         * If the client has a nonce, but it is not recognized in the database,
         * then it has been deleted. The active DPoPNonce is returned.
         */
        var isDPoPNonce = await _nonceRepository.IsDPoPNonce(nonce, clientId, cancellationToken);
        if (!isDPoPNonce)
        {
            _logger.LogWarning("DPoP token from client {ClientId} does not contain valid nonce {Nonce} claim", clientId, nonce);
            return new DPoPValidationResult
            {
                IsValid = false,
                DPoPNonce = activeDPoPNonce
            };
        }

        /*
         * If the client has a nonce, but it is expired,
         * then the active DPoPNonce is returned.
         */
        if (activeDPoPNonce != nonce)
        {
            _logger.LogWarning("DPoP token from client {ClientId} contains inactive nonce {Nonce} claim", clientId, nonce);
            return new DPoPValidationResult
            {
                IsValid = false,
                DPoPNonce = activeDPoPNonce
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
