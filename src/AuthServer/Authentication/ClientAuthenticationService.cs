using System.Diagnostics;
using AuthServer.Authentication.Abstractions;
using AuthServer.Authentication.Models;
using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Enums;
using AuthServer.Extensions;
using AuthServer.Helpers;
using AuthServer.Metrics.Abstractions;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.Extensions.Logging;

namespace AuthServer.Authentication;
internal class ClientAuthenticationService : IClientAuthenticationService
{
    private readonly ILogger<ClientAuthenticationService> _logger;
    private readonly ICachedClientStore _cachedClientStore;
    private readonly IClientTokenDecoder _clientTokenDecoder;
    private readonly IMetricService _metricService;

    public ClientAuthenticationService(
        ILogger<ClientAuthenticationService> logger,
        ICachedClientStore cachedClientStore,
        IClientTokenDecoder clientTokenDecoder,
        IMetricService metricService)
    {
        _logger = logger;
        _cachedClientStore = cachedClientStore;
        _clientTokenDecoder = clientTokenDecoder;
        _metricService = metricService;
    }

    /// inheritdoc/>
    public async Task<ClientAuthenticationResult> AuthenticateClient(ClientAuthentication clientAuthentication, CancellationToken cancellationToken)
    {
        var stopWatch = Stopwatch.StartNew();
        var result = clientAuthentication switch
        {
            ClientIdAuthentication clientIdAuthentication => await AuthenticateClientId(clientIdAuthentication, cancellationToken),
            ClientSecretAuthentication clientSecretAuthentication => await AuthenticateClientSecret(
                clientSecretAuthentication, cancellationToken),
            ClientAssertionAuthentication clientAssertionAuthentication => await AuthenticateClientAssertion(
                clientAssertionAuthentication, cancellationToken),
            _ => throw new NotSupportedException("authentication method is unsupported")
        };
        stopWatch.Stop();
        _metricService.AddClientAuthenticated(stopWatch.ElapsedMilliseconds, result.ClientId);

        return result;
    }

    private async Task<ClientAuthenticationResult> AuthenticateClientId(ClientIdAuthentication clientIdAuthentication, CancellationToken cancellationToken)
    {
        var client = await _cachedClientStore.TryGet(clientIdAuthentication.ClientId, cancellationToken);

        if (client is null)
        {
            _logger.LogWarning("ClientId {ClientId} does not exist", clientIdAuthentication.ClientId);
            return new ClientAuthenticationResult(null, false);
        }

        if (client.TokenEndpointAuthMethod != TokenEndpointAuthMethod.None)
        {
            _logger.LogWarning("Client {ClientId} is not registered for None", client.Id);
            return new ClientAuthenticationResult(null, false);
        }

        return new ClientAuthenticationResult(clientIdAuthentication.ClientId, true);
    }

    private async Task<ClientAuthenticationResult> AuthenticateClientSecret(ClientSecretAuthentication clientSecretAuthentication, CancellationToken cancellationToken)
    {
        var client = await _cachedClientStore.TryGet(clientSecretAuthentication.ClientId, cancellationToken);

        if (client is null)
        {
            _logger.LogWarning("ClientId {ClientId} does not exist", clientSecretAuthentication.ClientId);
            return new ClientAuthenticationResult(null, false);
        }

        if (client.TokenEndpointAuthMethod != clientSecretAuthentication.Method)
        {
            _logger.LogWarning("Client {ClientId} is not registered for {TokenEndpointAuthMethod}", client.Id, clientSecretAuthentication.Method);
            return new ClientAuthenticationResult(null, false);
        }

        if (client.SecretExpiresAt is not null
            && client.SecretExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("ClientSecret has expired at {Expiration}", client.SecretExpiresAt);
            return new ClientAuthenticationResult(null, false);
        }

        var isPasswordVerified = CryptographyHelper.VerifyPassword(client.SecretHash!, clientSecretAuthentication.ClientSecret);
        if (!isPasswordVerified)
        {
            _logger.LogWarning("ClientSecret is invalid");
            return new ClientAuthenticationResult(null, false);
        }

        return new ClientAuthenticationResult(client.Id, true);
    }

    private async Task<ClientAuthenticationResult> AuthenticateClientAssertion(ClientAssertionAuthentication clientAssertionAuthentication, CancellationToken cancellationToken)
    {
        var clientAssertionIsPrivateKey = clientAssertionAuthentication.ClientAssertionType ==
                                          ClientAssertionTypeConstants.PrivateKeyJwt;

        if (!clientAssertionIsPrivateKey)
        {
            _logger.LogDebug("Incorrect client_assertion_type");
            return new ClientAuthenticationResult(null, false);
        }

        var clientId = clientAssertionAuthentication.ClientId;
        if (string.IsNullOrWhiteSpace(clientId))
        {
            var unvalidatedToken = await _clientTokenDecoder.Read(clientAssertionAuthentication.ClientAssertion);
            clientId = unvalidatedToken.Issuer;
        }

        var client = await _cachedClientStore.TryGet(clientId, cancellationToken);

        if (client is null)
        {
            _logger.LogWarning("ClientId {ClientId} does not exist", clientId);
            return new ClientAuthenticationResult(null, false);
        }

        if (client.TokenEndpointAuthMethod != TokenEndpointAuthMethod.PrivateKeyJwt)
        {
            _logger.LogWarning("Client {ClientId} is not registered for PrivateKeyJwt", clientId);
            return new ClientAuthenticationResult(null, false);
        }

        List<string> algorithms = [client.TokenEndpointAuthSigningAlg!.GetDescription()];
        if (client.TokenEndpointAuthEncryptionEnc is not null)
        {
            algorithms.Add(client.TokenEndpointAuthEncryptionEnc.GetDescription());
        }
        var validatedToken = await _clientTokenDecoder.Validate(
            clientAssertionAuthentication.ClientAssertion,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = algorithms,
                ClientId = clientId,
                SubjectId = clientId,
                Audience = clientAssertionAuthentication.Audience,
                ValidateLifetime = true
            },
            cancellationToken);

        if (validatedToken is null)
        {
            return new ClientAuthenticationResult(null, false);
        }

        return new ClientAuthenticationResult(clientId, true);
    }
}