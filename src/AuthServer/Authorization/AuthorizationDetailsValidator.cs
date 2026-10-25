using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Cache.Abstractions;
using AuthServer.Extensions;
using AuthServer.Repositories.Abstractions;
using Microsoft.Extensions.Logging;
using System.Text.Json;

namespace AuthServer.Authorization;

internal class AuthorizationDetailsValidator : IAuthorizationDetailsValidator
{
    private readonly IClientRepository _clientRepository;
    private readonly ICachedClientStore _cachedClientStore;
    private readonly ILogger<AuthorizationDetailsValidator> _logger;
    private readonly IAuthorizationDetailValidator? _authorizationDetailValidator;

    public AuthorizationDetailsValidator(
        IClientRepository clientRepository,
        ICachedClientStore cachedClientStore,
        ILogger<AuthorizationDetailsValidator> logger,
        IAuthorizationDetailValidator? authorizationDetailValidator = null)
    {
        _clientRepository = clientRepository;
        _cachedClientStore = cachedClientStore;
        _logger = logger;
        _authorizationDetailValidator = authorizationDetailValidator;
    }

    public async Task<AuthorizationDetailsValidationResult> ValidateAuthorizationDetails(string? authorizationDetails, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(authorizationDetails))
        {
            return new AuthorizationDetailsValidationResult();
        }

        if (_authorizationDetailValidator is null)
        {
            return new AuthorizationDetailsValidationResult
            {
                Error = AuthorizationDetailsError.NotSupported
            };
        }

        var authorizationDetailsResult = await ValidateAuthorizationDetailsInternal(authorizationDetails, cancellationToken);

        if (authorizationDetailsResult is null)
        {
            return new AuthorizationDetailsValidationResult
            {
                Error = AuthorizationDetailsError.Invalid
            };
        }
        
        return new AuthorizationDetailsValidationResult
        {
            AuthorizationDetails = authorizationDetailsResult.AuthorizationDetails
        };
    }

    public async Task<AuthorizationDetailsValidationResult> AuthorizeAuthorizationDetails(string? authorizationDetails, string clientId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(authorizationDetails))
        {
            return new AuthorizationDetailsValidationResult();
        }

        if (_authorizationDetailValidator is null)
        {
            return new AuthorizationDetailsValidationResult
            {
                Error = AuthorizationDetailsError.NotSupported
            };
        }

        var authorizationDetailsResult = await ValidateAuthorizationDetailsInternal(authorizationDetails, cancellationToken);

        if (authorizationDetailsResult is null)
        {
            return new AuthorizationDetailsValidationResult
            {
                Error = AuthorizationDetailsError.Invalid
            };
        }

        var types = authorizationDetailsResult.ParsedAuthorizationDetails
            .GroupBy(x => x.Type)
            .ToDictionary(
                x => x.Key,
                x => x.SelectMany(y => y.Locations).ToList());

        var cachedClient = await _cachedClientStore.Get(clientId, cancellationToken);
        if (cachedClient.AuthorizationDetailTypes.IsDisjoint(types.Select(x => x.Key)))
        {
            return new AuthorizationDetailsValidationResult
            {
                Error = AuthorizationDetailsError.NotAuthorizedForClient
            };
        }

        foreach (var type in types)
        {
            var areResourcesAuthorizedForType = await _clientRepository.AreResourcesAuthorizedForAuthorizationDetailType(type.Value, type.Key, cancellationToken);
            if (!areResourcesAuthorizedForType)
            {
                return new AuthorizationDetailsValidationResult
                {
                    Error = AuthorizationDetailsError.NotAuthorizedForResource
                };
            }
        }

        return new AuthorizationDetailsValidationResult
        {
            AuthorizationDetails = authorizationDetailsResult.AuthorizationDetails
        };
    }

    private async Task<AuthorizationDetailsResult?> ValidateAuthorizationDetailsInternal(string authorizationDetails, CancellationToken cancellationToken)
    {
        IReadOnlyCollection<string> parsedAuthorizationDetails;

        try
        {
            using var document = JsonDocument.Parse(authorizationDetails);
            parsedAuthorizationDetails = document.RootElement
                .EnumerateArray()
                .Select(x => x.GetRawText())
                .ToList();
        }
        catch (Exception e)
        {
            _logger.LogDebug(
                e,
                "Invalid authorization_details {AuthorizationDetails} provided",
                authorizationDetails);

            return null;
        }

        var validatedAuthorizationDetails = new List<AuthorizationDetailDto>();

        foreach (var authorizationDetail in parsedAuthorizationDetails)
        {
            var validatedAuthorizationDetailDto = await _authorizationDetailValidator!.ValidateAuthorizationDetail(authorizationDetail, cancellationToken);
            if (validatedAuthorizationDetailDto is null)
            {
                return null;
            }

            validatedAuthorizationDetails.Add(validatedAuthorizationDetailDto);
        }

        return new AuthorizationDetailsResult(parsedAuthorizationDetails, validatedAuthorizationDetails);
    }

    private sealed record AuthorizationDetailsResult(IReadOnlyCollection<string> AuthorizationDetails, IReadOnlyCollection<AuthorizationDetailDto> ParsedAuthorizationDetails);
}