using AuthServer.Authentication.Abstractions;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.TokenBuilders;
using AuthServer.TokenBuilders.Abstractions;
using Microsoft.Extensions.Logging;

namespace AuthServer.Authentication;
internal class ClientLogoutService : IClientLogoutService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ITokenBuilder<LogoutTokenArguments> _tokenBuilder;
    private readonly ILogger<ClientLogoutService> _logger;
    private readonly AuthorizationDbContext _authorizationDbContext;

    public ClientLogoutService(
        IHttpClientFactory httpClientFactory,
        ITokenBuilder<LogoutTokenArguments> tokenBuilder,
        ILogger<ClientLogoutService> logger,
        AuthorizationDbContext authorizationDbContext)
    {
        _httpClientFactory = httpClientFactory;
        _tokenBuilder = tokenBuilder;
        _logger = logger;
        _authorizationDbContext = authorizationDbContext;
    }

    public async Task Logout(IReadOnlyCollection<string> clientIds, string? sessionId, string? subjectIdentifier, CancellationToken cancellationToken)
    {
        var logoutRequests = new List<LogoutRequest>();
        foreach (var clientId in clientIds)
        {
            var logoutToken = await _tokenBuilder.BuildToken(
                new LogoutTokenArguments
                {
                    ClientId = clientId,
                    SessionId = sessionId,
                    SubjectIdentifier = subjectIdentifier
                },
                cancellationToken);

            var client = (await _authorizationDbContext.FindAsync<Client>([clientId], cancellationToken))!;

            logoutRequests.Add(new LogoutRequest(clientId, client.BackchannelLogoutUri!, logoutToken));
        }

        await Parallel.ForEachAsync(
            logoutRequests,
            cancellationToken,
            async (logoutRequest, innerToken) =>
            {
                var httpClient = _httpClientFactory.CreateClient(HttpClientNameConstants.Client);

                var body = new Dictionary<string, string>
                {
                    { Parameter.LogoutToken, logoutRequest.LogoutToken }
                };

                var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, logoutRequest.LogoutUri)
                {
                    Content = new FormUrlEncodedContent(body)
                };

                try
                {
                    var response = await httpClient.SendAsync(httpRequestMessage, innerToken);
                    response.EnsureSuccessStatusCode();
                }
                catch (HttpRequestException e)
                {
                    _logger.LogWarning(e, "Error occurred requesting logout for client {ClientId}", logoutRequest.ClientId);
                }
            });
    }

    private sealed record LogoutRequest(string ClientId, string LogoutUri, string LogoutToken);
}
