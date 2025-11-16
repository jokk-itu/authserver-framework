using System.Diagnostics;
using System.Diagnostics.Metrics;
using AuthServer.Extensions;
using AuthServer.Metrics.Abstractions;

namespace AuthServer.Metrics;
internal sealed class MetricService : IMetricService, IDisposable
{
    private const string ClientId = "client_id";

    private readonly Meter _meter;

    private readonly Counter<int> _tokenBuiltAmount;
    private readonly Counter<int> _validateServerTokenAmount;
    private readonly Counter<int> _validateClientTokenAmount;
    private readonly Counter<int> _tokenIntrospectedAmount;
    private readonly Counter<int> _tokenRevokedAmount;

    private readonly Histogram<double> _tokenBuildTime;
    private readonly Histogram<double> _validateServerTokenTime;
    private readonly Histogram<double> _validateClientTokenTime;

    private readonly Histogram<double> _clientAuthenticationTime;

    private readonly Histogram<double> _authorizeInteractionTime;

    private readonly Histogram<double> _registerGetClientTime;
    private readonly Histogram<double> _registerDeleteClientTime;
    private readonly Histogram<double> _registerUpdateClientTime;

    public MetricService(IMeterFactory meterFactory)
    {
        ActivitySource = new ActivitySource("AuthServer");
        _meter = meterFactory.Create("AuthServer");

        _tokenBuiltAmount = _meter.CreateCounter<int>("authserver.token.built.count", "The amount of tokens built.");
        _validateServerTokenAmount = _meter.CreateCounter<int>("authserver.token.server.validate.count", "The amount of server tokens validated.");
        _validateClientTokenAmount = _meter.CreateCounter<int>("authserver.token.client.validate.count", "The amount of client tokens validated.");
        _tokenIntrospectedAmount = _meter.CreateCounter<int>("authserver.token.introspected.count", "The amount of tokens introspected.");
        _tokenRevokedAmount = _meter.CreateCounter<int>("authserver.token.revoked.count", "The amount of tokens revoked.");

        _tokenBuildTime = _meter.CreateHistogram<double>("authserver.token.built.duration", "The time it takes for a token to be built.");
        _validateServerTokenTime = _meter.CreateHistogram<double>("authserver.token.server.validate.duration", "The time it takes for a server token to be validated.");
        _validateClientTokenTime = _meter.CreateHistogram<double>("authserver.token.client.validate.duration", "The time it takes for a client token to be validated.");

        _clientAuthenticationTime = _meter.CreateHistogram<double>("authserver.client.authenticated.duration", "The time it takes for a client to be authenticated.");

        _authorizeInteractionTime = _meter.CreateHistogram<double>("authserver.authorize.interaction.duration", "The time it takes to deduce the interaction during authorize");

        _registerGetClientTime = _meter.CreateHistogram<double>("authserver.register.client.get", "The time it takes to get the client");
        _registerDeleteClientTime = _meter.CreateHistogram<double>("authserver.register.client.delete", "The time it takes to delete the client");
        _registerUpdateClientTime = _meter.CreateHistogram<double>("authserver.register.client.update", "The time it takes to update the client");
    }

    public ActivitySource ActivitySource { get; }

    public void AddBuiltToken(long durationMilliseconds, TokenTypeTag tokenTypeTag, TokenStructureTag tokenStructureTag)
    {
        var tags = new[]
        {
            new KeyValuePair<string, object?>("typ", tokenTypeTag.GetDescription()),
            new KeyValuePair<string, object?>("structure", tokenStructureTag.GetDescription())
        };

        _tokenBuiltAmount.Add(1, tags);
        _tokenBuildTime.Record(durationMilliseconds, tags);
    }

    public void AddValidateServerToken(long durationMilliseconds, TokenTypeTag? tokenTypeTag, TokenStructureTag tokenStructureTag)
    {
        var tags = new[]
        {
            new KeyValuePair<string, object?>("typ", tokenTypeTag?.GetDescription()),
            new KeyValuePair<string, object?>("structure", tokenStructureTag.GetDescription())
        };

        _validateServerTokenAmount.Add(1, tags);
        _validateServerTokenTime.Record(durationMilliseconds, tags);
    }

    public void AddValidateClientToken(long durationMilliseconds, TokenTypeTag? tokenTypeTag)
    {
        var tags = new[]
        {
            new KeyValuePair<string, object?>("typ", tokenTypeTag?.GetDescription())
        };

        _validateClientTokenAmount.Add(1, tags);
        _validateClientTokenTime.Record(durationMilliseconds, tags);
    }

    public void AddIntrospectedToken(TokenTypeTag tokenTypeTag)
    {
        _tokenIntrospectedAmount.Add(1, new KeyValuePair<string, object?>("typ", tokenTypeTag.GetDescription()));
    }

    public void AddRevokedToken(TokenTypeTag tokenTypeTag)
    {
        _tokenRevokedAmount.Add(1, new KeyValuePair<string, object?>("typ", tokenTypeTag.GetDescription()));
    }

    public void AddClientAuthenticated(long durationMilliseconds, string? clientId)
    {
        _clientAuthenticationTime.Record(durationMilliseconds, new KeyValuePair<string, object?>(ClientId, clientId));
    }

    public void AddAuthorizeInteraction(long durationMilliseconds, string clientId, string prompt, AuthenticationKind? authenticationKind)
    {
        _authorizeInteractionTime.Record(
            durationMilliseconds,
            new KeyValuePair<string, object?>(ClientId, clientId),
            new KeyValuePair<string, object?>("prompt", prompt),
            new KeyValuePair<string, object?>("authentication_kind", authenticationKind));
    }

    public void AddClientDelete(long durationMilliseconds)
    {
        _registerDeleteClientTime.Record(durationMilliseconds);
    }

    public void AddClientUpdate(long durationMilliseconds, string clientId)
    {
        _registerUpdateClientTime.Record(durationMilliseconds, new KeyValuePair<string, object?>(ClientId, clientId));
    }

    public void AddClientGet(long durationMilliseconds, string clientId)
    {
        _registerGetClientTime.Record(durationMilliseconds, new KeyValuePair<string, object?>(ClientId, clientId));
    }

    public void Dispose()
    {
        ActivitySource.Dispose();
        _meter.Dispose();
    }
}