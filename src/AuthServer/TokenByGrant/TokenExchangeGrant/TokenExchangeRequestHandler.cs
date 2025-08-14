using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;

namespace AuthServer.TokenByGrant.TokenExchangeGrant;
internal class TokenExchangeRequestHandler : RequestHandler<TokenRequest, TokenExchangeValidationRequest, TokenResponse>
{
    public TokenExchangeRequestHandler(IMetricService metricService)
        : base(metricService)
    {
    }

    protected override Task<ProcessResult<TokenResponse, ProcessError>> ProcessValidatedRequest(TokenExchangeValidationRequest request, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    protected override Task<ProcessResult<TokenExchangeValidationRequest, ProcessError>> ValidateRequest(TokenRequest request, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
