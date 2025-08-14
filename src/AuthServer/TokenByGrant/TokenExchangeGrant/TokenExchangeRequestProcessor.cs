using AuthServer.Core.Abstractions;

namespace AuthServer.TokenByGrant.TokenExchangeGrant;
internal class TokenExchangeRequestProcessor : IRequestProcessor<TokenExchangeValidationRequest, TokenResponse>
{
    public Task<TokenResponse> Process(TokenExchangeValidationRequest request, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
