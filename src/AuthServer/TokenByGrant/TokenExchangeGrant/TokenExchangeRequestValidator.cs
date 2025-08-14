using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;

namespace AuthServer.TokenByGrant.TokenExchangeGrant;
internal class TokenExchangeRequestValidator : IRequestValidator<TokenRequest, TokenExchangeValidationRequest>
{
    public Task<ProcessResult<TokenExchangeValidationRequest, ProcessError>> Validate(TokenRequest request, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
