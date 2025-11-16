using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.TokenDecoders.Abstractions;

namespace AuthServer.Userinfo;

internal class UserinfoRequestValidator : IRequestValidator<UserinfoRequest, UserinfoValidatedRequest>
{
    private readonly IServerTokenDecoder _serverTokenDecoder;
    
    public UserinfoRequestValidator(IServerTokenDecoder serverTokenDecoder)
    {
        _serverTokenDecoder = serverTokenDecoder;
    }

    public async Task<ProcessResult<UserinfoValidatedRequest, ProcessError>> Validate(UserinfoRequest request,
        CancellationToken cancellationToken)
    {
        // only read because the token has already been validated
        var tokenResult = await _serverTokenDecoder.Read(request.AccessToken, cancellationToken);
        return new UserinfoValidatedRequest
        {
            AuthorizationGrantId = tokenResult.GrantId!,
            Scope = tokenResult.Scope
        };
    }
}