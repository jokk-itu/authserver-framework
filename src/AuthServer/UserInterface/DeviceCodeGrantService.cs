using AuthServer.Authorize.Abstractions;
using AuthServer.Constants;
using AuthServer.Repositories.Abstractions;
using AuthServer.UserInterface.Abstractions;

namespace AuthServer.UserInterface;
internal class DeviceCodeGrantService : IDeviceCodeGrantService
{
    private readonly IAuthenticationContextReferenceResolver _authenticationContextReferenceResolver;
    private readonly IAuthorizationGrantRepository _authorizationGrantRepository;
    private readonly IUserCodeRepository _userCodeRepository;

    public DeviceCodeGrantService(
        IAuthenticationContextReferenceResolver authenticationContextReferenceResolver,
        IAuthorizationGrantRepository authorizationGrantRepository,
        IUserCodeRepository userCodeRepository)
    {
        _authenticationContextReferenceResolver = authenticationContextReferenceResolver;
        _authorizationGrantRepository = authorizationGrantRepository;
        _userCodeRepository = userCodeRepository;
    }

    public async Task<string> HandleDeviceCodeAuthorizationGrant(string subjectIdentifier, DeviceAuthorizeDto deviceAuthorizeDto, IReadOnlyCollection<string> amr, CancellationToken cancellationToken)
    {
        var isCreateAction = string.IsNullOrEmpty(deviceAuthorizeDto.GrantManagementAction)
                             || deviceAuthorizeDto.GrantManagementAction == GrantManagementActionConstants.Create;

        var acr = await _authenticationContextReferenceResolver.ResolveAuthenticationContextReference(amr, cancellationToken);

        if (isCreateAction)
        {
            var grant = await _authorizationGrantRepository.CreateDeviceCodeGrant(
                subjectIdentifier,
                deviceAuthorizeDto.ClientId,
                acr,
                amr,
                cancellationToken);

            return grant.Id;
        }
        else
        {
            var grantId = deviceAuthorizeDto.AuthorizationGrantId;
            if (grantId is null)
            {
                throw new ArgumentException("AuthorizationGrantId must not be null", nameof(deviceAuthorizeDto));
            }

            await _authorizationGrantRepository.UpdateAuthorizationGrant(
                grantId,
                acr,
                amr,
                cancellationToken);

            return grantId;
        }
    }

    public async Task RedeemUserCode(string userCode, CancellationToken cancellationToken)
    {
        await _userCodeRepository.RedeemUserCode(userCode, cancellationToken);
    }
}