namespace AuthServer.Repositories.Abstractions;

internal interface IUserCodeRepository
{
    Task RedeemUserCode(string userCode, CancellationToken cancellationToken);
}