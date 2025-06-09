using System.Text;
using AuthServer.Entities;

namespace AuthServer.Helpers;

internal static class PairwiseSubjectHelper
{
    public static string GenerateSubject(SectorIdentifier sectorIdentifier, string subjectIdentifier)
    {
        var host = sectorIdentifier!.GetHostComponent();
        var salt = sectorIdentifier!.Salt;
        return new StringBuilder()
            .Append(subjectIdentifier)
            .Append(host)
            .Append(salt)
            .ToString()
            .Sha256();
    }
}