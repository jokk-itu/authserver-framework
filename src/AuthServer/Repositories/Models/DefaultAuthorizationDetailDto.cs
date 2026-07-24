using AuthServer.Authorization.Models;
using System.Text.Json.Serialization;

namespace AuthServer.Repositories.Models;

public class DefaultAuthorizationDetailDto : AuthorizationDetailDto
{
    /// <summary>
    /// The raw JSON string of the authorization detail. It is required.
    /// </summary>
    [JsonIgnore]
    public string Raw { get; set; } = null!;
}