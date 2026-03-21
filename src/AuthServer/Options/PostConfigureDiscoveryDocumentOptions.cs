using AuthServer.Constants;
using Microsoft.Extensions.Options;

namespace AuthServer.Options;

internal class PostConfigureDiscoveryDocumentOptions : IPostConfigureOptions<DiscoveryDocument>
{
	public void PostConfigure(string? name, DiscoveryDocument options)
	{
		ScopeConstants.Scopes
			.Where(x => !options.ScopesSupported.Contains(x))
			.ToList()
			.ForEach(options.ScopesSupported.Add);

        if (!options.GrantManagementActionsSupported.Contains(GrantManagementActionConstants.Create))
        {
			options.GrantManagementActionsSupported.Add(GrantManagementActionConstants.Create);
        }
	}
}