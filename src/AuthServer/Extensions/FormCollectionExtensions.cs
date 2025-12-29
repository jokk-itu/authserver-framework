using AuthServer.Authentication.Models;
using AuthServer.Core;
using AuthServer.Enums;
using AuthServer.TokenDecoders;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace AuthServer.Extensions;

internal static class FormCollectionExtensions
{
    extension(IFormCollection formCollection)
    {
        public ClientAuthentication? GetClientSecretPost()
        {
            formCollection.TryGetValue(Parameter.ClientId, out var clientId);
            formCollection.TryGetValue(Parameter.ClientSecret, out var clientSecret);

            var isClientSecretPost = !string.IsNullOrWhiteSpace(clientId) && !string.IsNullOrWhiteSpace(clientSecret);
            return isClientSecretPost
                ? new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretPost, clientId!, clientSecret!)
                : null;
        }

        public ClientAuthentication? GetClientId()
        {
            formCollection.TryGetValue(Parameter.ClientId, out var clientId);
            formCollection.TryGetValue(Parameter.ClientSecret, out var clientSecret);
            formCollection.TryGetValue(Parameter.ClientAssertion, out var clientAssertion);
            formCollection.TryGetValue(Parameter.ClientAssertionType, out var clientAssertionType);

            var hasSecretOrAssertion = !string.IsNullOrEmpty(clientSecret)
                                       || !string.IsNullOrEmpty(clientAssertion)
                                       || !string.IsNullOrEmpty(clientAssertionType);

            var isClientId = !string.IsNullOrWhiteSpace(clientId) && !hasSecretOrAssertion;
            return isClientId
                ? new ClientIdAuthentication(clientId!)
                : null;
        }

        public ClientAuthentication? GetClientAssertion(ClientTokenAudience clientTokenAudience)
        {
            formCollection.TryGetValue(Parameter.ClientId, out var clientId);
            formCollection.TryGetValue(Parameter.ClientAssertion, out var clientAssertion);
            formCollection.TryGetValue(Parameter.ClientAssertionType, out var clientAssertionType);

            var isClientAssertion = !string.IsNullOrWhiteSpace(clientAssertion)
                                    && !string.IsNullOrWhiteSpace(clientAssertionType);

            return isClientAssertion
                ? new ClientAssertionAuthentication(clientTokenAudience, clientId, clientAssertionType!, clientAssertion!)
                : null;
        }

        public string? GetValue(string key)
        {
            formCollection.TryGetValue(key, out var value);
            return value == StringValues.Empty ? null : value.ToString();
        }

        public IReadOnlyCollection<string> GetSpaceDelimitedValue(string key)
        {
            formCollection.TryGetValue(key, out var value);
            var hasValue = !StringValues.IsNullOrEmpty(value);
            return !hasValue ? [] : value.ToString().Split(' ');
        }

        public IReadOnlyCollection<string> GetCollectionValue(string key)
        {
            formCollection.TryGetValue(key, out var value);
            var hasValue = !StringValues.IsNullOrEmpty(value);
            return (!hasValue ? [] : value.AsReadOnly())!;
        }
    }
}