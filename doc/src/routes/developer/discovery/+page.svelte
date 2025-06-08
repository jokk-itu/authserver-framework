<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('OpenId Connect Discovery', 'https://openid.net/specs/openid-connect-discovery-1_0.html'), new RowCellDefinition('Core specification for OpenId Connect Discovery') ],
        [ new RowCellDefinition('OAuth Discovery', 'https://datatracker.ietf.org/doc/html/rfc8414'), new RowCellDefinition('Core specification for OAuth Discovery') ]
    ];

    let metadataHeaders: string[] = ["Name", "Description"];
    let metadataRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('issuer'), new RowCellDefinition('URL of authserver instance') ],
        [ new RowCellDefinition('service_documentation'), new RowCellDefinition('URL of authserver documentation') ],
        [ new RowCellDefinition('op_policy_uri'), new RowCellDefinition('URL of authserver policy page') ],
        [ new RowCellDefinition('op_tos_uri'), new RowCellDefinition('URL of authserver terms-of-service page') ],
        [ new RowCellDefinition('authorization_endpoint'), new RowCellDefinition('URL of authserver authorize endpoint') ],
        [ new RowCellDefinition('token_endpoint'), new RowCellDefinition('URL of authserver token endpoint') ],
        [ new RowCellDefinition('userinfo_endpoint'), new RowCellDefinition('URL of authserver userinfo endpoint') ],
        [ new RowCellDefinition('jwks_uri'), new RowCellDefinition('URL of authserver jwks endpoint') ],
        [ new RowCellDefinition('registration_endpoint'), new RowCellDefinition('URL of authserver registration endpoint') ],
        [ new RowCellDefinition('endsession_endpoint'), new RowCellDefinition('URL of authserver endsession endpoint') ],
        [ new RowCellDefinition('introspection_endpoint'), new RowCellDefinition('URL of authserver introspection endpoint') ],
        [ new RowCellDefinition('revocation_endpoint'), new RowCellDefinition('URL of authserver revocation endpoint') ],
        [ new RowCellDefinition('pushed_authorization_request_endpoint'), new RowCellDefinition('URL of authserver pushed authorization request endpoint') ],
        [ new RowCellDefinition('grant_management_endpoint'), new RowCellDefinition('URL of authserver grant management endpoint') ],

        [ new RowCellDefinition('protected_resources'), new RowCellDefinition('URLS for protected resources that accept tokens from authserver') ],
        [ new RowCellDefinition('claims_supported'), new RowCellDefinition('Claims that are supported by authserver') ],
        [ new RowCellDefinition('scopes_supported'), new RowCellDefinition('Scopes that are supported by authserver') ],
        [ new RowCellDefinition('acr_values_supported'), new RowCellDefinition('Acr values that are supported by authserver') ],
        [ new RowCellDefinition('claim_types_supported'), new RowCellDefinition('Claim types that are supported by authserver') ],
        [ new RowCellDefinition('prompt_values_supported'), new RowCellDefinition('Prompt values that are supported by authserver') ],
        [ new RowCellDefinition('display_values_supported'), new RowCellDefinition('Display values that are supported by authserver') ],
        [ new RowCellDefinition('subject_values_supported'), new RowCellDefinition('Subject types that are supported by authserver') ],
        [ new RowCellDefinition('grant_types_supported'), new RowCellDefinition('Grant types that are supported by authserver') ],
        [ new RowCellDefinition('challenge_methods_supported'), new RowCellDefinition('Challenge methods that are supported by authserver') ],
        [ new RowCellDefinition('responses_types_supported'), new RowCellDefinition('Response types that are supported by authserver') ],
        [ new RowCellDefinition('response_modes_supported'), new RowCellDefinition('Response modes that are supported by authserver') ],

        [ new RowCellDefinition('introspection_endpoint_auth_methods_supported'), new RowCellDefinition('Introspection endpoint auth modes that are supported by authserver') ],
        [ new RowCellDefinition('revocation_endpoint_auth_methods_supported'), new RowCellDefinition('Revocation endpoint auth modes that are supported by authserver') ],
        [ new RowCellDefinition('token_endpoint_auth_methods_supported'), new RowCellDefinition('Token endpoint auth modes that are supported by authserver') ],
        [ new RowCellDefinition('grant_management_actions_supported'), new RowCellDefinition('Grant management actions that are supported by authserver') ],
        [ new RowCellDefinition('id_token_signing_alg_values_supported'), new RowCellDefinition('Id token signing alg values that are supported by authserver') ],
        [ new RowCellDefinition('id_token_encryption_alg_values_supported'), new RowCellDefinition('Id token encryption alg values that are supported by authserver') ],
        [ new RowCellDefinition('id_token_encryption_enc_values_supported'), new RowCellDefinition('Id token encryption enc values that are supported by authserver') ],
        [ new RowCellDefinition('userinfo_token_signing_alg_values_supported'), new RowCellDefinition('Userinfo token signing alg values that are supported by authserver') ],
        [ new RowCellDefinition('userinfo_token_encryption_alg_values_supported'), new RowCellDefinition('Userinfo token encryption alg values that are supported by authserver') ],
        [ new RowCellDefinition('userinfo_token_encryption_enc_values_supported'), new RowCellDefinition('Userinfo token encryption enc values that are supported by authserver') ],
        [ new RowCellDefinition('request_object_token_signing_alg_values_supported'), new RowCellDefinition('Request object token signing alg values that are supported by authserver') ],
        [ new RowCellDefinition('request_object_token_encryption_alg_values_supported'), new RowCellDefinition('Request object token encryption alg values that are supported by authserver') ],
        [ new RowCellDefinition('request_object_token_encryption_enc_values_supported'), new RowCellDefinition('Request object token encryption enc values that are supported by authserver') ],
        [ new RowCellDefinition('token_endpoint_auth_signing_alg_values'), new RowCellDefinition('Token endpoint auth signing alg values that are supported by authserver') ],
        [ new RowCellDefinition('token_endpoint_auth_encryption_alg_values'), new RowCellDefinition('Token endpoint auth encryption alg values that are supported by authserver') ],
        [ new RowCellDefinition('token_endpoint_auth_encryption_enc_values'), new RowCellDefinition('Token endpoint auth encryption enc values that are supported by authserver') ],
        [ new RowCellDefinition('dpop_signing_alg_values_supported'), new RowCellDefinition('DPoP token signing alg values that are supported by authserver') ],

        [ new RowCellDefinition('authorization_response_iss_parameter_supported'), new RowCellDefinition('Is the iss parameter in authorization responses supported by authserver') ],
        [ new RowCellDefinition('backchannel_logout_supported'), new RowCellDefinition('Is backchannel logout supported by authserver') ],
        [ new RowCellDefinition('require_request_uri_registration'), new RowCellDefinition('Is request uri registration required by authserver') ],
        [ new RowCellDefinition('claims_parameter_supported'), new RowCellDefinition('Is claims parameter supported by authserver') ],
        [ new RowCellDefinition('request_parameter_supported'), new RowCellDefinition('Is request parameter supported by authserver') ],
        [ new RowCellDefinition('request_uri_parameter_supported'), new RowCellDefinition('Is request uri parameter supported by authserver') ],
        [ new RowCellDefinition('require_signed_request_object'), new RowCellDefinition('Is request parameter required by authserver') ],
        [ new RowCellDefinition('require_pushed_authorization_requests'), new RowCellDefinition('Is pushed authorization requests required by authserver') ],
        [ new RowCellDefinition('grant_management_action_required'), new RowCellDefinition('Is grant management action required by authserver') ]
    ];
</script>

<svelte:head>
	<title>Discovery Metadata Endpoint</title>
</svelte:head>

<PageTitle title="Discovery" />
<Section title="Introduction">
    <p>The discovery endpoint returns a JSON document containing metadata about AuthServer, such as endpoints and supported functionality.</p>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Discovery Endpoint">
    <p>The discovery endpoint is invoked through HTTP using the GET method.</p>
    <p>The following example is a GET request to the discovery endpoint.</p>
    <CodeBlock>
        {`
GET /.well-known/openid-configuration HTTP/1.1
Host: idp.authserver.dk
        `}
    </CodeBlock>
    <p>The following example is a GET response from the discovery endpoint.
        The response is not complete, but contains an example of each type that is returned.</p>
    <CodeBlock>
        {`
HTTP/1.1 200 OK
Content-Type: appication/json;charset=UTF-8
Cache-Control: max-age=86400, public, must-revalidate

{
  "issuer": "https://idp.authserver.dk",
  "scopes_supported": ["openid", "profile"],
  "token_endpoint_auth_signing_alg_values": ["RS256"],
  "backchannel_logout_supported": true
}
        `}
    </CodeBlock>
    <p>The following table describes the fields in the JSON document.</p>
    <Table title="Metadata fields" tableNumber={2} headers={metadataHeaders} rowCellDefinitions={metadataRows} />
</Section>