<script lang="ts">
    import { base } from "$app/paths";
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('OAuth2.1', 'https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/'), new RowCellDefinition('Core specification for OAuth') ],
        [ new RowCellDefinition('OpenId Connect', 'https://openid.net/specs/openid-connect-core-1_0.html'), new RowCellDefinition('Core specification for OpenId Connect') ]
    ];    
</script>

<svelte:head>
	<title>Authorization Code Grant</title>
</svelte:head>

<PageTitle title="Authorization Code" />
<Section title="Introduction">
    <p>
        The authorization code grant type is used to exchange a code for an access token,
        id token and optional refresh token.
    </p>
    <br>
    <p>
        The following image shows the authorization code flow, from authenticating at the authorize endpoint,
        to exchanging the authorization code for tokens.
    </p>
    <figure>
        <img class="mx-auto" src="{base}/authorization-code.png" alt="authorization code flow" />
        <figCaption class="text-center">Image 1: Authorization Code flow</figCaption>
    </figure>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Authorize Endpoint">
    <p>Triggering the authorization code flow starts at the authorize endpoint,
        by requesting with the parameter "response_type" and value "code".
    </p>
    <p>
        The code returned from the IdentityProvider is encrypted,
        and contains information related to the original request,
        such that it can be validated and correlated to the token request.
    </p>
    <p>For example, it contains the redirect_uri, code_challenge, dpop_jkt and more.</p>
    <br>
    <p>The following HTTP example shows an authorize request with the response_type.
        The example is not complete to better illustrate the flow.</p>
    <CodeBlock>
        {`
GET /connect/authorize?response_type=code HTTP/1.1
Host: idp.authserver.dk
        `}
    </CodeBlock>
    <p>The following HTTP example shows an authorize response with a code.
        The example is not complete to better illustrate the flow.</p>
    <CodeBlock>
        {`
HTTP/1.1 303 SeeOther
Location: https://web-client.authserver.dk/callback?code=SplxlOBeZQQYbYS6WxSbIA
        `}
    </CodeBlock>
</Section>
<Section title="Token Endpoint">
    <p>
        The returned code is then used in the subsequent token request, in exchange for tokens.
    </p>
    <br>
    <p>The following HTTP example shows a token request using the code from the identity provider.
        The example is not complete to better illustrate the flow.</p>
    <CodeBlock>
        {`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&resource=https%3A%2F%2Fapi-one.protectedresource.dk
        `}
    </CodeBlock>
    <p>The following HTTP example shows a token response containing tokens exchanged from an authoriazation_code.
        The example is not complete to better illustrate the flow.
    </p>
    <CodeBlock>
        {`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "access_token":"2YotnFZFEjr1zCsicMWpAA",
  "token_type":"Bearer",
  "expires_in":3600,
  "id_token":"eyJhbGciOiJSUzI1NiIsImtpZCI...",
  "grant_id":"78FF77E8-F146-4F37-9C28-5FD0BC936980"
}
        `}
    </CodeBlock>
</Section>