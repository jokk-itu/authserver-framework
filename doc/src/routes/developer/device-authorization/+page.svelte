<script lang="ts">
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import { base } from "$app/paths";
    import InformationBanner from "../../../components/InformationBanner.svelte";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('Device Authorization', 'https://datatracker.ietf.org/doc/html/rfc8628'), new RowCellDefinition('Specification for device authorization') ]
    ];

    let deviceAuthorizationRequestHeaders: string[] = ["Name", "Description"];
    let deviceAuthorizationRequestFields: RowCellDefinition[][] = [
        [ new RowCellDefinition("code_challenge"), new RowCellDefinition("Hash of random string used to verify the requester between authorization and token endpoints.") ],
        [ new RowCellDefinition("code_challenge_method"), new RowCellDefinition("Name of the hashing method used for the code_challenge") ],
        [ new RowCellDefinition("nonce"), new RowCellDefinition("") ],
        [ new RowCellDefinition("grant_id"), new RowCellDefinition("") ],
        [ new RowCellDefinition("grant_management_action"), new RowCellDefinition("") ],
        [ new RowCellDefinition("scope"), new RowCellDefinition("") ],
        [ new RowCellDefinition("acr_values"), new RowCellDefinition("") ],
        [ new RowCellDefinition("resource"), new RowCellDefinition("") ],   
    ];

    let deviceAuthorizationResponseHeaders: string[] = ["Name", "Description"];
    let deviceAuthorizationResponseFields: RowCellDefinition[][] = [
        [ new RowCellDefinition("device_code"), new RowCellDefinition("") ],
        [ new RowCellDefinition("user_code"), new RowCellDefinition("") ],
        [ new RowCellDefinition("verification_uri"), new RowCellDefinition("") ],
        [ new RowCellDefinition("verification_uri_complete"), new RowCellDefinition("") ],
        [ new RowCellDefinition("expires_in"), new RowCellDefinition("") ],
        [ new RowCellDefinition("interval"), new RowCellDefinition("") ],
    ];
</script>

<svelte:head>
	<title>Device Authorization</title>
</svelte:head>

<PageTitle title="Device Authorization" />
<Section title="Introduction">
    <p>
        Device Authorization is used to issue a code, which can be used to exchange tokens at the token endpoint,
        using the device code grant type.
    </p>
    <br>
    <p>
        The flow is used for clients which cannot authenticate the end user, for example an app on a smart tv.
    </p>
    <p>
        Upon getting the code from the device authorization endpoint, the end-user is instructed to access the identity provider from another device, where they can authenticate.
        For example through their phone or computer.
    </p>
    <p>
        Simultaneously the app also polls the token endpoint using its own code, and once the end-user has redeemed their code through authentication, the app successfully redeems its own code and receives tokens.
    </p>
    <br>
    <figure>
        <img class="mx-auto" src="{base}/device-authorization.png" alt="device authorization flow" />
        <figCaption class="text-center">Image 1: Device Authorization flow</figCaption>
    </figure>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Device Authorization Endpoint">
    <p>
        The client starts by invoking the device authorization endpoint.
    </p>
    <p>
        It receives a device code, which is used to poll the token endpoint, until the identity provider returns that the authorization attempt has failed or successfully and tokens are returned.
    </p>
    <p>
        It also receives a user, which is used by the end user to authenticate at the identity provider, through another device, such as a computer or a phone.
    </p>
    <br>
    <Table title="Device Authorization request parameters" tableNumber={2} headers={deviceAuthorizationRequestHeaders} rowCellDefinitions={deviceAuthorizationRequestFields} />
    <br>
    <p>
        The endpoint supports DPoP, and can prove possession from authorization to the token endpoint.
    </p>
    <p>
        The endpoint supports client authentication for public and confidential clients.
    </p>
    <br>
    <Table title="Device Authorzation response parameters" tableNumber={3} headers={deviceAuthorizationResponseHeaders} rowCellDefinitions={deviceAuthorizationResponseFields} />
    <br>
    <p>
        The following HTTP request is an example of the device authorization endpoint.   
    </p>
    <CodeBlock>
         {`
POST /connect/device-authorization HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

code_challenge=cf4957ce5fea8d2fdf0ab6edb93b78331c15c1e94fb052
&code_challenge_method=S256
&nonce=0ad740f0794057ab635a80590907e8b5
&scope=openid%20account:delete
&resource=https://api.authserver.dk
&client_id=3a2e766d-ba78-47f5-9daa-1f3f106a5aa3
        `}
    </CodeBlock>
    <br>
    <p>
        The following HTTP response is an example of the device authorization endpoint.
    </p>
    <CodeBlock>
        {`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "device_code":"2YotnFZFEjr1zCsicMWpAA",
  "user_code":"AUPFLMQE",
  "verification_uri":"https://idp.authserver.dk/device",
  "verification_uri_complete":"https://idp.authserver.dk/device?user_code=AUPFLMQE",
  "expires_in":300,
  "interval":5
}
        `}
    </CodeBlock>
    <br>
    <p>
        The following HTTP resposne is an example of a failure at the device authorization endpoint,
        where the client does not request the openid scope.
    </p>
    <CodeBlock>
        {`
HTTP/1.1 400 BadRequest
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "error":"invalid_scope",
  "error_description":"openid is required"
}
        `}
    </CodeBlock>
</Section>
<Section title="Redeeming the user code">
    <p>
        Once the end user has the user code, they have to navigate to the device endpoint on their secondary device and authenticate.
    </p>
    <InformationBanner>The device endpoint is custom, and needs to be implemented by you. It must allow the end user to authenticate, like at the authorize endpoint during the authorization code grant type.</InformationBanner>
</Section>
<Section title="Device Code Grant">
    <p>
        Once the client has requested the device authorization endpoint successfully, it receives a device code.
    </p>
    <p>
        It starts polling the token endpoint, using the device code grant type, and polls in the interval returned from the device authorization endpoint.
        Default is every 5 seconds.
    </p>
    <br>
    <p>
        The following HTTP request is an example of a polling request at the token endpoint.
    </p>
    <CodeBlock>
        {`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=urn:ietf:params:oauth:grant-type:device_code
&device_code=2YotnFZFEjr1zCsicMWpAA
        `}
    </CodeBlock>
    <br>
    <p>
        The following HTTP response ia an example of a pending polling response at the token endpoint.
    </p>
    <CodeBlock>
        {`
HTTP/1.1 400 BadRequest
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "error":"authorization_pending",
  "error_description":"device authorization is pending"
}
        `}
    </CodeBlock>
    <br>
    <p>
        The following HTTP response is an example of a successfull polling response at the token endpoint.
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
  "grant_id":"78FF77E8-F146-4F37-9C28-5FD0BC936980",
  "scope": "account:update account:delete"
}
        `}
    </CodeBlock>
    <br>
    <p>
        The following HTTP response is an example of a failed polling response at the token endpoint.
    </p>
    <CodeBlock>
        {`
HTTP/1.1 400 BadRequest
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "error":"access_denied",
  "error_description":"end-user has denied the request"
}
        `}
    </CodeBlock>
</Section>