import{t as a,a as o,b as T}from"../chunks/BhbEvs11.js";import"../chunks/Cp21wPu0.js";import{p as U,f as c,a as $,s as n,n as I}from"../chunks/ANGeck7g.js";import{i as L}from"../chunks/pVRch7Ru.js";import{C}from"../chunks/D2PrUHZR.js";import{P as j,S as s}from"../chunks/Wq4Bs5Lt.js";import{T as w,R as e}from"../chunks/DXtZqmQs.js";var D=a("<p>The discovery endpoint returns a JSON document containing metadata about AuthServer, such as endpoints and supported functionality.</p>"),S=a("<p>The discovery endpoint is invoked through HTTP using the GET method.</p> <p>The following example is a GET request to the discovery endpoint.</p> <!> <p>The following table describes the fields in the JSON document.</p> <!>",1),P=a("<!> <!> <!> <!>",1);function J(v,y){U(y,!1);let m=["Name","Description"],g=[[new e("OpenId Connect Discovery","https://openid.net/specs/openid-connect-discovery-1_0.html"),new e("Core specification for OpenId Connect Discovery")],[new e("OAuth Discovery","https://datatracker.ietf.org/doc/html/rfc8414"),new e("Core specification for OAuth Discovery")]],f=["Name","Description"],b=[[new e("issuer"),new e("URL of authserver instance")],[new e("service_documentation"),new e("URL of authserver documentation")],[new e("op_policy_uri"),new e("URL of authserver policy page")],[new e("op_tos_uri"),new e("URL of authserver terms-of-service page")],[new e("authorization_endpoint"),new e("URL of authserver authorize endpoint")],[new e("token_endpoint"),new e("URL of authserver token endpoint")],[new e("userinfo_endpoint"),new e("URL of authserver userinfo endpoint")],[new e("jwks_uri"),new e("URL of authserver jwks endpoint")],[new e("registration_endpoint"),new e("URL of authserver registration endpoint")],[new e("endsession_endpoint"),new e("URL of authserver endsession endpoint")],[new e("introspection_endpoint"),new e("URL of authserver introspection endpoint")],[new e("revocation_endpoint"),new e("URL of authserver revocation endpoint")],[new e("pushed_authorization_request_endpoint"),new e("URL of authserver pushed authorization request endpoint")],[new e("grant_management_endpoint"),new e("URL of authserver grant management endpoint")],[new e("protected_resources"),new e("URLS for protected resources that accept tokens from authserver")],[new e("claims_supported"),new e("Claims that are supported by authserver")],[new e("scopes_supported"),new e("Scopes that are supported by authserver")],[new e("acr_values_supported"),new e("Acr values that are supported by authserver")],[new e("claim_types_supported"),new e("Claim types that are supported by authserver")],[new e("prompt_values_supported"),new e("Prompt values that are supported by authserver")],[new e("display_values_supported"),new e("Display values that are supported by authserver")],[new e("subject_values_supported"),new e("Subject types that are supported by authserver")],[new e("grant_types_supported"),new e("Grant types that are supported by authserver")],[new e("challenge_methods_supported"),new e("Challenge methods that are supported by authserver")],[new e("responses_types_supported"),new e("Response types that are supported by authserver")],[new e("response_modes_supported"),new e("Response modes that are supported by authserver")],[new e("introspection_endpoint_auth_methods_supported"),new e("Introspection endpoint auth modes that are supported by authserver")],[new e("revocation_endpoint_auth_methods_supported"),new e("Revocation endpoint auth modes that are supported by authserver")],[new e("token_endpoint_auth_methods_supported"),new e("Token endpoint auth modes that are supported by authserver")],[new e("grant_management_actions_supported"),new e("Grant management actions that are supported by authserver")],[new e("id_token_signing_alg_values_supported"),new e("Id token signing alg values that are supported by authserver")],[new e("id_token_encryption_alg_values_supported"),new e("Id token encryption alg values that are supported by authserver")],[new e("id_token_encryption_enc_values_supported"),new e("Id token encryption enc values that are supported by authserver")],[new e("userinfo_token_signing_alg_values_supported"),new e("Userinfo token signing alg values that are supported by authserver")],[new e("userinfo_token_encryption_alg_values_supported"),new e("Userinfo token encryption alg values that are supported by authserver")],[new e("userinfo_token_encryption_enc_values_supported"),new e("Userinfo token encryption enc values that are supported by authserver")],[new e("request_object_token_signing_alg_values_supported"),new e("Request object token signing alg values that are supported by authserver")],[new e("request_object_token_encryption_alg_values_supported"),new e("Request object token encryption alg values that are supported by authserver")],[new e("request_object_token_encryption_enc_values_supported"),new e("Request object token encryption enc values that are supported by authserver")],[new e("token_endpoint_auth_signing_alg_values"),new e("Token endpoint auth signing alg values that are supported by authserver")],[new e("token_endpoint_auth_encryption_alg_values"),new e("Token endpoint auth encryption alg values that are supported by authserver")],[new e("token_endpoint_auth_encryption_enc_values"),new e("Token endpoint auth encryption enc values that are supported by authserver")],[new e("authorization_response_iss_parameter_supported"),new e("Is the iss parameter in authorization responses supported by authserver")],[new e("backchannel_logout_supported"),new e("Is backchannel logout supported by authserver")],[new e("require_request_uri_registration"),new e("Is request uri registration required by authserver")],[new e("claims_parameter_supported"),new e("Is claims parameter supported by authserver")],[new e("request_parameter_supported"),new e("Is request parameter supported by authserver")],[new e("request_uri_parameter_supported"),new e("Is request uri parameter supported by authserver")],[new e("require_signed_request_object"),new e("Is request parameter required by authserver")],[new e("require_pushed_authorization_requests"),new e("Is pushed authorization requests required by authserver")],[new e("grant_management_action_required"),new e("Is grant management action required by authserver")]];L();var p=P(),i=c(p);j(i,{title:"Discovery"});var u=n(i,2);s(u,{title:"Introduction",children:(t,_)=>{var r=D();o(t,r)},$$slots:{default:!0}});var d=n(u,2);s(d,{title:"Specifications",children:(t,_)=>{w(t,{title:"Specifications",tableNumber:1,headers:m,rowCellDefinitions:g})},$$slots:{default:!0}});var k=n(d,2);s(k,{title:"Discovery Endpoint",children:(t,_)=>{var r=S(),h=n(c(r),4);C(h,{children:(R,z)=>{I();var l=T();l.nodeValue=`
GET /.well-known/openid-configuration HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/json

{
  "issuer": "https://idp.authserver.dk",
  "scopes_suppoted": ["openid", "profile"],
  "token_endpoint_auth_signing_alg_values": ["RS256"],
  "backchannel_logout_supported": true
}
        `,o(R,l)},$$slots:{default:!0}});var q=n(h,4);w(q,{title:"Metadata fields",tableNumber:2,headers:f,rowCellDefinitions:b}),o(t,r)},$$slots:{default:!0}}),o(v,p),$()}export{J as component};
