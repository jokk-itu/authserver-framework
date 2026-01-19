import{f as l,a as o,t as g}from"../chunks/BHF9wNqu.js";import"../chunks/CU9afjlv.js";import{p as O,f as T,a as F,e as S,s as t,$ as N,n as $}from"../chunks/DL6eumzt.js";import{h as z}from"../chunks/DMOXgEdX.js";import{i as I}from"../chunks/DQgLNG-F.js";import{C as k}from"../chunks/DbZgjyKz.js";import{P as B,S as i}from"../chunks/C3UgRdqy.js";import{T as c,R as e}from"../chunks/4YLJMDwf.js";var G=l('<p>The grant type "client credentials" is used at the token endpoint, in exchange for an access_token.</p>'),M=l('<p>If the parameter "grant_type" is passed with value "client_credentials" to the token endpoint, then an access_token is returned.</p> <p>Only confidential clients are eligible for this grant type, as it requires client authentication.</p> <p>The following is an example HTTP request using client credentials and client_secret_basic as client authentication.</p> <!> <p>The following is an example HTTP response using client credentials.</p> <!> <p>The following table describes the request parameters. Client authentication parameters are not listed.</p> <!> <p>The following table describes the response parameters.</p> <!>',1),J=l("<!> <!> <!> <!>",1);function E(v,b){O(b,!1);let C=["Name","Description"],q=[[new e("OAuth2.1","https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/"),new e("Core specification for OAuth")],[new e("Resource Indicators for OAuth 2.0","https://datatracker.ietf.org/doc/rfc8707/"),new e("OAuth specification for resource parameter")]],P=["Name","Description"],R=[[new e("grant_type"),new e("Required. Must be equal to client_credentials.")],[new e("scope"),new e("Required. Space delimited scopes.")],[new e("resource"),new e("Required. URL of protected resource that is the audience of the access token.")]],x=["Name","Description"],y=[[new e("access_token"),new e("The access token.")],[new e("token_type"),new e("The schema used in the Authorization HTTP header with the token, when requesting protected resources.")],[new e("expires_in"),new e("The amount of seconds until the token expires, from the issued time.")],[new e("scope"),new e("The scope the token is authorized for. It is equal to the request parameter.")]];I();var p=J();z("rphgbg",n=>{S(()=>{N.title="Client Credentials Grant"})});var d=T(p);B(d,{title:"Client Credentials"});var u=t(d,2);i(u,{title:"Introduction",children:(n,f)=>{var a=G();o(n,a)},$$slots:{default:!0}});var h=t(u,2);i(h,{title:"Specifications",children:(n,f)=>{c(n,{title:"Specifications",tableNumber:1,get headers(){return C},get rowCellDefinitions(){return q}})},$$slots:{default:!0}});var H=t(h,2);i(H,{title:"Token endpoint",children:(n,f)=>{var a=M(),m=t(T(a),6);k(m,{children:(s,D)=>{$();var r=g();r.nodeValue=`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=client_credentials
&scope=account:update%20account:delete
&resource=https%3A%2F%2Fapi-one.protectedresource.dk
&resource=https%3A%2F%2Fapi-two.protectedresource.dk
        `,o(s,r)},$$slots:{default:!0}});var w=t(m,4);k(w,{children:(s,D)=>{$();var r=g();r.nodeValue=`
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-cache, no-store

{
  "access_token": "eyJhbGciO...ssw56c",
  "token_type": "Bearer",
  "expires_in": 500,
  "scope": "account:update account:delete"
}
        `,o(s,r)},$$slots:{default:!0}});var _=t(w,4);c(_,{title:"Request parameters",tableNumber:1,get headers(){return P},get rowCellDefinitions(){return R}});var A=t(_,4);c(A,{title:"Response parameters",tableNumber:2,get headers(){return x},get rowCellDefinitions(){return y}}),o(n,a)},$$slots:{default:!0}}),o(v,p),F()}export{E as component};
