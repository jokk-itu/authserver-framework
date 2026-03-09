import{f as u,a as t,t as h}from"../chunks/BHF9wNqu.js";import"../chunks/CU9afjlv.js";import{p as x,f as l,a as y,e as I,s as n,$ as F,n as f}from"../chunks/DL6eumzt.js";import{h as S}from"../chunks/DMOXgEdX.js";import{i as O}from"../chunks/DQgLNG-F.js";import{C as T}from"../chunks/DbZgjyKz.js";import{I as D}from"../chunks/CuMYCe1t.js";import{P as z,S as d}from"../chunks/C3UgRdqy.js";import{T as A,R as i}from"../chunks/4YLJMDwf.js";var B=u(`<p>When the client has received its initial access token,
        it can be efficient to refresh the token when it expires,
        or if the tokens scope or audience needs to be updated.</p> <p>The use case is covered by the refresh_token grant type,
        which exchanges a fresh access token by a refresh_token.</p> <br/> <p>The refresh token typically has a longer lifetime than the access tokens,
        and can be defined in the client metadata.</p> <br/> <p>If the refresh token request uses DPoP,
        and the client is public, then the refresh token must also be DPoP bound.</p> <!>`,1),H=u(`<p>The request contains a refresh token from the initial token request,
        which returned the first token from another grant such as authorization_code.</p> <br/> <p>It is possible refresh a token, and only contain a subset of the grant's scope. Then you would need to pass a scope parameter along the request.</p> <p>You can also keep the original scope, and omit the scope parameter.</p> <br/> <p>The following HTTP example shows a token request using the code from the identity provider.</p> <!> <p>The following HTTP example shows a token response containing tokens exchanged from the refresh token.</p> <!>`,1),R=u("<!> <!> <!> <!>",1);function Q(v,b){x(b,!1);let w=["Name","Description"],C=[[new i("OAuth2.1","https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/"),new i("Core specification for OAuth")],[new i("OpenId Connect","https://openid.net/specs/openid-connect-core-1_0.html"),new i("Core specification for OpenId Connect")]];O();var m=R();S("1nv3v2h",e=>{I(()=>{F.title="Refresh Token Grant"})});var k=l(m);z(k,{title:"Refresh Token"});var $=n(k,2);d($,{title:"Introduction",children:(e,g)=>{var o=B(),s=n(l(o),12);D(s,{children:(p,a)=>{f();var c=h("It is recommended to sender-constraint the refresh token, instead of rotating refresh tokens.");t(p,c)},$$slots:{default:!0}}),t(e,o)},$$slots:{default:!0}});var _=n($,2);d(_,{title:"Specifications",children:(e,g)=>{A(e,{title:"Specifications",tableNumber:1,get headers(){return w},get rowCellDefinitions(){return C}})},$$slots:{default:!0}});var P=n(_,2);d(P,{title:"Token Endpoint",children:(e,g)=>{var o=H(),s=n(l(o),12);T(s,{children:(a,c)=>{f();var r=h();r.nodeValue=`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=refresh_token
&refresh_token=SplxlOBeZQQYbYS6WxSbIA
`,t(a,r)},$$slots:{default:!0}});var p=n(s,4);T(p,{children:(a,c)=>{f();var r=h();r.nodeValue=`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "access_token":"2YotnFZFEjr1zCsicMWpAA",
  "token_type":"Bearer",
  "expires_in":3600,
  "scope":"weather:read",
  "id_token":"eyJhbGciOiJSUzI1NiIsImtpZCI...",
  "grant_id":"78FF77E8-F146-4F37-9C28-5FD0BC936980"
}
        `,t(a,r)},$$slots:{default:!0}}),t(e,o)},$$slots:{default:!0}}),t(v,m),y()}export{Q as component};
