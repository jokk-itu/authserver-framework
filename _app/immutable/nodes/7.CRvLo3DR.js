import{t as f,h as P,a as n,b as p}from"../chunks/BdD32qd5.js";import"../chunks/BOyCDzPS.js";import{p as F,f as c,a as S,$ as y,s as t,c as A,n as l,r as H}from"../chunks/Db0b_LWK.js";import{a as I}from"../chunks/CANx_FtO.js";import{i as O}from"../chunks/hXpMuBZJ.js";import{b as q}from"../chunks/CSUicqL8.js";import{C as d}from"../chunks/Dg6GzD5d.js";import{P as B,S as h}from"../chunks/DcIxqC40.js";import{T as D,R as u}from"../chunks/BL1phRJf.js";var E=f(`<p>The authorization code grant type is used to exchange a code for an access token,
        id token and optional refresh token.</p> <br> <p>The following image shows the authorization code flow, from authenticating at the authorize endpoint,
        to exchanging the authorization code for tokens.</p> <figure><img class="mx-auto" alt="authorization code flow"> <figCaption class="text-center">Image 1: Authorization Code flow</figCaption></figure>`,1),Q=f(`<p>Triggering the authorization code flow starts at the authorize endpoint,
        by requesting with the parameter "response_type" and value "code".</p> <p>The code returned from the IdentityProvider is encrypted,
        and contains information related to the original request,
        such that it can be validated and correlated to the token request.</p> <p>For example, it contains the redirect_uri, code_challenge, dpop_jkt and more.</p> <br> <p>The following HTTP example shows an authorize request with the response_type.
        The example is not complete to better illustrate the flow.</p> <!> <p>The following HTTP example shows an authorize response with a code.
        The example is not complete to better illustrate the flow.</p> <!>`,1),W=f(`<p>The returned code is then used in the subsequent token request, in exchange for tokens.</p> <br> <p>The following HTTP example shows a token request using the code from the identity provider.
        The example is not complete to better illustrate the flow.</p> <!> <p>The following HTTP example shows a token response containing tokens exchanged from an authoriazation_code.
        The example is not complete to better illustrate the flow.</p> <!>`,1),Y=f("<!> <!> <!> <!> <!>",1);function K(x,b){F(b,!1);let k=["Name","Description"],z=[[new u("OAuth2.1","https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/"),new u("Core specification for OAuth")],[new u("OpenId Connect","https://openid.net/specs/openid-connect-core-1_0.html"),new u("Core specification for OpenId Connect")]];O();var T=Y();P(o=>{y.title="Authorization Code Grant"});var $=c(T);B($,{title:"Authorization Code"});var _=t($,2);h(_,{title:"Introduction",children:(o,m)=>{var a=E(),r=t(c(a),6),s=A(r);I(s,"src",`${q??""}/authorization-code.png`),l(2),H(r),n(o,a)},$$slots:{default:!0}});var w=t(_,2);h(w,{title:"Specifications",children:(o,m)=>{D(o,{title:"Specifications",tableNumber:1,headers:k,rowCellDefinitions:z})},$$slots:{default:!0}});var v=t(w,2);h(v,{title:"Authorize Endpoint",children:(o,m)=>{var a=Q(),r=t(c(a),10);d(r,{children:(i,g)=>{l();var e=p();e.nodeValue=`
GET /connect/authorize?response_type=code HTTP/1.1
Host: idp.authserver.dk
        `,n(i,e)},$$slots:{default:!0}});var s=t(r,4);d(s,{children:(i,g)=>{l();var e=p();e.nodeValue=`
HTTP/1.1 303 SeeOther
Location: https://web-client.authserver.dk/callback?code=SplxlOBeZQQYbYS6WxSbIA
        `,n(i,e)},$$slots:{default:!0}}),n(o,a)},$$slots:{default:!0}});var C=t(v,2);h(C,{title:"Token Endpoint",children:(o,m)=>{var a=W(),r=t(c(a),6);d(r,{children:(i,g)=>{l();var e=p();e.nodeValue=`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&resource=https%3A%2F%2Fapi-one.protectedresource.dk
        `,n(i,e)},$$slots:{default:!0}});var s=t(r,4);d(s,{children:(i,g)=>{l();var e=p();e.nodeValue=`
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
        `,n(i,e)},$$slots:{default:!0}}),n(o,a)},$$slots:{default:!0}}),n(x,T),S()}export{K as component};
