import{t as c,h as H,a as o,b as f}from"../chunks/BdD32qd5.js";import"../chunks/BOyCDzPS.js";import{p as O,f as p,a as B,$ as J,s as i,n as h}from"../chunks/Db0b_LWK.js";import{i as W}from"../chunks/hXpMuBZJ.js";import{C as m}from"../chunks/Dg6GzD5d.js";import{I as D}from"../chunks/BqXxNwWv.js";import{P as I,S as l}from"../chunks/DcIxqC40.js";import{T as y,R as e}from"../chunks/BL1phRJf.js";var V=c(`<p>The client can authenticate itself when requesting endpoints, through a
        backchannel, for example at the token endpoint.</p> <p>Authentication is grouped into either using shared secrets, or using
        public key cryptography.</p>`,1),j=c("<p>Authenticate using the HTTP Authorization header, using the basic schema.</p> <p>The header contains the client id as the username and the client secret as the password.</p> <p>The combination of client id and secret is afterwards base64 encoded.</p> <p>The following example is for the token endpoint. The client id is s6BhdRkqt3 and the client secret is gX1fBat3bV.</p> <!>",1),z=c("<p>Authenticate using the HTTP body. The body contains the client id and the client secret.</p> <p>The following example is for the token endpoint.</p> <!>",1),N=c(`<p>The client secret must be shared between the client and AuthServer for client secret JWT to work.
            AuthServer does not support this, because secrets are hashed.</p>`),F=c("<p>Authenticate using the HTTP body. The body contains the client assertion type, the client assertion and optionally the client id.</p> <p>The token must be signed, and can optionally be encrypted.</p> <p>The following example is for the token endpoint.</p> <!> <p>The following table describes the possible claims in the token.</p> <!>",1),K=c("<!> <!> <!> <!> <!> <!> <!>",1);function Y(P,A){O(A,!1);let C=["Name","Description"],x=[[new e("OAuth2.1","https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/"),new e("Core specification for OAuth")],[new e("OpenId Connect","https://openid.net/specs/openid-connect-core-1_0.html"),new e("Core specification for OpenId Connect")],[new e("JWT Assertion framework","https://datatracker.ietf.org/doc/rfc7523/"),new e("Core specification for OAuth")],[new e("Assertion framework","https://datatracker.ietf.org/doc/rfc7521/"),new e("Specification for OAuth assertions")]],S=["Name","Description"],R=[[new e("iss"),new e("Required. Issuer of the token, must be the client id")],[new e("sub"),new e("Required. Subject of the token, must be the client id")],[new e("aud"),new e("Required. Audience of the token, must be the endpoint where the client is authenticating")],[new e("jti"),new e("Required. Unique id of the token")],[new e("exp"),new e("Required. Expiration time of the token")],[new e("iat"),new e("Optional. Time at which the token was issued")],[new e("typ"),new e("Required. Type of token, which must be: pk+jwt")]];W();var w=K();H(t=>{J.title="Client Authentication"});var $=p(w);I($,{title:"Client Authentication"});var T=i($,2);l(T,{title:"Introduction",children:(t,d)=>{var n=V();h(2),o(t,n)},$$slots:{default:!0}});var v=i(T,2);l(v,{title:"Specifications",children:(t,d)=>{y(t,{title:"Specifications",tableNumber:1,headers:C,rowCellDefinitions:x})},$$slots:{default:!0}});var _=i(v,2);l(_,{title:"Client Secret Basic",children:(t,d)=>{var n=j(),r=i(p(n),8);m(r,{children:(a,u)=>{h();var s=f();s.nodeValue=`
POST /token HTTP/1.1
Host: idp.authserver.dk
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=weather:read
        `,o(a,s)},$$slots:{default:!0}}),o(t,n)},$$slots:{default:!0}});var k=i(_,2);l(k,{title:"Client Secret Post",children:(t,d)=>{var n=z(),r=i(p(n),4);m(r,{children:(a,u)=>{h();var s=f();s.nodeValue=`
POST /token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=weather:read&
client_id=s6BhdRkqt3&client_secret=gX1fBat3bV
        `,o(a,s)},$$slots:{default:!0}}),o(t,n)},$$slots:{default:!0}});var b=i(k,2);l(b,{title:"Client Secret JWT",children:(t,d)=>{D(t,{children:(n,r)=>{var a=N();o(n,a)},$$slots:{default:!0}})},$$slots:{default:!0}});var q=i(b,2);l(q,{title:"Private key JWT",children:(t,d)=>{var n=F(),r=i(p(n),6);m(r,{children:(u,s)=>{h();var g=f();g.nodeValue=`
POST /token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
scope=weather:read&
client_id=s6BhdRkqt3&
client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&
client_assertion=eyJ0eXAiOiJKV1QiLCJh...82U
        `,o(u,g)},$$slots:{default:!0}});var a=i(r,4);y(a,{title:"Private key JWT claims",tableNumber:2,headers:S,rowCellDefinitions:R}),o(t,n)},$$slots:{default:!0}}),o(P,w),B()}export{Y as component};
