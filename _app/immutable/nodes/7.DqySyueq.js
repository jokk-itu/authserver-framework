import{t as s,a as o,h as H,b as v}from"../chunks/BdD32qd5.js";import"../chunks/BOyCDzPS.js";import{c as O,r as B,p as J,f as h,a as W,$ as D,s as i,n as u}from"../chunks/Db0b_LWK.js";import{i as V}from"../chunks/hXpMuBZJ.js";import{C as T}from"../chunks/BZQAvLTj.js";import{s as I}from"../chunks/CANx_FtO.js";import{P as j,S as c}from"../chunks/DcIxqC40.js";import{T as x,R as e}from"../chunks/BL1phRJf.js";var z=s('<div class="p-4 my-2 rounded-lg bg-sky-700 font-medium text-cyan-200"><!></div>');function N(f,m){var d=z(),w=O(d);I(w,m,"default",{}),B(d),o(f,d)}var F=s(`<p>The client can authenticate itself when requesting endpoints, through a
        backchannel, for example at the token endpoint.</p> <p>Authentication is grouped into either using shared secrets, or using
        public key cryptography.</p>`,1),K=s("<p>Authenticate using the HTTP Authorization header, using the basic schema.</p> <p>The header contains the client id as the username and the client secret as the password.</p> <p>The combination of client id and secret is afterwards base64 encoded.</p> <p>The following example is for the token endpoint. The client id is s6BhdRkqt3 and the client secret is gX1fBat3bV.</p> <!>",1),X=s("<p>Authenticate using the HTTP body. The body contains the client id and the client secret.</p> <p>The following example is for the token endpoint.</p> <!>",1),M=s(`<p>The client secret must be shared between the client and AuthServer for client secret JWT to work.
            AuthServer does not support this, because secrets are hashed.</p>`),Q=s("<p>Authenticate using the HTTP body. The body contains the client assertion type, the client assertion and optionally the client id.</p> <p>The token must be signed, and can optionally be encrypted.</p> <p>The following example is for the token endpoint.</p> <!> <p>The following table describes the possible claims in the token.</p> <!>",1),U=s("<!> <!> <!> <!> <!> <!> <!>",1);function ie(f,m){J(m,!1);let d=["Name","Description"],w=[[new e("OAuth2.1","https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/"),new e("Core specification for OAuth")],[new e("OpenId Connect","https://openid.net/specs/openid-connect-core-1_0.html"),new e("Core specification for OpenId Connect")],[new e("JWT Assertion framework","https://datatracker.ietf.org/doc/rfc7523/"),new e("Core specification for OAuth")],[new e("Assertion framework","https://datatracker.ietf.org/doc/rfc7521/"),new e("Specification for OAuth assertions")]],S=["Name","Description"],R=[[new e("iss"),new e("Required. Issuer of the token, must be the client id")],[new e("sub"),new e("Required. Subject of the token, must be the client id")],[new e("aud"),new e("Required. Audience of the token, must be the endpoint where the client is authenticating")],[new e("jti"),new e("Required. Unique id of the token")],[new e("exp"),new e("Required. Expiration time of the token")],[new e("iat"),new e("Optional. Time at which the token was issued")],[new e("typ"),new e("Required. Type of token, which must be: pk+jwt")]];V();var _=U();H(t=>{D.title="Client authentication page of AuthServer"});var g=h(_);j(g,{title:"Client Authentication"});var b=i(g,2);c(b,{title:"Introduction",children:(t,p)=>{var n=F();u(2),o(t,n)},$$slots:{default:!0}});var k=i(b,2);c(k,{title:"Specifications",children:(t,p)=>{x(t,{title:"Specifications",tableNumber:1,headers:d,rowCellDefinitions:w})},$$slots:{default:!0}});var y=i(k,2);c(y,{title:"Client Secret Basic",children:(t,p)=>{var n=K(),r=i(h(n),8);T(r,{children:(a,$)=>{u();var l=v();l.nodeValue=`
POST /token HTTP/1.1
Host: idp.authserver.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded
grant_type=client_credentials&scope=weather:read
        `,o(a,l)},$$slots:{default:!0}}),o(t,n)},$$slots:{default:!0}});var P=i(y,2);c(P,{title:"Client Secret Post",children:(t,p)=>{var n=X(),r=i(h(n),4);T(r,{children:(a,$)=>{u();var l=v();l.nodeValue=`
POST /token HTTP/1.1
Host: idp.authserver.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=weather:read&
client_id=s6BhdRkqt3&client_secret=gX1fBat3bV
        `,o(a,l)},$$slots:{default:!0}}),o(t,n)},$$slots:{default:!0}});var A=i(P,2);c(A,{title:"Client Secret JWT",children:(t,p)=>{N(t,{children:(n,r)=>{var a=M();o(n,a)},$$slots:{default:!0}})},$$slots:{default:!0}});var q=i(A,2);c(q,{title:"Private key JWT",children:(t,p)=>{var n=Q(),r=i(h(n),6);T(r,{children:($,l)=>{u();var C=v();C.nodeValue=`
POST /token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
scope=weather:read&
client_id=s6BhdRkqt3&
client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&
client_assertion=eyJ0eXAiOiJKV1QiLCJh...82U
        `,o($,C)},$$slots:{default:!0}});var a=i(r,4);x(a,{title:"Private key JWT claims",tableNumber:2,headers:S,rowCellDefinitions:R}),o(t,n)},$$slots:{default:!0}}),o(f,_),W()}export{ie as component};
