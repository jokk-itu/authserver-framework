import{t as n,h as b,a as o,b as $}from"../chunks/BdD32qd5.js";import"../chunks/BOyCDzPS.js";import{p as S,f as w,a as q,$ as K,s as a,n as c}from"../chunks/Db0b_LWK.js";import{i as O}from"../chunks/hXpMuBZJ.js";import{C as _}from"../chunks/Dg6GzD5d.js";import{I as z}from"../chunks/BqXxNwWv.js";import{P as E,S as h}from"../chunks/DcIxqC40.js";import{T as H,R as i}from"../chunks/BL1phRJf.js";var A=n(`<p>PKCE which is short for Proof Key for Code Exchange, is used to mitigate the risks of code exchanges, such as authorization codes and device codes.
        It works by the client creating a secret, which is hashed, and send along the initial authentication request.
        Then the secret is sent along the token request,
        and the authorization server verifies the secret hashed is equal to the hash from the initial authentication request.</p> <br> <p>The proof key protects the client against malicious actors, who successfully intercepts codes and redeems them for a token.
        This is because the malicous actor is not in possession of the code_verifier, and the token request will therefore fail.</p>`,1),F=n('<p>The code_challenge_method "plain" is not supported, as that would expose the code_verifier value and make the Proof Key useless.</p>'),M=n("<p>The flow starts by the client generating a secret using a cryptographically strong random generator.</p> <p>The secret must be unique for each authentication request, and not reused.</p> <p>Then the secret is hashed using one of the supported code_challenge_methods, e.g. S256 which uses SHA256.</p> <!> <br> <p>The following example shows an initial authentication request.</p> <!> <p>The following example shows the token request.</p> <!>",1),B=n("<!> <!> <!> <!>",1);function G(T,P){S(P,!1);let y=["Name","Description"],k=[[new i("OAuth2.1","https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/"),new i("Core specification for OAuth")],[new i("OAuth Discovery Metadata","https://datatracker.ietf.org/doc/html/rfc8414"),new i("Core specification for OAuth discovery metadata")]];O();var l=B();b(t=>{K.title="Proof Key for Code Exchange"});var d=w(l);E(d,{title:"Proof Key for Code Exchange"});var p=a(d,2);h(p,{title:"Introduction",children:(t,f)=>{var s=A();c(4),o(t,s)},$$slots:{default:!0}});var u=a(p,2);h(u,{title:"Specifications",children:(t,f)=>{H(t,{title:"Specifications",tableNumber:1,headers:y,rowCellDefinitions:k})},$$slots:{default:!0}});var C=a(u,2);h(C,{title:"Proof Key",children:(t,f)=>{var s=M(),m=a(w(s),6);z(m,{children:(r,v)=>{var e=F();o(r,e)},$$slots:{default:!0}});var g=a(m,6);_(g,{children:(r,v)=>{c();var e=$();e.nodeValue=`
POST /connect/authorize HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded

code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
&code_challenge_method=S256
        `,o(r,e)},$$slots:{default:!0}});var x=a(g,4);_(x,{children:(r,v)=>{c();var e=$();e.nodeValue=`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=authorization_code
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
        `,o(r,e)},$$slots:{default:!0}}),o(t,s)},$$slots:{default:!0}}),o(T,l),q()}export{G as component};
