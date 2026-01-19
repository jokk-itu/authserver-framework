import{f as i,a as o,t as $}from"../chunks/BHF9wNqu.js";import"../chunks/CU9afjlv.js";import{p as b,f as w,a as S,e as q,s as a,$ as K,n as h}from"../chunks/DL6eumzt.js";import{h as O}from"../chunks/DMOXgEdX.js";import{i as z}from"../chunks/DQgLNG-F.js";import{C as _}from"../chunks/DbZgjyKz.js";import{I as E}from"../chunks/CuMYCe1t.js";import{P as H,S as c}from"../chunks/C3UgRdqy.js";import{T as A,R as s}from"../chunks/4YLJMDwf.js";var F=i(`<p>PKCE which is short for Proof Key for Code Exchange, is used to mitigate the risks of code exchanges, such as authorization codes and device codes.
        It works by the client creating a secret, which is hashed, and send along the initial authentication request.
        Then the secret is sent along the token request,
        and the authorization server verifies the secret hashed is equal to the hash from the initial authentication request.</p> <br/> <p>The proof key protects the client against malicious actors, who successfully intercepts codes and redeems them for a token.
        This is because the malicous actor is not in possession of the code_verifier, and the token request will therefore fail.</p>`,1),M=i('<p>The code_challenge_method "plain" is not supported, as that would expose the code_verifier value and make the Proof Key useless.</p>'),B=i("<p>The flow starts by the client generating a secret using a cryptographically strong random generator.</p> <p>The secret must be unique for each authentication request, and not reused.</p> <p>Then the secret is hashed using one of the supported code_challenge_methods, e.g. S256 which uses SHA256.</p> <!> <br/> <p>The following example shows an initial authentication request.</p> <!> <p>The following example shows the token request.</p> <!>",1),D=i("<!> <!> <!> <!>",1);function Z(T,P){b(P,!1);let y=["Name","Description"],k=[[new s("OAuth2.1","https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/"),new s("Core specification for OAuth")],[new s("OAuth Discovery Metadata","https://datatracker.ietf.org/doc/html/rfc8414"),new s("Core specification for OAuth discovery metadata")]];z();var l=D();O("37b7hf",t=>{q(()=>{K.title="Proof Key for Code Exchange"})});var d=w(l);H(d,{title:"Proof Key for Code Exchange"});var p=a(d,2);c(p,{title:"Introduction",children:(t,u)=>{var n=F();h(4),o(t,n)},$$slots:{default:!0}});var f=a(p,2);c(f,{title:"Specifications",children:(t,u)=>{A(t,{title:"Specifications",tableNumber:1,get headers(){return y},get rowCellDefinitions(){return k}})},$$slots:{default:!0}});var C=a(f,2);c(C,{title:"Proof Key",children:(t,u)=>{var n=B(),m=a(w(n),6);E(m,{children:(r,v)=>{var e=M();o(r,e)},$$slots:{default:!0}});var g=a(m,6);_(g,{children:(r,v)=>{h();var e=$();e.nodeValue=`
POST /connect/authorize HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded

code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
&code_challenge_method=S256
        `,o(r,e)},$$slots:{default:!0}});var x=a(g,4);_(x,{children:(r,v)=>{h();var e=$();e.nodeValue=`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=authorization_code
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
        `,o(r,e)},$$slots:{default:!0}}),o(t,n)},$$slots:{default:!0}}),o(T,l),S()}export{Z as component};
