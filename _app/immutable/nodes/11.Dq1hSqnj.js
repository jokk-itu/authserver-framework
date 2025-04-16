import{t as s,a as i,b as x}from"../chunks/BhbEvs11.js";import"../chunks/Cp21wPu0.js";import{p as _,f as w,a as H,s as n,n as C}from"../chunks/ANGeck7g.js";import{i as N}from"../chunks/pVRch7Ru.js";import{C as P}from"../chunks/D2PrUHZR.js";import{P as E,S as r}from"../chunks/Wq4Bs5Lt.js";import{T as f,R as e}from"../chunks/DXtZqmQs.js";var J=s("<p>The JWKS endpoint returns a JSON document containing public keys used for verifying signatures in tokens, and encrypting tokens.</p>"),W=s("<p>The jwks endpoint is invoked through HTTP using the GET method.</p> <p>The following exmaple is a GET request to the jwks endpoint.</p> <!> <p>The following table describes the fields in the JSON document.</p> <!>",1),D=s("<!> <!> <!> <!>",1);function V(m,y){_(y,!1);let k=["Name","Description"],T=[[new e("JSON Web Key","https://datatracker.ietf.org/doc/html/rfc7517"),new e("Core specification for JSON Web Key")]],v=["Name","Description"],b=[[new e("keys"),new e("Array of Json Web Keys")],[new e("kty"),new e("The cryptographic algorithm family, the key can use")],[new e("use"),new e("The usage of the key")],[new e("alg"),new e("The cryptographic algorithm the key can be used with")],[new e("key_ops"),new e("The operations the key can be used with")],[new e("kid"),new e("The unique identifier of the key")],[new e("crv"),new e("The elliptic curve used by the key")],[new e("x"),new e("The base64 x coordinate on the curve")],[new e("y"),new e("The base64 y coordinate on the curve")],[new e("n"),new e("The modulus value used with kty: RSA")],[new e("e"),new e("The exponnent value used with kty: RSA")],[new e("x5t"),new e("The SHA1 thumpbrint of the certificate")],[new e("x5c"),new e("Array of one base64 certificate")],[new e("x5t#S256"),new e("The SHA256 thumbprint of the certificate")]];N();var a=D(),l=w(a);E(l,{title:"Discovery"});var p=n(l,2);r(p,{title:"Introduction",children:(t,h)=>{var o=J();i(t,o)},$$slots:{default:!0}});var c=n(p,2);r(c,{title:"Specifications",children:(t,h)=>{f(t,{title:"Specifications",tableNumber:1,headers:k,rowCellDefinitions:T})},$$slots:{default:!0}});var g=n(c,2);r(g,{title:"JWKS Endpoint",children:(t,h)=>{var o=W(),d=n(w(o),4);P(d,{children:($,K)=>{C();var u=x();u.nodeValue=`
GET /.well-known/jwks HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/json

{
  "keys": [
    {
      "kty": "EC",
      "use": "enc",
      "crv": "P-256",
      "alg": "ECDH-ES+A128KW",
      "key_ops": ["encryption"],
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "kid": "d890e7ed-662b-48c5-8914-c5c58571f8b6"
    }
  ]
}
        `,i($,u)},$$slots:{default:!0}});var S=n(d,4);f(S,{title:"JWKS fields",tableNumber:3,headers:v,rowCellDefinitions:b}),i(t,o)},$$slots:{default:!0}}),i(m,a),H()}export{V as component};
