import{t as l,h as J,a as i,b as m}from"../chunks/BdD32qd5.js";import"../chunks/BOyCDzPS.js";import{p as K,f as y,a as W,$ as A,s as n,n as k}from"../chunks/Db0b_LWK.js";import{i as C}from"../chunks/hXpMuBZJ.js";import{C as T}from"../chunks/Dg6GzD5d.js";import{P as N,S as r}from"../chunks/DcIxqC40.js";import{T as v,R as e}from"../chunks/BL1phRJf.js";var R=l("<p>The JWKS endpoint returns a JSON document containing public keys used for verifying signatures in tokens, and encrypting tokens.</p>"),j=l("<p>The jwks endpoint is invoked through HTTP using the GET method.</p> <p>The following exmaple is a GET request to the jwks endpoint.</p> <!> <p>The following example is a GET response to the jwks endpoint.</p> <!> <p>The following table describes the fields in the JSON document.</p> <!>",1),D=l("<!> <!> <!> <!>",1);function q(g,b){K(b,!1);let $=["Name","Description"],S=[[new e("JSON Web Key","https://datatracker.ietf.org/doc/html/rfc7517"),new e("Core specification for JSON Web Key")]],x=["Name","Description"],_=[[new e("keys"),new e("Array of Json Web Keys")],[new e("kty"),new e("The cryptographic algorithm family, the key can use")],[new e("use"),new e("The usage of the key")],[new e("alg"),new e("The cryptographic algorithm the key can be used with")],[new e("key_ops"),new e("The operations the key can be used with")],[new e("kid"),new e("The unique identifier of the key")],[new e("crv"),new e("The elliptic curve used by the key")],[new e("x"),new e("The base64 x coordinate on the curve")],[new e("y"),new e("The base64 y coordinate on the curve")],[new e("n"),new e("The modulus value used with kty: RSA")],[new e("e"),new e("The exponnent value used with kty: RSA")],[new e("x5c"),new e("Array of one base64 certificate")],[new e("x5t"),new e("The SHA1 thumpbrint of the certificate")],[new e("x5t#S256"),new e("The SHA256 thumbprint of the certificate")]];C();var p=D();J(t=>{A.title="JWKS Metadata Endpoint"});var c=y(p);N(c,{title:"JWKS"});var d=n(c,2);r(d,{title:"Introduction",children:(t,u)=>{var a=R();i(t,a)},$$slots:{default:!0}});var h=n(d,2);r(h,{title:"Specifications",children:(t,u)=>{v(t,{title:"Specifications",tableNumber:1,headers:$,rowCellDefinitions:S})},$$slots:{default:!0}});var P=n(h,2);r(P,{title:"JWKS Endpoint",children:(t,u)=>{var a=j(),f=n(y(a),4);T(f,{children:(s,E)=>{k();var o=m();o.nodeValue=`
GET /.well-known/jwks HTTP/1.1
Host: idp.authserver.dk
        `,i(s,o)},$$slots:{default:!0}});var w=n(f,4);T(w,{children:(s,E)=>{k();var o=m();o.nodeValue=`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8

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
    },
    {
      "kty":"RSA",
      "use": "sig",
      "alg": "RS256",
      "key_ops": ["verify"],
      "n": "0vx7agoebGcQSuuPi...",
      "e":"AQAB",
      "kid":"b3f74555-ce9f-4dd3-a3fc-9789a77580a9"
    }
  ]
}
        `,i(s,o)},$$slots:{default:!0}});var H=n(w,4);v(H,{title:"JWKS fields",tableNumber:3,headers:x,rowCellDefinitions:_}),i(t,a)},$$slots:{default:!0}}),i(g,p),W()}export{q as component};
