import{t as l,h as J,a as i,b as m}from"../chunks/BdD32qd5.js";import"../chunks/BOyCDzPS.js";import{p as K,f as T,a as W,$ as C,s as n,n as y}from"../chunks/Db0b_LWK.js";import{i as N}from"../chunks/hXpMuBZJ.js";import{C as k}from"../chunks/Dg6GzD5d.js";import{P as j,S as r}from"../chunks/DcIxqC40.js";import{T as v,R as e}from"../chunks/BL1phRJf.js";var R=l("<p>The JWKS endpoint returns a JSON document containing public keys used for verifying signatures in tokens, and encrypting tokens.</p>"),A=l("<p>The jwks endpoint is invoked through HTTP using the GET method.</p> <p>The following exmaple is a GET request to the jwks endpoint.</p> <!> <p>The following example is a GET response to the jwks endpoint.</p> <!> <p>The following table describes the fields in the JSON document.</p> <!>",1),D=l("<!> <!> <!> <!>",1);function z($,b){K(b,!1);let g=["Name","Description"],S=[[new e("JSON Web Key","https://datatracker.ietf.org/doc/html/rfc7517"),new e("Core specification for JSON Web Key")]],x=["Name","Description"],_=[[new e("keys"),new e("Array of Json Web Keys")],[new e("kty"),new e("The cryptographic algorithm family, the key can use")],[new e("use"),new e("The usage of the key")],[new e("alg"),new e("The cryptographic algorithm the key can be used with")],[new e("key_ops"),new e("The operations the key can be used with")],[new e("kid"),new e("The unique identifier of the key")],[new e("crv"),new e("The elliptic curve used by the key")],[new e("x"),new e("The base64 x coordinate on the curve")],[new e("y"),new e("The base64 y coordinate on the curve")],[new e("n"),new e("The modulus value used with kty: RSA")],[new e("e"),new e("The exponnent value used with kty: RSA")],[new e("x5t"),new e("The SHA1 thumpbrint of the certificate")],[new e("x5c"),new e("Array of one base64 certificate")],[new e("x5t#S256"),new e("The SHA256 thumbprint of the certificate")]];N();var p=D();J(t=>{C.title="JWKS Metadata Endpoint"});var c=T(p);j(c,{title:"JWKS"});var d=n(c,2);r(d,{title:"Introduction",children:(t,u)=>{var a=R();i(t,a)},$$slots:{default:!0}});var h=n(d,2);r(h,{title:"Specifications",children:(t,u)=>{v(t,{title:"Specifications",tableNumber:1,headers:g,rowCellDefinitions:S})},$$slots:{default:!0}});var H=n(h,2);r(H,{title:"JWKS Endpoint",children:(t,u)=>{var a=A(),w=n(T(a),4);k(w,{children:(s,E)=>{y();var o=m();o.nodeValue=`
GET /.well-known/jwks HTTP/1.1
Host: idp.authserver.dk
        `,i(s,o)},$$slots:{default:!0}});var f=n(w,4);k(f,{children:(s,E)=>{y();var o=m();o.nodeValue=`
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
    }
  ]
}
        `,i(s,o)},$$slots:{default:!0}});var P=n(f,4);v(P,{title:"JWKS fields",tableNumber:3,headers:x,rowCellDefinitions:_}),i(t,a)},$$slots:{default:!0}}),i($,p),W()}export{z as component};
