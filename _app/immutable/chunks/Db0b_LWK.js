var fn=Array.isArray,un=Array.prototype.indexOf,$n=Array.from,Zn=Object.defineProperty,V=Object.getOwnPropertyDescriptor,on=Object.getOwnPropertyDescriptors,_n=Object.prototype,cn=Array.prototype,kt=Object.getPrototypeOf,Dt=Object.isExtensible;const zn=()=>{};function Wn(t){return t()}function Pt(t){for(var e=0;e<t.length;e++)t[e]()}const x=2,Ct=4,it=8,gt=16,O=32,H=64,nt=128,m=256,et=512,E=1024,I=2048,M=4096,Y=8192,ut=16384,vn=32768,Ft=65536,Xn=1<<17,hn=1<<19,Mt=1<<20,pt=1<<21,G=Symbol("$state"),Jn=Symbol("legacy props"),Qn=Symbol("");function Lt(t){return t===this.v}function pn(t,e){return t!=t?e==e:t!==e||t!==null&&typeof t=="object"||typeof t=="function"}function qt(t){return!pn(t,this.v)}function dn(t){throw new Error("https://svelte.dev/e/effect_in_teardown")}function wn(){throw new Error("https://svelte.dev/e/effect_in_unowned_derived")}function En(t){throw new Error("https://svelte.dev/e/effect_orphan")}function yn(){throw new Error("https://svelte.dev/e/effect_update_depth_exceeded")}function te(){throw new Error("https://svelte.dev/e/hydration_failed")}function ne(t){throw new Error("https://svelte.dev/e/props_invalid_value")}function gn(){throw new Error("https://svelte.dev/e/state_descriptors_fixed")}function mn(){throw new Error("https://svelte.dev/e/state_prototype_fixed")}function Tn(){throw new Error("https://svelte.dev/e/state_unsafe_mutation")}let ot=!1;function ee(){ot=!0}const re=1,le=2,ae=4,se=8,fe=16,ie=1,ue=2,oe=4,_e=8,ce=16,ve=1,he=2,An="[",xn="[!",Rn="]",Yt={},y=Symbol(),pe="http://www.w3.org/1999/xhtml";let p=null;function bt(t){p=t}function de(t,e=!1,n){var r=p={p,c:null,d:!1,e:null,m:!1,s:t,x:null,l:null};ot&&!e&&(p.l={s:null,u:null,r1:[],r2:Tt(!1)}),Nn(()=>{r.d=!0})}function we(t){const e=p;if(e!==null){const u=e.e;if(u!==null){var n=h,r=v;e.e=null;try{for(var l=0;l<u.length;l++){var a=u[l];at(a.effect),j(a.reaction),Zt(a.fn)}}finally{at(n),j(r)}}p=e.p,e.m=!0}return{}}function _t(){return!ot||p!==null&&p.l===null}function q(t){if(typeof t!="object"||t===null||G in t)return t;const e=kt(t);if(e!==_n&&e!==cn)return t;var n=new Map,r=fn(t),l=S(0),a=v,u=i=>{var s=v;j(a);var f=i();return j(s),f};return r&&n.set("length",S(t.length)),new Proxy(t,{defineProperty(i,s,f){(!("value"in f)||f.configurable===!1||f.enumerable===!1||f.writable===!1)&&gn();var _=n.get(s);return _===void 0?(_=u(()=>S(f.value)),n.set(s,_)):N(_,u(()=>q(f.value))),!0},deleteProperty(i,s){var f=n.get(s);if(f===void 0)s in i&&n.set(s,u(()=>S(y)));else{if(r&&typeof s=="string"){var _=n.get("length"),o=Number(s);Number.isInteger(o)&&o<_.v&&N(_,o)}N(f,y),It(l)}return!0},get(i,s,f){var A;if(s===G)return t;var _=n.get(s),o=s in i;if(_===void 0&&(!o||(A=V(i,s))!=null&&A.writable)&&(_=u(()=>S(q(o?i[s]:y))),n.set(s,_)),_!==void 0){var c=U(_);return c===y?void 0:c}return Reflect.get(i,s,f)},getOwnPropertyDescriptor(i,s){var f=Reflect.getOwnPropertyDescriptor(i,s);if(f&&"value"in f){var _=n.get(s);_&&(f.value=U(_))}else if(f===void 0){var o=n.get(s),c=o==null?void 0:o.v;if(o!==void 0&&c!==y)return{enumerable:!0,configurable:!0,value:c,writable:!0}}return f},has(i,s){var c;if(s===G)return!0;var f=n.get(s),_=f!==void 0&&f.v!==y||Reflect.has(i,s);if(f!==void 0||h!==null&&(!_||(c=V(i,s))!=null&&c.writable)){f===void 0&&(f=u(()=>S(_?q(i[s]):y)),n.set(s,f));var o=U(f);if(o===y)return!1}return _},set(i,s,f,_){var Rt;var o=n.get(s),c=s in i;if(r&&s==="length")for(var A=f;A<o.v;A+=1){var J=n.get(A+"");J!==void 0?N(J,y):A in i&&(J=u(()=>S(y)),n.set(A+"",J))}o===void 0?(!c||(Rt=V(i,s))!=null&&Rt.writable)&&(o=u(()=>S(void 0)),N(o,u(()=>q(f))),n.set(s,o)):(c=o.v!==y,N(o,u(()=>q(f))));var Q=Reflect.getOwnPropertyDescriptor(i,s);if(Q!=null&&Q.set&&Q.set.call(_,f),!c){if(r&&typeof s=="string"){var xt=n.get("length"),ht=Number(s);Number.isInteger(ht)&&ht>=xt.v&&N(xt,ht+1)}It(l)}return!0},ownKeys(i){U(l);var s=Reflect.ownKeys(i).filter(o=>{var c=n.get(o);return c===void 0||c.v!==y});for(var[f,_]of n)_.v!==y&&!(f in i)&&s.push(f);return s},setPrototypeOf(){mn()}})}function It(t,e=1){N(t,t.v+e)}function mt(t){var e=x|I,n=v!==null&&(v.f&x)!==0?v:null;return h===null||n!==null&&(n.f&m)!==0?e|=m:h.f|=Mt,{ctx:p,deps:null,effects:null,equals:Lt,f:e,fn:t,reactions:null,rv:0,v:null,wv:0,parent:n??h}}function Ee(t){const e=mt(t);return nn(e),e}function ye(t){const e=mt(t);return e.equals=qt,e}function jt(t){var e=t.effects;if(e!==null){t.effects=null;for(var n=0;n<e.length;n+=1)F(e[n])}}function Dn(t){for(var e=t.parent;e!==null;){if((e.f&x)===0)return e;e=e.parent}return null}function Ht(t){var e,n=h;at(Dn(t));try{jt(t),e=an(t)}finally{at(n)}return e}function Bt(t){var e=Ht(t),n=(k||(t.f&m)!==0)&&t.deps!==null?M:E;D(t,n),t.equals(e)||(t.v=e,t.wv=rn())}const $=new Map;function Tt(t,e){var n={f:0,v:t,reactions:null,equals:Lt,rv:0,wv:0};return n}function S(t,e){const n=Tt(t);return nn(n),n}function ge(t,e=!1){var r;const n=Tt(t);return e||(n.equals=qt),ot&&p!==null&&p.l!==null&&((r=p.l).s??(r.s=[])).push(n),n}function N(t,e,n=!1){v!==null&&!b&&_t()&&(v.f&(x|gt))!==0&&!(w!=null&&w.includes(t))&&Tn();let r=n?q(e):e;return bn(t,r)}function bn(t,e){if(!t.equals(e)){var n=t.v;W?$.set(t,e):$.set(t,n),t.v=e,(t.f&x)!==0&&((t.f&I)!==0&&Ht(t),D(t,(t.f&m)===0?E:M)),t.wv=rn(),Ut(t,I),_t()&&h!==null&&(h.f&E)!==0&&(h.f&(O|H))===0&&(T===null?qn([t]):T.push(t))}return e}function Ut(t,e){var n=t.reactions;if(n!==null)for(var r=_t(),l=n.length,a=0;a<l;a++){var u=n[a],i=u.f;(i&I)===0&&(!r&&u===h||(D(u,e),(i&(E|m))!==0&&((i&x)!==0?Ut(u,M):vt(u))))}}function Vt(t){console.warn("https://svelte.dev/e/hydration_mismatch")}let C=!1;function me(t){C=t}let R;function Z(t){if(t===null)throw Vt(),Yt;return R=t}function Te(){return Z(L(R))}function Ae(t){if(C){if(L(R)!==null)throw Vt(),Yt;R=t}}function xe(t=1){if(C){for(var e=t,n=R;e--;)n=L(n);R=n}}function Re(){for(var t=0,e=R;;){if(e.nodeType===8){var n=e.data;if(n===Rn){if(t===0)return e;t-=1}else(n===An||n===xn)&&(t+=1)}var r=L(e);e.remove(),e=r}}var Ot,In,On,Gt,Kt;function De(){if(Ot===void 0){Ot=window,In=document,On=/Firefox/.test(navigator.userAgent);var t=Element.prototype,e=Node.prototype,n=Text.prototype;Gt=V(e,"firstChild").get,Kt=V(e,"nextSibling").get,Dt(t)&&(t.__click=void 0,t.__className=void 0,t.__attributes=null,t.__style=void 0,t.__e=void 0),Dt(n)&&(n.__t=void 0)}}function dt(t=""){return document.createTextNode(t)}function wt(t){return Gt.call(t)}function L(t){return Kt.call(t)}function be(t,e){if(!C)return wt(t);var n=wt(R);if(n===null)n=R.appendChild(dt());else if(e&&n.nodeType!==3){var r=dt();return n==null||n.before(r),Z(r),r}return Z(n),n}function Ie(t,e){if(!C){var n=wt(t);return n instanceof Comment&&n.data===""?L(n):n}return R}function Oe(t,e=1,n=!1){let r=C?R:t;for(var l;e--;)l=r,r=L(r);if(!C)return r;var a=r==null?void 0:r.nodeType;if(n&&a!==3){var u=dt();return r===null?l==null||l.after(u):r.before(u),Z(u),u}return Z(r),r}function Se(t){t.textContent=""}function $t(t){h===null&&v===null&&En(),v!==null&&(v.f&m)!==0&&h===null&&wn(),W&&dn()}function Sn(t,e){var n=e.last;n===null?e.last=e.first=t:(n.next=t,t.prev=n,e.last=t)}function B(t,e,n,r=!0){var l=h,a={ctx:p,deps:null,nodes_start:null,nodes_end:null,f:t|I,first:null,fn:e,last:null,next:null,parent:l,prev:null,teardown:null,transitions:null,wv:0};if(n)try{At(a),a.f|=vn}catch(s){throw F(a),s}else e!==null&&vt(a);var u=n&&a.deps===null&&a.first===null&&a.nodes_start===null&&a.teardown===null&&(a.f&(Mt|nt))===0;if(!u&&r&&(l!==null&&Sn(a,l),v!==null&&(v.f&x)!==0)){var i=v;(i.effects??(i.effects=[])).push(a)}return a}function Nn(t){const e=B(it,null,!1);return D(e,E),e.teardown=t,e}function Ne(t){$t();var e=h!==null&&(h.f&O)!==0&&p!==null&&!p.m;if(e){var n=p;(n.e??(n.e=[])).push({fn:t,effect:h,reaction:v})}else{var r=Zt(t);return r}}function ke(t){return $t(),kn(t)}function Pe(t){const e=B(H,t,!0);return(n={})=>new Promise(r=>{n.outro?Fn(e,()=>{F(e),r(void 0)}):(F(e),r(void 0))})}function Zt(t){return B(Ct,t,!1)}function kn(t){return B(it,t,!0)}function Ce(t,e=[],n=mt){const r=e.map(n);return Pn(()=>t(...r.map(U)))}function Pn(t,e=0){return B(it|gt|e,t,!0)}function Fe(t,e=!0){return B(it|O,t,!0,e)}function zt(t){var e=t.teardown;if(e!==null){const n=W,r=v;Nt(!0),j(null);try{e.call(null)}finally{Nt(n),j(r)}}}function Wt(t,e=!1){var n=t.first;for(t.first=t.last=null;n!==null;){var r=n.next;(n.f&H)!==0?n.parent=null:F(n,e),n=r}}function Cn(t){for(var e=t.first;e!==null;){var n=e.next;(e.f&O)===0&&F(e),e=n}}function F(t,e=!0){var n=!1;if((e||(t.f&hn)!==0)&&t.nodes_start!==null){for(var r=t.nodes_start,l=t.nodes_end;r!==null;){var a=r===l?null:L(r);r.remove(),r=a}n=!0}Wt(t,e&&!n),ft(t,0),D(t,ut);var u=t.transitions;if(u!==null)for(const s of u)s.stop();zt(t);var i=t.parent;i!==null&&i.first!==null&&Xt(t),t.next=t.prev=t.teardown=t.ctx=t.deps=t.fn=t.nodes_start=t.nodes_end=null}function Xt(t){var e=t.parent,n=t.prev,r=t.next;n!==null&&(n.next=r),r!==null&&(r.prev=n),e!==null&&(e.first===t&&(e.first=r),e.last===t&&(e.last=n))}function Fn(t,e){var n=[];Jt(t,n,!0),Mn(n,()=>{F(t),e&&e()})}function Mn(t,e){var n=t.length;if(n>0){var r=()=>--n||e();for(var l of t)l.out(r)}else e()}function Jt(t,e,n){if((t.f&Y)===0){if(t.f^=Y,t.transitions!==null)for(const u of t.transitions)(u.is_global||n)&&e.push(u);for(var r=t.first;r!==null;){var l=r.next,a=(r.f&Ft)!==0||(r.f&O)!==0;Jt(r,e,a?n:!1),r=l}}}function Me(t){Qt(t,!0)}function Qt(t,e){if((t.f&Y)!==0){t.f^=Y,(t.f&E)===0&&(t.f^=E),X(t)&&(D(t,I),vt(t));for(var n=t.first;n!==null;){var r=n.next,l=(n.f&Ft)!==0||(n.f&O)!==0;Qt(n,l?e:!1),n=r}if(t.transitions!==null)for(const a of t.transitions)(a.is_global||e)&&a.in()}}let z=[],Et=[];function tn(){var t=z;z=[],Pt(t)}function Ln(){var t=Et;Et=[],Pt(t)}function Le(t){z.length===0&&queueMicrotask(tn),z.push(t)}function St(){z.length>0&&tn(),Et.length>0&&Ln()}let tt=!1,rt=!1,lt=null,P=!1,W=!1;function Nt(t){W=t}let K=[];let v=null,b=!1;function j(t){v=t}let h=null;function at(t){h=t}let w=null;function nn(t){v!==null&&v.f&pt&&(w===null?w=[t]:w.push(t))}let d=null,g=0,T=null;function qn(t){T=t}let en=1,st=0,k=!1;function rn(){return++en}function X(t){var o;var e=t.f;if((e&I)!==0)return!0;if((e&M)!==0){var n=t.deps,r=(e&m)!==0;if(n!==null){var l,a,u=(e&et)!==0,i=r&&h!==null&&!k,s=n.length;if(u||i){var f=t,_=f.parent;for(l=0;l<s;l++)a=n[l],(u||!((o=a==null?void 0:a.reactions)!=null&&o.includes(f)))&&(a.reactions??(a.reactions=[])).push(f);u&&(f.f^=et),i&&_!==null&&(_.f&m)===0&&(f.f^=m)}for(l=0;l<s;l++)if(a=n[l],X(a)&&Bt(a),a.wv>t.wv)return!0}(!r||h!==null&&!k)&&D(t,E)}return!1}function Yn(t,e){for(var n=e;n!==null;){if((n.f&nt)!==0)try{n.fn(t);return}catch{n.f^=nt}n=n.parent}throw tt=!1,t}function jn(t){return(t.f&ut)===0&&(t.parent===null||(t.parent.f&nt)===0)}function ct(t,e,n,r){if(tt){if(n===null&&(tt=!1),jn(e))throw t;return}n!==null&&(tt=!0);{Yn(t,e);return}}function ln(t,e,n=!0){var r=t.reactions;if(r!==null)for(var l=0;l<r.length;l++){var a=r[l];w!=null&&w.includes(t)||((a.f&x)!==0?ln(a,e,!1):e===a&&(n?D(a,I):(a.f&E)!==0&&D(a,M),vt(a)))}}function an(t){var A;var e=d,n=g,r=T,l=v,a=k,u=w,i=p,s=b,f=t.f;d=null,g=0,T=null,k=(f&m)!==0&&(b||!P||v===null),v=(f&(O|H))===0?t:null,w=null,bt(t.ctx),b=!1,st++,t.f|=pt;try{var _=(0,t.fn)(),o=t.deps;if(d!==null){var c;if(ft(t,g),o!==null&&g>0)for(o.length=g+d.length,c=0;c<d.length;c++)o[g+c]=d[c];else t.deps=o=d;if(!k)for(c=g;c<o.length;c++)((A=o[c]).reactions??(A.reactions=[])).push(t)}else o!==null&&g<o.length&&(ft(t,g),o.length=g);if(_t()&&T!==null&&!b&&o!==null&&(t.f&(x|M|I))===0)for(c=0;c<T.length;c++)ln(T[c],t);return l!==t&&(st++,T!==null&&(r===null?r=T:r.push(...T))),_}finally{d=e,g=n,T=r,v=l,k=a,w=u,bt(i),b=s,t.f^=pt}}function Hn(t,e){let n=e.reactions;if(n!==null){var r=un.call(n,t);if(r!==-1){var l=n.length-1;l===0?n=e.reactions=null:(n[r]=n[l],n.pop())}}n===null&&(e.f&x)!==0&&(d===null||!d.includes(e))&&(D(e,M),(e.f&(m|et))===0&&(e.f^=et),jt(e),ft(e,0))}function ft(t,e){var n=t.deps;if(n!==null)for(var r=e;r<n.length;r++)Hn(t,n[r])}function At(t){var e=t.f;if((e&ut)===0){D(t,E);var n=h,r=p,l=P;h=t,P=!0;try{(e&gt)!==0?Cn(t):Wt(t),zt(t);var a=an(t);t.teardown=typeof a=="function"?a:null,t.wv=en;var u=t.deps,i}catch(s){ct(s,t,n,r||t.ctx)}finally{P=l,h=n}}}function Bn(){try{yn()}catch(t){if(lt!==null)ct(t,lt,null);else throw t}}function sn(){var t=P;try{var e=0;for(P=!0;K.length>0;){e++>1e3&&Bn();var n=K,r=n.length;K=[];for(var l=0;l<r;l++){var a=Vn(n[l]);Un(a)}$.clear()}}finally{rt=!1,P=t,lt=null}}function Un(t){var e=t.length;if(e!==0)for(var n=0;n<e;n++){var r=t[n];if((r.f&(ut|Y))===0)try{X(r)&&(At(r),r.deps===null&&r.first===null&&r.nodes_start===null&&(r.teardown===null?Xt(r):r.fn=null))}catch(l){ct(l,r,null,r.ctx)}}}function vt(t){rt||(rt=!0,queueMicrotask(sn));for(var e=lt=t;e.parent!==null;){e=e.parent;var n=e.f;if((n&(H|O))!==0){if((n&E)===0)return;e.f^=E}}K.push(e)}function Vn(t){for(var e=[],n=t;n!==null;){var r=n.f,l=(r&(O|H))!==0,a=l&&(r&E)!==0;if(!a&&(r&Y)===0){if((r&Ct)!==0)e.push(n);else if(l)n.f^=E;else{var u=v;try{v=n,X(n)&&At(n)}catch(f){ct(f,n,null,n.ctx)}finally{v=u}}var i=n.first;if(i!==null){n=i;continue}}var s=n.parent;for(n=n.next;n===null&&s!==null;)n=s.next,s=s.parent}return e}function Gn(t){var e;for(St();K.length>0;)rt=!0,sn(),St();return e}async function qe(){await Promise.resolve(),Gn()}function U(t){var e=t.f,n=(e&x)!==0;if(v!==null&&!b){if(!(w!=null&&w.includes(t))){var r=v.deps;t.rv<st&&(t.rv=st,d===null&&r!==null&&r[g]===t?g++:d===null?d=[t]:(!k||!d.includes(t))&&d.push(t))}}else if(n&&t.deps===null&&t.effects===null){var l=t,a=l.parent;a!==null&&(a.f&m)===0&&(l.f^=m)}return n&&(l=t,X(l)&&Bt(l)),W&&$.has(t)?$.get(t):t.v}function Ye(t){var e=b;try{return b=!0,t()}finally{b=e}}const Kn=-7169;function D(t,e){t.f=t.f&Kn|e}function je(t){if(!(typeof t!="object"||!t||t instanceof EventTarget)){if(G in t)yt(t);else if(!Array.isArray(t))for(let e in t){const n=t[e];typeof n=="object"&&n&&G in n&&yt(n)}}}function yt(t,e=new Set){if(typeof t=="object"&&t!==null&&!(t instanceof EventTarget)&&!e.has(t)){e.add(t),t instanceof Date&&t.getTime();for(let r in t)try{yt(t[r],e)}catch{}const n=kt(t);if(n!==Object.prototype&&n!==Array.prototype&&n!==Map.prototype&&n!==Set.prototype&&n!==Date.prototype){const r=on(n);for(let l in r){const a=r[l].get;if(a)try{a.call(t)}catch{}}}}}export{In as $,Le as A,h as B,re as C,bn as D,Ft as E,le as F,ge as G,An as H,Y as I,Tt as J,fn as K,se as L,Jt as M,Se as N,Mn as O,F as P,fe as Q,L as R,p as S,ke as T,y as U,Ne as V,Pt as W,Ye as X,Wn as Y,je as Z,mt as _,we as a,ee as a0,ot as a1,V as a2,Xn as a3,G as a4,Jn as a5,ue as a6,_e as a7,ne as a8,oe as a9,qe as aA,Ee as aB,zn as aC,pn as aD,qt as aa,q as ab,N as ac,ce as ad,ie as ae,Qn as af,pe as ag,kt as ah,on as ai,Zn as aj,j as ak,at as al,v as am,De as an,Yt as ao,Vt as ap,te as aq,Pe as ar,hn as as,On as at,ve as au,he as av,Zt as aw,kn as ax,Gn as ay,S as az,Te as b,be as c,Pn as d,xn as e,Ie as f,U as g,C as h,Re as i,Z as j,me as k,Me as l,Fe as m,xe as n,Fn as o,de as p,R as q,Ae as r,Oe as s,Ce as t,dt as u,ae as v,wt as w,ye as x,Rn as y,$n as z};
