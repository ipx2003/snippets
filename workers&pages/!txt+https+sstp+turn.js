import { connect } from 'cloudflare:sockets';

let v1 = 'proxyip.example.com!txt';
let v2 = '495c7195-85b8-498a-bf20-2ea9ce9175b5';
let v3 = null;
let v4 = null;

const v5 = new TextDecoder();
const v6 = s => new TextEncoder().encode(s);

const v7 = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const v8 = /^\[?([a-fA-F0-9:]+)\]?$/;
const v9 = /^\[([^\]]+)\](?::(\d+))?$/;
const v10 = /^(?:\[([^\]]+)\]|([^:]+))(?::(\d+))?$/;
const v11 = /\.tp(\d+)/;
const v12 = /sstp:\/\/([^?&#\s]*)/i;
const v13 = /turn:\/\/([^?&#\s]*)/i;

const { TlsClient } = (() => {
const e=769,t=771,n=772,r=20,i=21,s=22,a=23,h=1,c=2,o=4,l=8,f=11,u=12,y=13,p=14,w=15,d=16,g=20,k=24,v=0,A=10,S=11,m=13,b=16,C=43,H=45,T=51,E=0,L=new TextEncoder,K=new TextDecoder,P=new Uint8Array(0),U=new Map(Object.entries({TLS_AES_128_GCM_SHA256:{id:4865,keyLen:16,ivLen:12,hash:"SHA-256",tls13:!0},TLS_AES_256_GCM_SHA384:{id:4866,keyLen:32,ivLen:12,hash:"SHA-384",tls13:!0},TLS_CHACHA20_POLY1305_SHA256:{id:4867,keyLen:32,ivLen:12,hash:"SHA-256",tls13:!0,chacha:!0},TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:{id:49199,keyLen:16,ivLen:4,hash:"SHA-256",kex:"ECDHE"},TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:{id:49200,keyLen:32,ivLen:4,hash:"SHA-384",kex:"ECDHE"},TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:{id:52392,keyLen:32,ivLen:12,hash:"SHA-256",kex:"ECDHE",chacha:!0},TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:{id:49195,keyLen:16,ivLen:4,hash:"SHA-256",kex:"ECDHE"},TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:{id:49196,keyLen:32,ivLen:4,hash:"SHA-384",kex:"ECDHE"},TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:{id:52393,keyLen:32,ivLen:12,hash:"SHA-256",kex:"ECDHE",chacha:!0}}).map((([,e])=>[e.id,e]))),I=new Map([[29,"X25519"],[23,"P-256"]]),x=[2052,2053,2054,1025,1281,1537,1027,1283,1539],_=(...e)=>{const t=e=>{const n=[];for(const r of e)r instanceof Uint8Array?n.push(...r):Array.isArray(r)?n.push(...t(r)):"number"==typeof r&&n.push(r);return n};return new Uint8Array(t(e))},B=e=>[e>>8&255,255&e],R=(e,t)=>e[t]<<8|e[t+1],M=(e,t)=>e[t]<<16|e[t+1]<<8|e[t+2],W=(...e)=>{let s=0;for(let i=0;i<e.length;i++)if(e[i])s+=e[i].length;const r=new Uint8Array(s);let o=0;for(let i=0;i<e.length;i++){if(e[i]&&e[i].length>0){r.set(e[i],o);o+=e[i].length;}}return r;},D=e=>crypto.getRandomValues(new Uint8Array(e)),N=(e,t)=>{if(!e||!t||e.length!==t.length)return!1;let n=0;for(let r=0;r<e.length;r++)n|=e[r]^t[r];return 0===n},q=e=>"SHA-512"===e?64:"SHA-384"===e?48:32;async function $(e,t,n){const r=await crypto.subtle.importKey("raw",t,{name:"HMAC",hash:e},!1,["sign"]);return new Uint8Array(await crypto.subtle.sign("HMAC",r,n))}async function G(e,t){return new Uint8Array(await crypto.subtle.digest(e,t))}async function V(e,t,n,r,i="SHA-256"){const s=W(L.encode(t),n);let a=new Uint8Array(0),h=s;for(;a.length<r;){h=await $(i,e,h);const t=await $(i,e,W(h,s));a=W(a,t)}return a.slice(0,r)}async function X(e,t,n){return t&&t.length||(t=new Uint8Array(q(e))),$(e,t,n)}async function O(e,t,n,r,i){const s=L.encode("tls13 "+n);return async function(e,t,n,r){const i=q(e),s=Math.ceil(r/i);let a=new Uint8Array(0),h=new Uint8Array(0);for(let r=1;r<=s;r++)h=await $(e,t,W(h,n,[r])),a=W(a,h);return a.slice(0,r)}(e,t,_(B(i),s.length,s,r.length,r),i)}async function F(e="P-256"){if("X25519"===e){const e=await crypto.subtle.generateKey({name:"X25519"},!0,["deriveBits"]);return{keyPair:e,publicKeyRaw:new Uint8Array(await crypto.subtle.exportKey("raw",e.publicKey))}}const t=await crypto.subtle.generateKey({name:"ECDH",namedCurve:e},!0,["deriveBits"]);return{keyPair:t,publicKeyRaw:new Uint8Array(await crypto.subtle.exportKey("raw",t.publicKey))}}async function Y(e,t,n="P-256"){if("X25519"===n){const n=await crypto.subtle.importKey("raw",t,{name:"X25519"},!1,[]);return new Uint8Array(await crypto.subtle.deriveBits({name:"X25519",public:n},e,256))}const r=await crypto.subtle.importKey("raw",t,{name:"ECDH",namedCurve:n},!1,[]),i="P-384"===n?384:"P-521"===n?528:256;return new Uint8Array(await crypto.subtle.deriveBits({name:"ECDH",public:r},e,i))}async function j(e,t,n,r){const i=await crypto.subtle.importKey("raw",e,{name:"AES-GCM"},!1,["encrypt"]);return new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:t,additionalData:r,tagLength:128},i,n))}async function z(e,t,n,r){const i=await crypto.subtle.importKey("raw",e,{name:"AES-GCM"},!1,["decrypt"]);return new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:t,additionalData:r,tagLength:128},i,n))}function J(e,t){return(e<<t|e>>>32-t)>>>0}function Q(e,t,n,r,i){e[t]=e[t]+e[n]>>>0,e[i]=J(e[i]^e[t],16),e[r]=e[r]+e[i]>>>0,e[n]=J(e[n]^e[r],12),e[t]=e[t]+e[n]>>>0,e[i]=J(e[i]^e[t],8),e[r]=e[r]+e[i]>>>0,e[n]=J(e[n]^e[r],7)}function Z(e,t,n){const r=new Uint32Array(16);r[0]=1634760805,r[1]=857760878,r[2]=2036477234,r[3]=1797285236;const i=new DataView(e.buffer,e.byteOffset,e.byteLength);for(let e=0;e<8;e++)r[4+e]=i.getUint32(4*e,!0);r[12]=t;const s=new DataView(n.buffer,n.byteOffset,n.byteLength);r[13]=s.getUint32(0,!0),r[14]=s.getUint32(4,!0),r[15]=s.getUint32(8,!0);const a=new Uint32Array(r);for(let e=0;e<10;e++)Q(a,0,4,8,12),Q(a,1,5,9,13),Q(a,2,6,10,14),Q(a,3,7,11,15),Q(a,0,5,10,15),Q(a,1,6,11,12),Q(a,2,7,8,13),Q(a,3,4,9,14);for(let e=0;e<16;e++)a[e]=a[e]+r[e]>>>0;return new Uint8Array(a.buffer.slice(0))}function ee(e,t,n){const r=new Uint8Array(n.length);let i=1;for(let s=0;s<n.length;s+=64){const a=Z(e,i++,t),h=Math.min(64,n.length-s);for(let e=0;e<h;e++)r[s+e]=n[s+e]^a[e]}return r}function te(e,t){const n=function(e){const t=new Uint8Array(e);return t[3]&=15,t[7]&=15,t[11]&=15,t[15]&=15,t[4]&=252,t[8]&=252,t[12]&=252,t}(e.slice(0,16)),r=e.slice(16,32);let i=[0n,0n,0n,0n,0n];const s=[0x3ffffffn&BigInt(n[0]|n[1]<<8|n[2]<<16|n[3]<<24),0x3ffffffn&BigInt(n[3]>>2|n[4]<<6|n[5]<<14|n[6]<<22),0x3ffffffn&BigInt(n[6]>>4|n[7]<<4|n[8]<<12|n[9]<<20),0x3ffffffn&BigInt(n[9]>>6|n[10]<<2|n[11]<<10|n[12]<<18),0x3ffffffn&BigInt(n[13]|n[14]<<8|n[15]<<16)];for(let e=0;e<t.length;e+=16){const n=t.slice(e,e+16),r=new Uint8Array(17);r.set(n),r[n.length]=1,i[0]+=BigInt(r[0]|r[1]<<8|r[2]<<16|(3&r[3])<<24),i[1]+=BigInt(r[3]>>2|r[4]<<6|r[5]<<14|(15&r[6])<<22),i[2]+=BigInt(r[6]>>4|r[7]<<4|r[8]<<12|(63&r[9])<<20),i[3]+=BigInt(r[9]>>6|r[10]<<2|r[11]<<10|r[12]<<18),i[4]+=BigInt(r[13]|r[14]<<8|r[15]<<16|r[16]<<24);const a=[0n,0n,0n,0n,0n];for(let e=0;e<5;e++)for(let t=0;t<5;t++){const n=e+t;n<5?a[n]+=i[e]*s[t]:a[n-5]+=i[e]*s[t]*5n}let h=0n;for(let e=0;e<5;e++)a[e]+=h,i[e]=0x3ffffffn&a[e],h=a[e]>>26n;i[0]+=5n*h,h=i[0]>>26n,i[0]&=0x3ffffffn,i[1]+=h}let a=i[0]|i[1]<<26n|i[2]<<52n|i[3]<<78n|i[4]<<104n;a=a+r.reduce(((e,t,n)=>e+(BigInt(t)<<BigInt(8*n))),0n)&(1n<<128n)-1n;const h=new Uint8Array(16);for(let e=0;e<16;e++)h[e]=Number(a>>BigInt(8*e)&0xffn);return h}function ne(e,t,n,r){const i=Z(e,0,t).slice(0,32),s=ee(e,t,n),a=(16-r.length%16)%16,h=(16-s.length%16)%16,c=new Uint8Array(r.length+a+s.length+h+16);c.set(r,0),c.set(s,r.length+a);const o=new DataView(c.buffer,r.length+a+s.length+h);o.setBigUint64(0,BigInt(r.length),!0),o.setBigUint64(8,BigInt(s.length),!0);const l=te(i,c);return W(s,l)}function re(e,t,n,r){if(n.length<16)throw new Error("Ciphertext too short");const i=n.slice(-16),s=n.slice(0,-16),a=Z(e,0,t).slice(0,32),h=(16-r.length%16)%16,c=(16-s.length%16)%16,o=new Uint8Array(r.length+h+s.length+c+16);o.set(r,0),o.set(s,r.length+h);const l=new DataView(o.buffer,r.length+h+s.length+c);l.setBigUint64(0,BigInt(r.length),!0),l.setBigUint64(8,BigInt(s.length),!0);const f=te(a,o);let u=0;for(let e=0;e<16;e++)u|=i[e]^f[e];if(0!==u)throw new Error("ChaCha20-Poly1305 authentication failed");return ee(e,t,s)}function ie(e,n,r=t){return _(e,B(r),B(n.length),n)}function se(e,t){return _(e,(e=>[e>>16&255,e>>8&255,255&e])(t.length),t)}class ae{constructor(){this.buffer=new Uint8Array(0)}feed(e){this.buffer=W(this.buffer,e)}next(){if(this.buffer.length<5)return null;const e=this.buffer[0],t=R(this.buffer,1),n=R(this.buffer,3);if(this.buffer.length<5+n)return null;const r=this.buffer.slice(5,5+n);return this.buffer=this.buffer.slice(5+n),{type:e,version:t,length:n,fragment:r}}}class he{constructor(){this.buffer=new Uint8Array(0)}feed(e){this.buffer=W(this.buffer,e)}next(){if(this.buffer.length<4)return null;const e=this.buffer[0],t=M(this.buffer,1);if(this.buffer.length<4+t)return null;const n=this.buffer.slice(4,4+t),r=this.buffer.slice(0,4+t);return this.buffer=this.buffer.slice(4+t),{type:e,length:t,body:n,raw:r}}}function ce(e){let t=0;const r=R(e,t);t+=2;const i=e.slice(t,t+32);t+=32;const s=e[t++],a=e.slice(t,t+s);t+=s;const h=R(e,t);t+=2;const c=e[t++];let o=r,l=null,f=null;if(t<e.length){const n=R(e,t);t+=2;const r=t+n;for(;t+4<=r;){const n=R(e,t);t+=2;const r=R(e,t);t+=2;const i=e.slice(t,t+r);if(t+=r,n===C&&r>=2)o=R(i,0);else if(n===T&&r>=4){const e=R(i,0),t=R(i,2);l={group:e,key:i.slice(4,4+t)}}else n===b&&r>=3&&(f=K.decode(i.slice(3,3+i[2])))}}const u=new Uint8Array([207,33,173,116,229,154,97,17,190,29,140,2,30,101,184,145,194,162,17,22,122,187,140,94,7,158,9,226,200,168,51,156]);return{version:r,serverRandom:i,sessionId:a,cipherSuite:h,compression:c,selectedVersion:o,keyShare:l,alpn:f,isHRR:N(i,u),isTls13:o===n}}function oe(e){let t=0;t++;const n=R(e,t);t+=2;const r=e[t++];return{namedCurve:n,serverPublicKey:e.slice(t,t+r)}}function le(e,t=0){let n=0;if(t){const t=e[n++];n+=t}if(n+3>e.length)return null;const r=M(e,n);if(n+=3,!r||n+3>e.length)return null;const i=M(e,n);return n+=3,i?e.slice(n,n+i):null}function fe(e){const t={alpn:null};let n=2;const r=2+R(e,0);for(;n+4<=r;){const r=R(e,n);n+=2;const i=R(e,n);if(n+=2,r===b&&i>=3){const r=e[n+2];r>0&&n+3+r<=n+i&&(t.alpn=K.decode(e.slice(n+3,n+3+r)))}n+=i}return t}const F0=e=>{if(e=String(e??"").trim(),"["===e[0]&&"]"===e[e.length-1]&&(e=e.slice(1,-1)),!e||e.includes(":"))return"";const t=e.split(".");if(4!==t.length)return e;for(const n of t){if(""===n||n.length>3)return e;let t=0;for(let r=0;r<n.length;r++){const i=n.charCodeAt(r)-48;if(i<0||i>9)return e;t=10*t+i}if(t>255)return e}return""},Z0=e=>e&&1===e[0]&&112===e[1];function ue(e,n,r,{tls13:i=!0,tls12:s=!0,alpn:a=null}={}){n=F0(n);const c=[];i&&c.push(4865,4866,4867),s&&c.push(49199,49200,52392,49195,49196,52393);const o=_(...c.flatMap(B)),l=[_(255,1,0,1,0)];if(n){const e=L.encode(n),t=_(0,B(e.length),e);l.push(_(B(v),B(t.length+2),B(t.length),t))}l.push(_(B(S),0,2,1,0)),l.push(_(B(A),0,6,0,4,0,29,0,23));const f=_(...x.flatMap(B));l.push(_(B(m),B(f.length+2),B(f.length),f));const u=Array.isArray(a)?a.filter(Boolean):a?[a]:[];if(u.length){const e=W(...u.map((e=>{const t=L.encode(e);return _(t.length,t)})));l.push(_(B(b),B(e.length+2),B(e.length),e))}if(i&&r){let e;if(l.push(s?_(B(C),0,5,4,3,4,3,3):_(B(C),0,3,2,3,4)),l.push(_(B(H),0,2,1,1)),r?.x25519&&r?.p256)e=W(_(0,29,B(r.x25519.length),r.x25519),_(0,23,B(r.p256.length),r.p256));else if(r?.x25519)e=_(0,29,B(r.x25519.length),r.x25519);else if(r?.p256)e=_(0,23,B(r.p256.length),r.p256);else{if(!(r instanceof Uint8Array))throw new Error("Invalid keyShares");e=_(0,23,B(r.length),r)}l.push(_(B(T),B(e.length+2),B(e.length),e))}const y=W(...l);return se(h,_(B(t),e,0,B(o.length),o,1,0,B(y.length),y))}const ye=e=>{const t=new Uint8Array(8);return new DataView(t.buffer).setBigUint64(0,e,!1),t},pe=(e,t)=>{const n=e.slice(),r=ye(t);for(let e=0;e<8;e++)n[n.length-8+e]^=r[e];return n},we=(e,t,n,r)=>Promise.all([O(e,t,"key",P,n),O(e,t,"iv",P,r)]);class TlsClient{constructor(e,t={}){if(this.socket=e,this.serverName=t.serverName||"",this.supportTls13=!1!==t.tls13,this.supportTls12=!1!==t.tls12,!this.supportTls13&&!this.supportTls12)throw new Error("At least one TLS version must be enabled");this.alpnProtocols=Array.isArray(t.alpn)?t.alpn:t.alpn?[t.alpn]:null,this.timeout=t.timeout??3e4,this.clientRandom=D(32),this.serverRandom=null,this.handshakeChunks=[],this.handshakeComplete=!1,this.negotiatedAlpn=null,this.cipherSuite=null,this.cipherConfig=null,this.isTls13=!1,this.masterSecret=null,this.handshakeSecret=null,this.clientWriteKey=null,this.serverWriteKey=null,this.clientWriteIv=null,this.serverWriteIv=null,this.clientHandshakeKey=null,this.serverHandshakeKey=null,this.clientHandshakeIv=null,this.serverHandshakeIv=null,this.clientAppKey=null,this.serverAppKey=null,this.clientAppIv=null,this.serverAppIv=null,this.clientSeqNum=0n,this.serverSeqNum=0n,this.recordParser=new ae,this.handshakeParser=new he,this.keyPairs=new Map,this.ecdhKeyPair=null,this.sawCert=!1}recordHandshake(e){this.handshakeChunks.push(e)}transcript(){return 1===this.handshakeChunks.length?this.handshakeChunks[0]:W(...this.handshakeChunks)}getCipherConfig(e){return U.get(e)||null}
async readChunk(e){
    const v=new Uint8Array(4096);
    if(!this.timeout){
        const {value:a,done:b} = await e.read(v);
        return {value: a ? new Uint8Array(a) : undefined, done: b};
    }
    let t;const n=e.read(v),r=await Promise.race([n,new Promise(x=>t=setTimeout(x,this.timeout,0))]).finally(()=>clearTimeout(t));
    if(r)return {value: r.value ? new Uint8Array(r.value) : undefined, done: r.done};
    try{await e.cancel("TLS read timeout")}catch{}
    try{await n}catch{}
    throw new Error("TLS read timeout")
}
async pr(e,t,n){for(;;){let r;for(;r=this.recordParser.next();)if(await t(r))return;const{value:i,done:s}=await this.readChunk(e);if(s)throw new Error(n);this.recordParser.feed(i)}}async ph(e,t,n){for(let e;e=this.handshakeParser.next();)if(await t(e))return;return this.pr(e,(async e=>{if(e.type===i){if(Z0(e.fragment))return;throw new Error(`TLS Alert: ${e.fragment[1]}`)}if(e.type===s){this.handshakeParser.feed(e.fragment);for(let e;e=this.handshakeParser.next();)if(await t(e))return 1}}),n)}async acceptCertificate(e){if(!e?.length)throw new Error("Empty certificate");this.sawCert=!0}async handshake(){const[t,n]=await Promise.all([F("P-256"),F("X25519")]);this.keyPairs=new Map([[23,t],[29,n]]),this.ecdhKeyPair=t.keyPair;const r=this.socket.readable.getReader({mode:'byob'}),i=this.socket.writable.getWriter();try{const a=ue(this.clientRandom,this.serverName,{x25519:n.publicKeyRaw,p256:t.publicKeyRaw},{tls13:this.supportTls13,tls12:this.supportTls12,alpn:this.alpnProtocols});this.recordHandshake(a),await i.write(ie(s,a,e));const h=await this.receiveServerHello(r);if(h.isHRR)throw new Error("HelloRetryRequest is not supported by TLSClientMini");if(h.keyShare?.group&&this.keyPairs.has(h.keyShare.group)){const e=this.keyPairs.get(h.keyShare.group);this.ecdhKeyPair=e.keyPair}h.isTls13?await this.handshakeTls13(r,i,h):await this.handshakeTls12(r,i),this.handshakeComplete=!0}finally{r.releaseLock(),i.releaseLock()}}async receiveServerHello(e){for(;;){const{value:t,done:n}=await this.readChunk(e);if(n)throw new Error("Connection closed waiting for ServerHello");let r;for(this.recordParser.feed(t);r=this.recordParser.next();){if(r.type===i){if(Z0(r.fragment))continue;throw new Error(`TLS Alert: level=${r.fragment[0]}, desc=${r.fragment[1]}`)}if(r.type!==s)continue;let e;for(this.handshakeParser.feed(r.fragment);e=this.handshakeParser.next();){if(e.type!==c)continue;this.recordHandshake(e.raw);const t=ce(e.body);if(this.serverRandom=t.serverRandom,this.cipherSuite=t.cipherSuite,this.cipherConfig=this.getCipherConfig(t.cipherSuite),this.isTls13=t.isTls13,this.negotiatedAlpn=t.alpn||null,!this.cipherConfig)throw new Error(`Unsupported cipher suite: 0x${t.cipherSuite.toString(16)}`);return t}}}}async handshakeTls12(e,t){let n=null,a=!1;if(await this.ph(e,(async e=>{switch(e.type){case f:{this.recordHandshake(e.raw);const t=le(e.body,1);if(!t)throw new Error("Missing TLS 1.2 certificate");await this.acceptCertificate(t);break}case u:this.recordHandshake(e.raw),n=oe(e.body);break;case p:return this.recordHandshake(e.raw),a=!0,1;case y:throw new Error("Client certificate is not supported");default:this.recordHandshake(e.raw)}}),"Connection closed during TLS 1.2 handshake"),!this.sawCert)throw new Error("Missing TLS 1.2 leaf certificate");if(!n)throw new Error("Missing TLS 1.2 ServerKeyExchange");const h=I.get(n.namedCurve);if(!h)throw new Error(`Unsupported named curve: 0x${n.namedCurve.toString(16)}`);const c=this.keyPairs.get(n.namedCurve);if(!c)throw new Error(`Missing key pair for curve: 0x${n.namedCurve.toString(16)}`);const o=await Y(c.keyPair.privateKey,n.serverPublicKey,h),l=se(d,_(c.publicKeyRaw.length,c.publicKeyRaw));this.recordHandshake(l);const w=this.cipherConfig.hash;this.masterSecret=await V(o,"master secret",W(this.clientRandom,this.serverRandom),48,w);const k=this.cipherConfig.keyLen,v=this.cipherConfig.ivLen,A=await V(this.masterSecret,"key expansion",W(this.serverRandom,this.clientRandom),2*k+2*v,w);this.clientWriteKey=A.slice(0,k),this.serverWriteKey=A.slice(k,2*k),this.clientWriteIv=A.slice(2*k,2*k+v),this.serverWriteIv=A.slice(2*k+v,2*k+2*v),await t.write(ie(s,l)),await t.write(ie(r,_(1)));const S=await V(this.masterSecret,"client finished",await G(w,this.transcript()),12,w),m=se(g,S);this.recordHandshake(m),await t.write(ie(s,await this.encryptTls12(m,s)));let b=!1;await this.pr(e,(async e=>{if(e.type===i){if(Z0(e.fragment))return;throw new Error(`TLS Alert: ${e.fragment[1]}`)}if(e.type===r)return void(b=!0);if(e.type!==s||!b)return;const t=await this.decryptTls12(e.fragment,s);if(t[0]!==g)return;const n=M(t,1),a=t.slice(4,4+n),h=await V(this.masterSecret,"server finished",await G(w,this.transcript()),12,w);if(!N(a,h))throw new Error("TLS 1.2 server Finished verify failed");return 1}),"Connection closed waiting for TLS 1.2 Finished")}async handshakeTls13(e,t,n){const h=I.get(n.keyShare?.group);if(!h||!n.keyShare?.key?.length)throw new Error("Missing TLS 1.3 key_share");const c=this.cipherConfig.hash,o=q(c),u=this.cipherConfig.keyLen,p=this.cipherConfig.ivLen,d=await Y(this.ecdhKeyPair.privateKey,n.keyShare.key,h),k=await X(c,null,new Uint8Array(o)),v=await O(c,k,"derived",await G(c,P),o);this.handshakeSecret=await X(c,v,d);const A=await G(c,this.transcript()),S=await O(c,this.handshakeSecret,"c hs traffic",A,o),m=await O(c,this.handshakeSecret,"s hs traffic",A,o);[this.clientHandshakeKey,this.clientHandshakeIv]=await we(c,S,u,p),[this.serverHandshakeKey,this.serverHandshakeIv]=await we(c,m,u,p);const b=await O(c,m,"finished",P,o);let C=!1;const H=async e=>{switch(e.type){case l:{const t=fe(e.body);t.alpn&&(this.negotiatedAlpn=t.alpn),this.recordHandshake(e.raw);break}case f:{const t=le(e.body);if(!t)throw new Error("Missing TLS 1.3 certificate");await this.acceptCertificate(t),this.recordHandshake(e.raw);break}case y:throw new Error("Client certificate is not supported");case w:this.recordHandshake(e.raw);break;case g:{const t=await $(c,b,await G(c,this.transcript()));if(!N(t,e.body))throw new Error("TLS 1.3 server Finished verify failed");this.recordHandshake(e.raw),C=!0;break}default:this.recordHandshake(e.raw)}};await this.pr(e,(async e=>{if(e.type===r||e.type===s)return;if(e.type===i){if(Z0(e.fragment))return;throw new Error(`TLS Alert: ${e.fragment[1]}`)}if(e.type!==a)return;const t=await this.decryptTls13Handshake(e.fragment),n=t[t.length-1],h=t.slice(0,-1);if(n===s){this.handshakeParser.feed(h);for(let e;e=this.handshakeParser.next();)if(await H(e),C)return 1}}),"Connection closed during TLS 1.3 handshake");const T=await G(c,this.transcript()),E=await O(c,this.handshakeSecret,"derived",await G(c,P),o),L=await X(c,E,new Uint8Array(o)),K=await O(c,L,"c ap traffic",T,o),U=await O(c,L,"s ap traffic",T,o);[this.clientAppKey,this.clientAppIv]=await we(c,K,u,p),[this.serverAppKey,this.serverAppIv]=await we(c,U,u,p);const x=await O(c,S,"finished",P,o),_=await $(c,x,await G(c,this.transcript())),B=se(g,_);this.recordHandshake(B),await t.write(ie(a,await this.encryptTls13Handshake(W(B,[s])))),this.clientSeqNum=0n,this.serverSeqNum=0n}async encryptTls12(e,n){const r=this.clientSeqNum++,i=ye(r),s=W(i,[n],B(t),B(e.length));if(this.cipherConfig.chacha){const t=pe(this.clientWriteIv,r);return ne(this.clientWriteKey,t,e,s)}const a=D(8);return W(a,await j(this.clientWriteKey,W(this.clientWriteIv,a),e,s))}async decryptTls12(e,n){const r=this.serverSeqNum++,i=ye(r);if(this.cipherConfig.chacha){const s=pe(this.serverWriteIv,r);return re(this.serverWriteKey,s,e,W(i,[n],B(t),B(e.length-16)))}const s=e.slice(0,8),a=e.slice(8);return z(this.serverWriteKey,W(this.serverWriteIv,s),a,W(i,[n],B(t),B(a.length-16)))}async encryptTls13Handshake(e){const t=pe(this.clientHandshakeIv,this.clientSeqNum++),n=_(a,3,3,B(e.length+16));return this.cipherConfig.chacha?ne(this.clientHandshakeKey,t,e,n):j(this.clientHandshakeKey,t,e,n)}async decryptTls13Handshake(e){const t=pe(this.serverHandshakeIv,this.serverSeqNum++),n=_(a,3,3,B(e.length));return this.cipherConfig.chacha?re(this.serverHandshakeKey,t,e,n):z(this.serverHandshakeKey,t,e,n)}async encryptTls13(e){const t=W(e,[a]),n=pe(this.clientAppIv,this.clientSeqNum++),r=_(a,3,3,B(t.length+16));return this.cipherConfig.chacha?ne(this.clientAppKey,n,t,r):j(this.clientAppKey,n,t,r)}async decryptTls13(e){const t=pe(this.serverAppIv,this.serverSeqNum++),n=_(a,3,3,B(e.length)),r=this.cipherConfig.chacha?await re(this.serverAppKey,t,e,n):await z(this.serverAppKey,t,e,n);return{data:r.slice(0,-1),type:r[r.length-1]}}async write(e){if(!this.handshakeComplete)throw new Error("Handshake not complete");const t=this.socket.writable.getWriter();try{this.isTls13?await t.write(ie(a,await this.encryptTls13(e))):await t.write(ie(a,await this.encryptTls12(e,a)))}finally{t.releaseLock()}}async read(){for(;;){let e;for(;e=this.recordParser.next();){if(e.type===i){if(e.fragment[1]===E)return null;throw new Error(`TLS Alert: ${e.fragment[1]}`)}if(e.type!==a)continue;if(!this.isTls13)return this.decryptTls12(e.fragment,a);const{data:t,type:n}=await this.decryptTls13(e.fragment);if(n===a)return t;if(n!==s)continue;let r;for(this.handshakeParser.feed(t);r=this.handshakeParser.next();)if(r.type!==o&&r.type===k)throw new Error("TLS 1.3 KeyUpdate is not supported by TLSClientMini")}const t=this.socket.readable.getReader({mode:'byob'});try{const{value:e,done:n}=await this.readChunk(t);if(n)return null;this.recordParser.feed(e)}finally{t.releaseLock()}}}close(){this.socket.close()}}
return { TlsClient };
})();

const f15 = url => {
    if (!url) return null;
    try { url = decodeURIComponent(url); } catch {}
    const m = url.match(/(?:^|[\?&])https:\/\/([^&\s]+)/i);
    if (!m) return null;
    let t = m[1];
    const insecure = /!ip\b/i.test(url);
    t = t.replace(/!ip\b/i, '');
    const at = t.lastIndexOf('@');
    let u = null, p = null, hp = t;
    if (at !== -1) {
        const up = t.slice(0, at).split(':');
        u = up[0]; p = up.slice(1).join(':');
        hp = t.slice(at + 1);
    }
    let h = hp, pt = 443;
    const hm = hp.match(v10);
    if (hm) {
        h = hm[1] || hm[2];
        pt = hm[3] ? parseInt(hm[3], 10) : 443;
    }
    return { u, p, h, pt, insecure };
};

const f16 = async (tg, pt, px) => {
    let h = `CONNECT ${tg}:${pt} HTTP/1.1\r\nHost: ${tg}:${pt}\r\n`;
    if (px.u) h += `Proxy-Authorization: Basic ${btoa(px.u + ':' + (px.p || ''))}\r\n`;
    h += '\r\n';

    if (px.insecure) {
        const sk = connect({ hostname: px.h, port: px.pt });
        await sk.opened;
        const tc = new TlsClient(sk, { serverName: px.h, insecure: true });
        await tc.handshake();
        await tc.write(v6(h));
        
        let rs = '';
        while (1) {
            const d = await tc.read();
            if (!d) return null;
            rs += v5.decode(d);
            if (rs.includes('\r\n\r\n')) break;
            if (rs.length > 1024) return null;
        }
        if (!/^HTTP\/1\.[01] 200/.test(rs)) { tc.close(); return null; }

        const rd = new ReadableStream({
            async pull(c) {
                try {
                    const d = await tc.read();
                    if (d) c.enqueue(d); else c.close();
                } catch (e) { c.error(e); }
            },
            cancel() { tc.close(); }
        });
        const wr = new WritableStream({
            async write(ck) { await tc.write(ck); },
            close() { tc.close(); },
            abort() { tc.close(); }
        });
        return { readable: rd, writable: wr, close: () => tc.close() };
    }

    const sk = connect({ hostname: px.h, port: px.pt }, { secureTransport: 'on', allowHalfOpen: false });
    await sk.opened;
    const w = sk.writable.getWriter();
    await w.write(v6(h));
    w.releaseLock();

    const r = sk.readable.getReader({ mode: 'byob' });
    let bf = new Uint8Array(4096), bl = 0;
    while (1) {
        const { value, done } = await r.read(new Uint8Array(bf.buffer, bl, bf.byteLength - bl));
        if (done || !value) { r.releaseLock(); return null; }
        bf = new Uint8Array(value.buffer);
        bl += value.byteLength;

        if (bl >= 12 && bf[9] !== 50) { r.releaseLock(); return null; }
        for (let i = 0; i <= bl - 4; i++) {
            if (bf[i] === 13 && bf[i + 1] === 10 && bf[i + 2] === 13 && bf[i + 3] === 10) {
                r.releaseLock();
                if (bl > i + 4) {
                    const { readable, writable } = new TransformStream();
                    const tw = writable.getWriter();
                    tw.write(bf.subarray(i + 4, bl));
                    tw.releaseLock();
                    sk.readable.pipeTo(writable).catch(() => {});
                    return { readable, writable: sk.writable, close: () => sk.close() };
                }
                return sk;
            }
        }
        if (bl === bf.byteLength) {
            const nb = new Uint8Array(bf.byteLength * 2);
            nb.set(bf); bf = nb;
        }
        if (bl > 8192) { r.releaseLock(); return null; }
    }
};

function f1(a, o = 0) {
    let h = '';
    for (let i = 0; i < 16; i++) {
        let hex = a[o + i].toString(16);
        h += hex.length === 1 ? '0' + hex : hex;
    }
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function f2(s) {
    if (!s) return { e: null };
    try {
        const b = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
        const y = new Uint8Array(b.length);
        for(let i=0; i<b.length; i++) y[i] = b.charCodeAt(i);
        return { d: y.buffer, e: null };
    } catch (e) { return { e }; }
}

function f3(s) {
    try { if (s?.readyState === WebSocket.OPEN || s?.readyState === WebSocket.CLOSING) s.close(); } catch (e) {}
}

function f4(p) {
    if (!p) return null;
    p = p.trim();
    const m = p.match(v9);
    if (m) {
        const pt = parseInt(m[2], 10);
        return { t: 'direct', h: m[1], p: (!isNaN(pt) && pt > 0) ? pt : 443 };
    }
    const l = p.lastIndexOf(':');
    if (l > 0) {
        const h = p.substring(0, l);
        const pt = parseInt(p.substring(l + 1), 10);
        if (!isNaN(pt) && pt > 0 && pt <= 65535) return { t: 'direct', h, p: pt };
    }
    return { t: 'direct', h: p, p: 443 };
}

async function f5(d, t) {
    const fn = async (u) => {
        try {
            const r = await fetch(`${u}?name=${d}&type=${t}`, { 
                headers: { 'Accept': 'application/dns-json' },
                cf: { cacheTtl: 3600, cacheEverything: true }
            });
            if (r.ok) { const j = await r.json(); return j.Answer || []; }
        } catch (e) {}
        return null;
    };
    const r = await fn('https://1.1.1.1/dns-query');
    return r || (await fn('https://dns.google/dns-query')) || [];
}

function f6(s) {
    let a = s, p = 443;
    const m = s.match(v10);
    if (m) { a = m[1] || m[2]; p = m[3] ? parseInt(m[3], 10) : 443; }
    return [a, p];
}

async function f7(s, t = 'dash.cloudflare.com', u = '00000000-0000-4000-8000-000000000000') {
    const rs = s.trim();
    if (v3 === rs && v4) return v4;
    const ls = rs.toLowerCase();
    const i = ls.endsWith('!txt');
    const td = i ? rs.slice(0, -4).trim() : rs;
    let a = [];

    if (i) {
        const tr = await f5(td, 'TXT');
        const td2 = tr.filter(r => r.type === 16).map(r => r.data);
        if (td2.length > 0) {
            let d = td2[0].replace(/^"|"$/g, '');
            const p = d.replace(/\\010|\n/g, ',').split(',').map(x => x.trim()).filter(Boolean);
            a = p.map(f6);
        }
    } else {
        let [ad, pt] = f6(td);
        const tm = td.match(v11);
        if (tm) pt = parseInt(tm[1], 10);

        if (!v7.test(ad) && !v8.test(ad)) {
            const [ar, a4r] = await Promise.all([f5(ad, 'A'), f5(ad, 'AAAA')]);
            const i4 = ar.filter(r => r.type === 1).map(r => r.data);
            const i6 = a4r.filter(r => r.type === 28).map(r => `[${r.data}]`);
            const ip = [...i4, ...i6];
            a = ip.length > 0 ? ip.map(x => [x, pt]) : [[ad, pt]];
        } else {
            a = [[ad, pt]];
        }
    }

    const sa = a.sort((x, y) => x[0].localeCompare(y[0]));
    const trg = t.includes('.') ? t.split('.').slice(-2).join('.') : t;
    let sd = [...(trg + u)].reduce((ac, c) => ac + c.charCodeAt(0), 0);

    v4 = [...sa].sort(() => {
        sd = (sd * 1103515245 + 12345) & 0x7fffffff;
        return (sd / 0x7fffffff) - 0.5;
    }).slice(0, 8);
    
    v3 = rs;
    return v4;
}

export default {
    async fetch(rq, e, c) {
        try {
            const u = new URL(rq.url);
            const is = rq.headers.get('Upgrade') === 'websocket';
            let cv = null;

            if (u.pathname.startsWith('/fdip=')) {
                try { cv = decodeURIComponent(u.pathname.substring(9)).trim(); } catch (e) {}
                if (cv && !is) {
                    v1 = cv;
                    return new Response(`set fdIP to: ${v1}\n\n`, {
                        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0' },
                    });
                }
            }

            if (is) {
                const fv = cv || u.searchParams.get('fdip') || rq.headers.get('fdip');
                const p = rq.headers.get('sec-websocket-protocol');
                const rsp = await f8(rq, fv);
                if (p && rsp.status === 101) rsp.headers.set('Sec-WebSocket-Protocol', p);
                return rsp;
            }

            return new Response('Not Found', { status: 404 });
        } catch (err) { return new Response('Error', { status: 500 }); }
    },
};

async function f8(rq, cv) {
    const wp = new WebSocketPair();
    const [c, s] = Object.values(wp);
    s.accept();
    let rw = { sk: null };
    let dq = false;
    let tu = null;

    const ed = rq.headers.get('sec-websocket-protocol') || '';
    const rd = f12(s, ed);
    const tc = f44(cv);
    const sc = f39(cv);
    const hc = f15(cv);

    rd.pipeTo(new WritableStream({
        async write(ck) {
            const uk = ck instanceof Uint8Array ? ck : new Uint8Array(ck);
            if (tu) return tu.processXUDP(uk);
            if (dq) return await f14(uk, s, null);
            if (rw.sk) {
                const wt = rw.sk.writable.getWriter();
                await wt.write(uk);
                wt.releaseLock();
                return;
            }

            const { he, m, at, p, h, ri, v, iu } = f11(uk, v2);
            if (he) throw new Error(m);

            const rh = new Uint8Array([v[0], 0]);
            const rwd = uk.subarray(ri);
            
            if (iu) {
                if (tc) {
                    s.send(rh);
                    tu = await f51(tc, d => { if (s.readyState === WebSocket.OPEN) s.send(d); });
                    if (!tu) { f3(s); return; }
                    if (rwd.byteLength) tu.processXUDP(rwd);
                    return;
                } else if (sc || hc) {
                    throw new Error('UDP ✘');
                } else {
                    if (p === 53) dq = true; else throw new Error('UDP ✘');
                }
            }

            if (tc) {
                const ip = await f31(h) || h;
                const ts = await f50(tc, ip, p);
                if (!ts) { f3(s); return; }
                rw.sk = ts;
                const wt = ts.writable.getWriter();
                if (rwd.byteLength) await wt.write(rwd);
                wt.releaseLock();
                f13(ts, s, rh, null);
                return;
            }

            if (sc) {
                const ipP = f31(h).then(res => res || h);
                const ss = await f42(sc, ipP, p);
                if (!ss) { f3(s); return; }
                rw.sk = ss;
                const wt = ss.writable.getWriter();
                if (rwd.byteLength) await wt.write(rwd);
                wt.releaseLock();
                f13(ss, s, rh, null);
                return;
            }

            if (hc) {
                const ps = await f16(h, p, hc);
                if (!ps) { f3(s); return; }
                rw.sk = ps;
                const wt = ps.writable.getWriter();
                if (rwd.byteLength) await wt.write(rwd);
                wt.releaseLock();
                f13(ps, s, rh, null);
                return;
            }

            if (dq) return f14(rwd, s, rh);
            await f10(at, h, p, rwd, s, rh, rw, cv);
        },
    })).catch(() => {});

    return new Response(null, { status: 101, webSocket: c });
}

async function f10(at, h, pn, rwd, ws, rh, rw, cv) {
    const cd = async (a, p, d) => {
        const rs = connect({ hostname: a, port: p });
        const wt = rs.writable.getWriter();
        await wt.write(d);
        wt.releaseLock();
        return rs;
    };

    let c1 = cv || v1;
    let pc = c1 ? f4(c1) : null;
    if (!pc) pc = { t: 'direct', h: v1, p: 443 };

    if (pc.t === 'direct' && c1) {
        try {
            const rl = await f7(c1, h, v2);
            if (rl?.length > 0) [pc.h, pc.p] = rl[0];
        } catch (e) {}
    }

    const cp = async () => {
        let ns = await cd(pc.h, pc.p, rwd);
        rw.sk = ns;
        f13(ns, ws, rh, null);
    };

    try {
        const is = await cd(h, pn, rwd);
        rw.sk = is;
        f13(is, ws, rh, cp);
    } catch (e) { await cp(); }
}

function f11(ck, tk) {
    if (ck.byteLength < 24) return { he: true, m: 'invalid' };
    const v = ck.subarray(0, 1);
    if (f1(ck, 1) !== tk) return { he: true, m: 'invalid' };
    
    const ol = ck[17];
    const c = ck[18 + ol];
    if (c !== 1 && c !== 2) return { he: true, m: 'invalid' };
    
    const pi = 19 + ol;
    const p = (ck[pi] << 8) | ck[pi + 1];
    let ai = pi + 3, al = 0, hn = '';
    const at = ck[pi + 2];

    switch (at) {
        case 1: al = 4; hn = ck.subarray(ai, ai + al).join('.'); break;
        case 2: al = ck[ai]; ai += 1; hn = v5.decode(ck.subarray(ai, ai + al)); break;
        case 3: al = 16; hn = Array.from({ length: 8 }, (_, i) => ((ck[ai + i * 2] << 8) | ck[ai + i * 2 + 1]).toString(16)).join(':'); break;
        default: return { he: true, m: 'invalid' };
    }
    
    if (!hn) return { he: true, m: 'invalid' };
    return { he: false, at, p, h: hn, iu: c === 2, ri: ai + al, v };
}

function f12(sk, edh) {
    let c = false;
    return new ReadableStream({
        start(co) {
            sk.addEventListener('message', e => { if (!c) co.enqueue(e.data); });
            sk.addEventListener('close', () => { if (!c) { co.close(); } });
            sk.addEventListener('error', err => co.error(err));
            
            const { d, e } = f2(edh);
            if (e) co.error(e);
            else if (d) co.enqueue(new Uint8Array(d));
        },
        cancel() { c = true; f3(sk); }
    });
}

async function f13(rs, ws, hd, rf) {
    let h = hd, hdf = false;
    try {
        await rs.readable.pipeTo(new WritableStream({
            async write(ck) {
                hdf = true;
                if (ws.readyState !== WebSocket.OPEN) throw new Error('ws_closed');
                const uk = ck instanceof Uint8Array ? ck : new Uint8Array(ck);
                if (h) {
                    const r = new Uint8Array(h.length + uk.byteLength);
                    r.set(h, 0); r.set(uk, h.length);
                    ws.send(r); h = null;
                } else {
                    ws.send(uk);
                }
            }
        }));
    } catch (e) {}
    
    if (!hdf && rf) {
        await rf();
    } else {
        f3(ws);
    }
}

async function f14(uc, ws, rh) {
    try {
        const ts = connect({ hostname: '8.8.4.4', port: 53 });
        let vh = rh;
        const wt = ts.writable.getWriter();
        await wt.write(uc);
        wt.releaseLock();
        
        await ts.readable.pipeTo(new WritableStream({
            async write(ck) {
                if (ws.readyState === WebSocket.OPEN) {
                    const uk = ck instanceof Uint8Array ? ck : new Uint8Array(ck);
                    if (vh) {
                        const r = new Uint8Array(vh.length + uk.byteLength);
                        r.set(vh, 0); r.set(uk, vh.length);
                        ws.send(r); vh = null;
                    } else {
                        ws.send(uk);
                    }
                }
            },
        }));
    } catch (e) {}
}

const f17 = (b, o = 0) => (b[o] << 8) | b[o + 1], f18 = n => -n & 3;
const v14 = new Uint8Array([0x21, 0x12, 0xA4, 0x42]);
const v15 = { AQ: 0x003, AO: 0x103, AE: 0x113, PQ: 0x008, PO: 0x108, CQ: 0x00A, CO: 0x10A, BQ: 0x00B, BO: 0x10B, SI: 0x016, DI: 0x017 };
const v16 = { USER: 0x006, MI: 0x008, ERR: 0x009, PEER: 0x012, DATA: 0x013, REALM: 0x014, NONCE: 0x015, TRANSPORT: 0x019, CONNID: 0x02A };
const f19 = (...a) => {
    let s = 0; for (let i = 0; i < a.length; i++) s += a[i].length;
    const r = new Uint8Array(s);
    let o = 0; for (let i = 0; i < a.length; i++) { r.set(a[i], o); o += a[i].length; }
    return r;
};
const f20 = (...a) => a.forEach(x => { try { x?.close?.(); } catch {} });
const f21 = async (h, p) => { const s = connect({ hostname: h, port: p }); await s.opened; return s; };
const f22 = () => crypto.getRandomValues(new Uint8Array(12));
const f23 = (t, v) => { const b = new Uint8Array(4 + v.length + f18(v.length)), d = new DataView(b.buffer); d.setUint16(0, t); d.setUint16(2, v.length); b.set(v, 4); return b; };
const f24 = (t, id, a) => { const bd = f19(...a), h = new Uint8Array(20), d = new DataView(h.buffer); d.setUint16(0, t); d.setUint16(2, bd.length); h.set(v14, 4); h.set(id, 8); return f19(h, bd); };
const f25 = (ip, port) => { const b = new Uint8Array(8); b[1] = 1; new DataView(b.buffer).setUint16(2, port ^ 0x2112); ip.split('.').forEach((v, i) => b[4 + i] = +v ^ v14[i]); return b; };
const f26 = d => {
  if (d.length < 20 || v14.some((v, i) => d[4 + i] !== v)) return null;
  const dv = new DataView(d.buffer, d.byteOffset, d.byteLength), ml = dv.getUint16(2), attrs = {};
  for (let o = 20; o + 4 <= 20 + ml; ) { const t = dv.getUint16(o), l = dv.getUint16(o + 2); if (o + 4 + l > d.length) break; attrs[t] = d.slice(o + 4, o + 4 + l); o += 4 + l + f18(l); }
  return { type: dv.getUint16(0), attrs };
};
const f27 = d => d?.length >= 4 ? (d[2] & 7) * 100 + d[3] : 0;
const f28 = d => d?.length >= 8 ? [v14.map((m, i) => d[4 + i] ^ m).join('.'), f17(d, 2) ^ 0x2112] : ['', 0];
const f29 = async (m, key) => { const c = new Uint8Array(m), d = new DataView(c.buffer); d.setUint16(2, d.getUint16(2) + 24); const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']); return f19(c, f23(v16.MI, new Uint8Array(await crypto.subtle.sign('HMAC', k, c)))); };
const f30 = async (rd, buf) => {
  let b = buf ?? new Uint8Array(0); const pull = async () => { const { done, value } = await rd.read(); if (done) throw 0; b = f19(b, new Uint8Array(value)); };
  try { while (b.length < 20) await pull(); const n = 20 + f17(b, 2); while (b.length < n) await pull();
    return [f26(b.subarray(0, n)), b.length > n ? b.subarray(n) : null]; } catch { return [null, null]; }
};
const f31 = async h => /^\d+\.\d+\.\d+\.\d+$/.test(h) ? h : (await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(h)}&type=A`, { headers: { Accept: 'application/dns-json' }, cf: { cacheTtl: 3600, cacheEverything: true } }).then(r => r.json()).catch(() => ({}))).Answer?.find(a => a.type === 1)?.data ?? null;
const f32 = async s => new Uint8Array(await crypto.subtle.digest('MD5', v6(s)));

const v17 = new Uint8Array(0);
const v18 = 1400;
const f33 = (b, o) => (b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]) >>> 0;
const f34 = n => crypto.getRandomValues(new Uint8Array(n));
const f35 = () => { const r = f34(2); return f17(r, 0); };
const f36 = () => { const r = f34(4); return f33(r, 0); };
const f37 = ip => new Uint8Array(ip.split('.').map(Number));
const v19 = v6(atob('dnBu'));
const f38 = (d, o, n) => { let s = 0; for (let i = o; i < o + n - 1; i += 2) s += f17(d, i); if (n & 1) s += d[o + n - 1] << 8; while (s >> 16) s = (s & 0xFFFF) + (s >> 16); return (~s) & 0xFFFF; };

const f39 = url => {
    if (!url) return null;
    const m = decodeURIComponent(url).match(v12);
    if (!m) return null;
    const t = m[1], [host, p] = t.split(':');
    return p ? { host, port: +p } : null;
};

const f40 = () => {
    let buf = v17, pId = 1, sk, rd, wr, ht, rb = new ArrayBuffer(65536);
    const readB = async n => {
      if (buf.length >= n) { const r = buf.subarray(0, n); buf = buf.subarray(n); return r; }
      const sv = buf.length > 0 ? new Uint8Array(buf) : null, nd = n - buf.length;
      const { value, done } = await rd.readAtLeast(nd, new Uint8Array(rb, 0, 65536));
      if (done) throw 0; rb = value.buffer;
      if (sv) { const t = f19(sv, value); buf = t.subarray(n); return t.subarray(0, n); }
      buf = value.subarray(n); return value.subarray(0, n);
    };
    const readL = async () => {
      for (;;) {
        const i = buf.indexOf(10);
        if (i >= 0) { let l = v5.decode(buf.subarray(0, i)); buf = buf.subarray(i + 1); return l.replace(/\r$/, ''); }
        const sv = buf.length > 0 ? new Uint8Array(buf) : null;
        const { value, done } = await rd.readAtLeast(1, new Uint8Array(rb, 0, 65536));
        if (done) throw 0; rb = value.buffer; buf = sv ? f19(sv, value) : value;
      }
    };
    const readP = async (ms = 10000) => {
      let t; const to = new Promise((_, r) => { t = setTimeout(() => r('T'), ms); });
      try { const h = await Promise.race([readB(4), to]); clearTimeout(t); const len = f17(h, 2) & 0xFFF;
        return { ctrl: (h[1] & 1) !== 0, body: len > 4 ? await readB(len - 4) : v17 }; } catch (e) { clearTimeout(t); throw e; }
    };
    const sdData = f => { const n = 6 + f.length, p = new Uint8Array(n); p.set([0x10, 0, ((n >> 8) & 0xF) | 0x80, n & 0xFF, 0xFF, 0x03]); p.set(f, 6); return p; };
    const sdCtrl = (mt, attrs = []) => {
      const al = attrs.reduce((s, a) => s + 4 + a.data.length, 0), p = new Uint8Array(8 + al), v = new DataView(p.buffer);
      p[0] = 0x10; p[1] = 0x01; v.setUint16(2, (8 + al) | 0x8000); v.setUint16(4, mt); v.setUint16(6, attrs.length);
      attrs.reduce((o, a) => (p[o + 1] = a.id, v.setUint16(o + 2, 4 + a.data.length), p.set(a.data, o + 4), o + 4 + a.data.length), 8);
      return p;
    };
    const mkPpp = (pt, c, id, opts = []) => {
      const ol = opts.reduce((s, o) => s + 2 + o.data.length, 0), f = new Uint8Array(6 + ol), v = new DataView(f.buffer);
      v.setUint16(0, pt); f[2] = c; f[3] = id; v.setUint16(4, 4 + ol);
      opts.reduce((o, x) => (f[o] = x.type, f[o + 1] = 2 + x.data.length, f.set(x.data, o + 2), o + 2 + x.data.length), 6);
      return f;
    };
    const mkPap = id => { const ul = v19.length, tl = 6 + ul * 2, f = new Uint8Array(2 + tl), v = new DataView(f.buffer);
      v.setUint16(0, 0xc023); f[2] = 1; f[3] = id; v.setUint16(4, tl); f[6] = ul; f.set(v19, 7); f[7 + ul] = ul; f.set(v19, 8 + ul); return f; };
    const pPpp = d => { let o = d.length >= 2 && d[0] === 0xFF && d[1] === 0x03 ? 2 : 0; if (d.length - o < 4) return null;
      const p = f17(d, o); return p === 0x0021 ? { protocol: p, ip: d.subarray(o + 2) } : d.length - o >= 6 ? { protocol: p, code: d[o + 2], id: d[o + 3], payload: d.subarray(o + 6), raw: d.subarray(o) } : null; };
    const pOpts = d => { const r = []; for (let i = 0; i + 2 <= d.length;) { const t = d[i], l = d[i + 1]; if (l < 2 || i + l > d.length) break; r.push({ type: t, data: d.subarray(i + 2, i + l) }); i += l; } return r; };
    const conn_ = async (h, p) => { sk = connect({ hostname: h, port: p }, { secureTransport: 'on' }); await sk.opened;
      rd = sk.readable.getReader({ mode: 'byob' }); wr = sk.writable.getWriter(); ht = h; };
    const est = async () => {
      const h = v6(`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\nHost: ${ht}\r\nContent-Length: 18446744073709551615\r\nSSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`);
      const pa = new Uint8Array(2); new DataView(pa.buffer).setUint16(0, 1); const mru = new Uint8Array(2); new DataView(mru.buffer).setUint16(0, 1500);
      await wr.write(f19(h, sdCtrl(0x0001, [{ id: 1, data: pa }]), sdData(mkPpp(0xc021, 1, pId++, [{ type: 1, data: mru }]))));
      const st = await readL(); while ((await readL()) !== ''); if (!st.includes('200')) throw 0;
      let sa = false, ld = false, auth = false, dn = false, mi = null;
      for (let r = 0; r < 25 && !dn; r++) {
        const pk = await readP(); if (pk.ctrl) { if (!sa && pk.body.length >= 2 && f17(pk.body, 0) === 2) sa = true; continue; }
        const pp = pPpp(pk.body); if (!pp) continue;
        if (pp.protocol === 0xc021) {
          if (pp.code === 1) { const a = new Uint8Array(pp.raw); a[2] = 2;
            await wr.write(ld && !auth ? f19(sdData(a), sdData(mkPap(pId++))) : sdData(a)); if (ld) auth = true;
          } else if (pp.code === 2) { ld = true; if (!auth) { await wr.write(sdData(mkPap(pId++))); auth = true; } }
        } else if (pp.protocol === 0xc023 && pp.code === 2) await wr.write(sdData(mkPpp(0x8021, 1, pId++, [{ type: 3, data: new Uint8Array(4) }])));
        else if (pp.protocol === 0x8021) {
          if (pp.code === 1) { const a = new Uint8Array(pp.raw); a[2] = 2; await wr.write(sdData(a)); }
          else if (pp.code === 3) { const o = pOpts(pp.payload).find(x => x.type === 3); if (o) { mi = [...o.data].join('.'); await wr.write(sdData(mkPpp(0x8021, 1, pId++, [{ type: 3, data: o.data }]))); } }
          else if (pp.code === 2) { const o = pOpts(pp.payload).find(x => x.type === 3); if (o) mi = [...o.data].join('.'); dn = true; }
        }
      }
      if (!mi) throw 0; return mi;
    };
    const cls = () => { [rd, wr, sk].forEach(x => { try { x?.cancel?.() ?? x?.close?.(); } catch {} }); };
    return { connect: conn_, establish: est, readPkt: readP, parsePPP: pPpp, get buf() { return buf; }, get wr() { return wr; }, close: cls };
  };

  const f41 = (sstp, srcIp, dstIp, dstPort) => {
    const sPt = 10000 + (f35() % 50000), sB = f37(srcIp), dB = f37(dstIp);
    let sq = f36(), ak = 0;
    const ipT = new Uint8Array(20); ipT.set([0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6]); ipT.set(sB, 12); ipT.set(dB, 16);
    const ps = new Uint8Array(1432); ps.set(sB); ps.set(dB, 4); ps[9] = 6;
    const fr = (fl, d = v17) => {
      const pl = d.length, tl = 20 + pl, il = 20 + tl, st = 8 + il, f = new Uint8Array(st), v = new DataView(f.buffer);
      f.set([0x10, 0, ((st >> 8) & 0xF) | 0x80, st & 0xFF, 0xFF, 0x03, 0, 0x21]); f.set(ipT, 8);
      v.setUint16(10, il); v.setUint16(12, f35()); v.setUint16(18, f38(f, 8, 20));
      v.setUint16(28, sPt); v.setUint16(30, dstPort); v.setUint32(32, sq); v.setUint32(36, ak);
      f[40] = 0x50; f[41] = fl; v.setUint16(42, 65535); if (pl) f.set(d, 48);
      ps[10] = tl >> 8; ps[11] = tl & 0xFF; ps.set(f.subarray(28, 28 + tl), 12);
      v.setUint16(44, f38(ps, 0, 12 + tl)); return f;
    };
    const mh = ip => { if (ip.length < 40 || ip[9] !== 6) return null; const ihl = (ip[0] & 0xF) * 4;
      if (f17(ip, ihl) !== dstPort || f17(ip, ihl + 2) !== sPt) return null;
      return { flags: ip[ihl + 13], seq: f33(ip, ihl + 4), off: ihl + ((ip[ihl + 12] >> 4) & 0xF) * 4 }; };
    const hs = async () => {
      await sstp.wr.write(fr(0x02)); sq++;
      for (let i = 0; i < 30; i++) { const pk = await sstp.readPkt(); if (pk.ctrl) continue;
        const pp = sstp.parsePPP(pk.body); if (!pp || pp.protocol !== 0x0021) continue;
        const m = mh(pp.ip); if (!m || (m.flags & 0x12) !== 0x12) continue;
        ak = (m.seq + 1) >>> 0; sstp.wr.write(fr(0x10)); return true; }
      throw 0;
    };
    return { frame: fr, match: mh, handshake: hs, get seq() { return sq; }, set seq(v) { sq = v; }, get ack() { return ak; }, set ack(v) { ak = v; } };
  };

  const f42 = async ({ host, port }, ipP, targetPort) => {
    const st = f40(), cls = () => st.close();
    try {
      await st.connect(host, port);
      const [mI, tI] = await Promise.all([st.establish(), ipP]); if (!tI) { cls(); return null; }
      const tc = f41(st, mI, tI, targetPort); await tc.handshake();
      let cr = null;
      const rd = new ReadableStream({ start: c => { cr = c; }, cancel: cls });
      (async () => {
        try { let pd = [], pL = 0;
          const fl = () => { if (!pL) return; cr.enqueue(pd.length === 1 ? pd[0] : f19(...pd)); pd = []; pL = 0; st.wr.write(tc.frame(0x10)).catch(() => {}); };
          for (;;) { const pk = await st.readPkt(60000); if (pk.ctrl) continue;
            const pp = st.parsePPP(pk.body); if (!pp || pp.protocol !== 0x0021) continue;
            const m = tc.match(pp.ip); if (!m) continue;
            if (m.off < pp.ip.length) { const d = pp.ip.subarray(m.off); if (d.length) { tc.ack = (m.seq + d.length) >>> 0; pd.push(new Uint8Array(d)); pL += d.length; } }
            if (m.flags & 0x01) { fl(); tc.ack = (tc.ack + 1) >>> 0; st.wr.write(tc.frame(0x11)).catch(() => {}); cr.close(); return; }
            if (st.buf.length < 4 || pL >= 32768) fl();
          }
        } catch { try { cr.close(); } catch {} }
      })();
      const wr = new WritableStream({
        async write(ck) { const d = ck instanceof Uint8Array ? ck : new Uint8Array(ck);
          if (d.length <= v18) { await st.wr.write(tc.frame(0x18, d)); tc.seq = (tc.seq + d.length) >>> 0; return; }
          const fs = []; for (let o = 0; o < d.length; o += v18) { const sg = d.subarray(o, Math.min(o + v18, d.length)); fs.push(tc.frame(0x18, sg)); tc.seq = (tc.seq + sg.length) >>> 0; }
          await st.wr.write(f19(...fs));
        }, close: () => st.wr.write(tc.frame(0x11)).catch(() => {}), abort: cls
      });
      return { readable: rd, writable: wr, close: cls };
    } catch { cls(); return null; }
  };

const f43 = async (w, r, tp, { u, p }, pl) => {
  const tm = new Uint8Array([tp, 0, 0, 0]);
  await w.write(f24(v15.AQ, f22(), [f23(v16.TRANSPORT, tm)]));
  let [m, x] = await f30(r); if (!m) return null;
  let k = null, aa = [];
  const sign = ms => k ? f29(ms, k) : Promise.resolve(ms);
  if (m.type === v15.AE && u && f27(m.attrs[v16.ERR]) === 401) {
    const rl = v5.decode(m.attrs[v16.REALM] ?? v17), nn = m.attrs[v16.NONCE] ?? v17;
    k = await f32(`${u}:${rl}:${p}`);
    aa = [f23(v16.USER, v6(u)), f23(v16.REALM, v6(rl)), f23(v16.NONCE, nn)];
    const aq = await f29(f24(v15.AQ, f22(), [f23(v16.TRANSPORT, tm), ...aa]), k);
    const ex = pl ? await Promise.all(pl(aa, sign)) : [];
    await w.write(ex.length ? f19(aq, ...ex) : aq);
    [m, x] = await f30(r, x); if (!m) return null;
  } else if (pl && m.type === v15.AO) {
    const ex = await Promise.all(pl(aa, sign));
    if (ex.length) await w.write(f19(...ex));
  }
  return m.type === v15.AO ? { k, aa, ex: x, sign } : null;
};

const f44 = url => {
  if (!url) return null;
  const m = decodeURIComponent(url).match(v13);
  if (!m) return null;
  const t = m[1], at = t.lastIndexOf('@'), cr = at >= 0 ? t.slice(0, at) : '', hp = t.slice(at + 1), [h, p] = hp.split(':'), ci = cr.indexOf(':');
  return p ? { host: h, port: +p, u: ci >= 0 ? cr.slice(0, ci) : '', p: ci >= 0 ? cr.slice(ci + 1) : '' } : null;
};

const f45 = h => {
  const s = h.replace(/^\[|\]$/g, ''), m = s.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) return new Uint8Array([0x01, ...m.slice(1).map(Number)]);
  if (s.includes(':')) { const b = new Uint8Array(17); b[0] = 0x03; s.split(':').forEach((x, i) => { const v = parseInt(x, 16) || 0; b[1 + i * 2] = v >> 8; b[2 + i * 2] = v & 0xff; }); return b; }
  const e = v6(h); return f19(new Uint8Array([0x02, e.length]), e);
};

const f46 = d => {
  if (!d.length) return ['', 0];
  if (d[0] <= 1) return d.length >= 5 ? [d.subarray(1, 5).join('.'), 5] : ['', 0];
  if (d[0] === 2) return d.length >= 2 + d[1] ? [v5.decode(d.subarray(2, 2 + d[1])), 2 + d[1]] : ['', 0];
  return d[0] === 3 && d.length >= 17 ? [`[${Array.from({ length: 8 }, (_, i) => f17(d, 1 + i * 2).toString(16)).join(':')}]`, 17] : ['', 0];
};

const f47 = h => { const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/); return m && +m[1] === 198 && [18, 19].includes(+m[2]) ? 4 : h.replace(/^\[|\]$/g, '').startsWith('fc') && h.includes(':') ? 6 : 0; };

const f48 = d => {
  if (d.length < 6) return null;
  const ml = f17(d), me = 2 + ml;
  if (ml < 4 || me > d.length) return null;
  const f = { nw: me > 6 ? d[6] : 0, pt: me >= 9 ? f17(d, 7) : 0, ht: me > 9 ? f46(d.subarray(9, me))[0] : '', pl: null, tl: me };
  if ((d[5] & 1) && me + 2 <= d.length) { const pL = f17(d, me); if (me + 2 + pL <= d.length) { f.pl = d.subarray(me + 2, me + 2 + pL); f.tl = me + 2 + pL; } }
  return f;
};

const f49 = (h, p, pl) => { const a = f45(h), ml = 7 + a.length, bf = new Uint8Array(2 + ml + 2 + pl.length); [bf[0], bf[1], bf[4], bf[5], bf[6], bf[7], bf[8]] = [ml >> 8, ml & 0xff, 2, 1, 2, p >> 8, p & 0xff]; bf.set(a, 9); const po = 2 + ml; [bf[po], bf[po + 1]] = [pl.length >> 8, pl.length & 0xff]; bf.set(pl, po + 2); return bf; };

const f50 = async ({ host, port, u, p }, tI, tP) => {
  let ct = null, dt = null;
  const cls = () => f20(ct, dt);
  try {
    ct = await f21(host, port);
    const cw = ct.writable.getWriter(), cr = ct.readable.getReader();
    const pr = f23(v16.PEER, f25(tI, tP));
    const au = await f43(cw, cr, 6, { u, p }, (aa, sn) => [sn(f24(v15.PQ, f22(), [pr, ...aa])), sn(f24(v15.CQ, f22(), [pr, ...aa]))]);
    if (!au) { cls(); return null; }
    const { aa, sign: sn } = au; let ex = au.ex;
    dt = connect({ hostname: host, port });
    let r; [r, ex] = await f30(cr, ex); if (r?.type !== v15.PO) { cls(); return null; }
    [r, ex] = await f30(cr, ex); if (r?.type !== v15.CO || !r.attrs[v16.CONNID]) { cls(); return null; }
    await dt.opened; const dw = dt.writable.getWriter(), dr = dt.readable.getReader();
    await dw.write(await sn(f24(v15.BQ, f22(), [f23(v16.CONNID, r.attrs[v16.CONNID]), ...aa])));
    let xr; [r, xr] = await f30(dr); if (r?.type !== v15.BO) { cls(); return null; }
    cr.releaseLock(); cw.releaseLock(); dw.releaseLock();
    const rd = new ReadableStream({ start: c => xr?.length && c.enqueue(xr), pull: c => dr.read().then(({ done, value }) => done ? c.close() : c.enqueue(new Uint8Array(value))), cancel: () => dr.cancel() });
    return { readable: rd, writable: dt.writable, close: cls };
  } catch { cls(); return null; }
};

const f51 = async ({ host, port, u, p }, sw) => {
  let sk = null, cd = false;
  const pm = new Set(), sm = new Map(), rv = {};
  const cls = () => { cd = true; f20(sk); };
  try {
    sk = await f21(host, port);
    const w = sk.writable.getWriter(), r = sk.readable.getReader();
    const au = await f43(w, r, 17, { u, p }); if (!au) { cls(); return null; }
    const { aa, sign: sn } = au; let bf = au.ex;
    (async () => { while (!cd) { const [m, nx] = await f30(r, bf); bf = nx; if (!m) break; if (m.type === v15.DI && m.attrs[v16.PEER] && m.attrs[v16.DATA]) { const [ip, pt] = f28(m.attrs[v16.PEER]), s = rv[`${ip}:${pt}`]; sw(f49(s?.host ?? ip, s?.port ?? pt, m.attrs[v16.DATA])); } } })();
    const ep = ip => { if (pm.has(ip)) return; pm.add(ip); sn(f24(v15.PQ, f22(), [f23(v16.PEER, f25(ip, 0)), ...aa])).then(m => w.write(m)); };
    const su = (ip, pt, d) => w.write(f24(v15.SI, f22(), [f23(v16.PEER, f25(ip, pt)), f23(v16.DATA, d)]));
    const gi = (h, pt) => {
      const k = `${h}:${pt}`, c = sm.get(k); if (c) return c.ip;
      const ft = f47(h); if (ft) for (const s of sm.values()) if (s.port === pt && s.isV6 === (ft === 6)) { const ns = { ip: s.ip, host: h, port: pt, isV6: s.isV6 }; sm.set(k, ns); rv[`${s.ip}:${pt}`] = ns; return s.ip; }
      return null;
    };
    const ra = async (h, pt, k) => { const ip = await f31(h); if (ip) { const s = { ip, host: h, port: pt, isV6: ip.includes(':') }; sm.set(k, s); rv[`${ip}:${pt}`] = s; } };
    const px = d => { while (d.length >= 6) { const f = f48(d); if (!f) break; if (f.nw === 2 && f.pl?.length && f.ht) { const k = `${f.ht}:${f.pt}`, ip = gi(f.ht, f.pt); ip ? (ep(ip), su(ip, f.pt, f.pl)) : sm.has(k) || ra(f.ht, f.pt, k); } d = d.subarray(f.tl); } };
    return { processXUDP: px, close: cls };
  } catch { cls(); return null; }
};
