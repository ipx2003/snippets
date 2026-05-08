import { connect as c0 } from 'cloudflare:sockets';

let v1 = 'proxyip.example.com!txt';
let v2 = '495c7195-85b8-498a-bf20-2ea9ce9175b5';

let v3 = null;
let v4 = null;

const r1 = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const r2 = /^\[?([a-fA-F0-9:]+)\]?$/;
const e1 = new Uint8Array(0);
const d1 = new TextDecoder();
const tc = new TextEncoder();

const lut = [];
for (let i = 0; i < 256; i++) lut[i] = (i < 16 ? '0' : '') + i.toString(16);

const e2 = s => tc.encode(s);

const f1 = (...args) => { 
    let len = 0; 
    for (let i = 0; i < args.length; i++) len += args[i].length;
    const r = new Uint8Array(len); 
    let offset = 0; 
    for (let i = 0; i < args.length; i++) { r.set(args[i], offset); offset += args[i].length; }
    return r; 
};

const f2 = (b, o) => b[o] << 8 | b[o + 1];
const f3 = (b, o) => (b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]) >>> 0;
const f4 = n => crypto.getRandomValues(new Uint8Array(n));
const f5 = () => f2(f4(2), 0);
const f6 = () => f3(f4(4), 0);
const f7 = ip => new Uint8Array(ip.split('.').map(Number));
const f8 = (d, o, n) => { let s = 0; for (let i = o; i < o + n - 1; i += 2) s += f2(d, i); if (n & 1) s += d[o + n - 1] << 8; while (s >> 16) s = (s & 0xFFFF) + (s >> 16); return (~s) & 0xFFFF; };
const m1 = 1400;
const m2 = new Uint8Array([0x21, 0x12, 0xA4, 0x42]);

const f28 = n => -n & 3;
const f29 = (t, v) => { const b = new Uint8Array(4 + v.length + f28(v.length)), d = new DataView(b.buffer); d.setUint16(0, t); d.setUint16(2, v.length); b.set(v, 4); return b; };
const f30 = (t, id, a) => { const bd = f1(...a), h = new Uint8Array(20), d = new DataView(h.buffer); d.setUint16(0, t); d.setUint16(2, bd.length); h.set(m2, 4); h.set(id, 8); return f1(h, bd); };
const f31 = (ip, pt) => { const b = new Uint8Array(8); b[1] = 1; new DataView(b.buffer).setUint16(2, pt ^ 0x2112); ip.split('.').forEach((v, i) => b[4 + i] = +v ^ m2[i]); return b; };
const f32 = d => {
    if (d.length < 20 || m2.some((v, i) => d[4 + i] !== v)) return null;
    const dv = new DataView(d.buffer, d.byteOffset, d.byteLength), ml = dv.getUint16(2), a = {};
    for (let o = 20; o + 4 <= 20 + ml; ) { const t = dv.getUint16(o), l = dv.getUint16(o + 2); if (o + 4 + l > d.length) break; a[t] = d.subarray(o + 4, o + 4 + l); o += 4 + l + f28(l); }
    return { t: dv.getUint16(0), a };
};
const f33 = d => d?.length >= 4 ? (d[2] & 7) * 100 + d[3] : 0;
const f34 = d => d?.length >= 8 ? [m2.map((m, i) => d[4 + i] ^ m).join('.'), f2(d, 2) ^ 0x2112] : ['', 0];
const f35 = async (m, k) => { const c = new Uint8Array(m), d = new DataView(c.buffer); d.setUint16(2, d.getUint16(2) + 24); const ky = await crypto.subtle.importKey('raw', k, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']); return f1(c, f29(0x008, new Uint8Array(await crypto.subtle.sign('HMAC', ky, c)))); };
const f36 = async (rd, bf) => {
    let b = bf ?? e1; const pl = async () => { const { done: d, value: v } = await rd.read(); if (d) throw 0; b = f1(b, new Uint8Array(v)); };
    try { while (b.length < 20) await pl(); const n = 20 + f2(b, 2); while (b.length < n) await pl();
        return [f32(b.subarray(0, n)), b.length > n ? b.subarray(n) : null]; } catch { return [null, null]; }
};
const f37 = async s => new Uint8Array(await crypto.subtle.digest('MD5', e2(s)));

const f38 = async (wt, rd, tp, { u, w: p }, pl) => {
    const tb = new Uint8Array([tp, 0, 0, 0]);
    await wt.write(f30(0x003, f4(12), [f29(0x019, tb)]));
    let [m, ex] = await f36(rd); if (!m) return null;
    let k = null, aa = [];
    const sg = mg => k ? f35(mg, k) : Promise.resolve(mg);
    if (m.t === 0x113 && u && f33(m.a[0x009]) === 401) {
        const rl = d1.decode(m.a[0x014] ?? e1), nc = m.a[0x015] ?? e1;
        k = await f37(`${u}:${rl}:${p}`);
        aa = [f29(0x006, e2(u)), f29(0x014, e2(rl)), f29(0x015, nc)];
        const aq = await f35(f30(0x003, f4(12), [f29(0x019, tb), ...aa]), k);
        const xt = pl ? await Promise.all(pl(aa, sg)) : [];
        await wt.write(xt.length ? f1(aq, ...xt) : aq);
        [m, ex] = await f36(rd, ex); if (!m) return null;
    } else if (pl && m.t === 0x103) {
        const xt = await Promise.all(pl(aa, sg));
        if (xt.length) await wt.write(f1(...xt));
    }
    return m.t === 0x103 ? { k, aa, ex, sg } : null;
};

const f41 = h => {
    const s = h.replace(/^\[|\]$/g, ''), m = s.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (m) return new Uint8Array([0x01, ...m.slice(1).map(Number)]);
    if (s.includes(':')) { const b = new Uint8Array(17); b[0] = 0x03; s.split(':').forEach((x, i) => { const v = parseInt(x, 16) || 0; b[1 + i * 2] = v >> 8; b[2 + i * 2] = v & 0xff; }); return b; }
    const e = e2(h); return f1(new Uint8Array([0x02, e.length]), e);
};
const f42 = d => {
    if (!d.length) return ['', 0];
    if (d[0] <= 1) return d.length >= 5 ? [d.subarray(1, 5).join('.'), 5] : ['', 0];
    if (d[0] === 2) return d.length >= 2 + d[1] ? [d1.decode(d.subarray(2, 2 + d[1])), 2 + d[1]] : ['', 0];
    return d[0] === 3 && d.length >= 17 ? [`[${Array.from({ length: 8 }, (_, i) => f2(d, 1 + i * 2).toString(16)).join(':')}]`, 17] : ['', 0];
};
const f43 = h => { const m = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/); return m && +m[1] === 198 && [18, 19].includes(+m[2]) ? 4 : h.replace(/^\[|\]$/g, '').startsWith('fc') && h.includes(':') ? 6 : 0; };
const f44 = d => {
    if (d.length < 6) return null; const ml = f2(d, 0), me = 2 + ml; if (ml < 4 || me > d.length) return null;
    const f = { n: me > 6 ? d[6] : 0, p: me >= 9 ? f2(d, 7) : 0, h: me > 9 ? f42(d.subarray(9, me))[0] : '', pl: null, tl: me };
    if ((d[5] & 1) && me + 2 <= d.length) { const pl = f2(d, me); if (me + 2 + pl <= d.length) { f.pl = d.subarray(me + 2, me + 2 + pl); f.tl = me + 2 + pl; } }
    return f;
};
const f45 = (h, p, pl) => { const a = f41(h), ml = 7 + a.length, b = new Uint8Array(2 + ml + 2 + pl.length); [b[0], b[1], b[4], b[5], b[6], b[7], b[8]] = [ml >> 8, ml & 0xff, 2, 1, 2, p >> 8, p & 0xff]; b.set(a, 9); const po = 2 + ml; [b[po], b[po + 1]] = [pl.length >> 8, pl.length & 0xff]; b.set(pl, po + 2); return b; };

function f9(a, o = 0) {
    return lut[a[o]] + lut[a[o+1]] + lut[a[o+2]] + lut[a[o+3]] + '-' +
           lut[a[o+4]] + lut[a[o+5]] + '-' +
           lut[a[o+6]] + lut[a[o+7]] + '-' +
           lut[a[o+8]] + lut[a[o+9]] + '-' +
           lut[a[o+10]] + lut[a[o+11]] + lut[a[o+12]] + lut[a[o+13]] + lut[a[o+14]] + lut[a[o+15]];
}

function f10(s) {
    if (!s) return { e: null };
    try { return { d: Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)).buffer, e: null }; } catch (e) { return { e }; }
}

function f11(s) {
    try { if (s?.readyState === 1 || s?.readyState === 2) s.close(); if (s?.close) s.close(); } catch (e) {}
}

function f12(s) {
    if (!s) return null;
    s = s.trim();
    if (s.startsWith('sstp://')) { try { const u = new URL(s); return { t: 'sstp', h: u.hostname, p: parseInt(u.port) || 443, u: u.username ? decodeURIComponent(u.username) : 'vpn', w: u.password ? decodeURIComponent(u.password) : 'vpn' }; } catch (e) { return null; } }
    if (s.startsWith('socks://') || s.startsWith('socks5://')) { try { const u = new URL(s.replace(/^socks:\/\//, 'socks5://')); return { t: 'socks5', h: u.hostname, p: parseInt(u.port) || 1080, u: u.username ? decodeURIComponent(u.username) : '', w: u.password ? decodeURIComponent(u.password) : '' }; } catch (e) { return null; } }
    if (s.startsWith('http://') || s.startsWith('https://')) { try { const b = s.startsWith('https://'); const u = new URL(s); return { t: b ? 'https' : 'http', h: u.hostname, p: parseInt(u.port) || (b ? 443 : 80), u: u.username ? decodeURIComponent(u.username) : '', w: u.password ? decodeURIComponent(u.password) : '' }; } catch (e) { return null; } }
    if (s.startsWith('turn://') || s.startsWith('turns://')) { try { const b = s.startsWith('turns://'); const u = new URL(s.replace(/^turns?:\/\//, 'http://')); return { t: b ? 'turns' : 'turn', h: u.hostname, p: parseInt(u.port) || (b ? 5349 : 3478), u: u.username ? decodeURIComponent(u.username) : '', w: u.password ? decodeURIComponent(u.password) : '' }; } catch (e) { return null; } }
    const m = s.match(/^\[([^\]]+)\](?::(\d+))?$/);
    if (m) { const p = parseInt(m[2], 10); return { t: 'direct', h: m[1], p: (!isNaN(p) && p > 0) ? p : 443 }; }
    const i = s.lastIndexOf(':');
    if (i > 0) { const h = s.substring(0, i), p = parseInt(s.substring(i + 1), 10); if (!isNaN(p) && p > 0 && p <= 65535) return { t: 'direct', h, p }; }
    return { t: 'direct', h: s, p: 443 };
}

async function f13(d, t) {
    const g = async (u) => { try { const r = await fetch(`${u}?name=${d}&type=${t}`, { headers: { 'Accept': 'application/dns-json' } }); if (r.ok) return (await r.json()).Answer || []; } catch (e) {} return null; };
    return (await g('https://1.1.1.1/dns-query')) || (await g('https://dns.google/dns-query')) || [];
}

function f14(s) {
    let a = s, p = 443; const m = s.match(/^(?:\[([^\]]+)\]|([^:]+))(?::(\d+))?$/);
    if (m) { a = m[1] || m[2]; p = m[3] ? parseInt(m[3], 10) : 443; } return [a, p];
}

async function f15(s, d = 'dash.cloudflare.com', u = '00000000-0000-4000-8000-000000000000') {
    const s1 = s.trim();
    if (v3 === s1 && v4) return v4;
    const l = s1.toLowerCase(), b = l.endsWith('!txt'), t = b ? s1.slice(0, -4).trim() : s1;
    let a = [];
    if (b) {
        const r = await f13(t, 'TXT'), d1 = r.filter(x => x.type === 16).map(x => x.data);
        if (d1.length > 0) { a = d1[0].replace(/^"|"$/g, '').replace(/\\010|\n/g, ',').split(',').map(x => x.trim()).filter(Boolean).map(f14); }
    } else {
        let [h, p] = f14(t); const m = t.match(/\.tp(\d+)/); if (m) p = parseInt(m[1], 10);
        if (!r1.test(h) && !r2.test(h)) {
            const [r4, r6] = await Promise.all([f13(h, 'A'), f13(h, 'AAAA')]);
            const i = [...(r4.filter(x => x.type === 1).map(x => x.data)), ...(r6.filter(x => x.type === 28).map(x => `[${x.data}]`))];
            a = i.length > 0 ? i.map(x => [x, p]) : [[h, p]];
        } else { a = [[h, p]]; }
    }
    const g = d.includes('.') ? d.split('.').slice(-2).join('.') : d; let n = [...(g + u)].reduce((c, x) => c + x.charCodeAt(0), 0);
    v4 = [...a.sort((x, y) => x[0].localeCompare(y[0]))].sort(() => { n = (n * 1103515245 + 12345) & 0x7fffffff; return (n / 0x7fffffff) - 0.5; }).slice(0, 8);
    v3 = s1; return v4;
}

const f16 = (u, w) => {
  let b = e1, i = 1, s, r, t, h, rb = new ArrayBuffer(65536);
  const g1 = async n => {
    if (b.length >= n) { const x = b.subarray(0, n); b = b.subarray(n); return x; }
    const o = b.length > 0 ? new Uint8Array(b) : null, m = n - b.length;
    const { value: v, done: d } = await r.readAtLeast(m, new Uint8Array(rb, 0, 65536));
    if (d) throw 0; rb = v.buffer;
    if (o) { const c = f1(o, v); b = c.subarray(n); return c.subarray(0, n); }
    b = v.subarray(n); return v.subarray(0, n);
  };
  const g2 = async () => {
    for (;;) {
      const j = b.indexOf(10); if (j >= 0) { let l = d1.decode(b.subarray(0, j)); b = b.subarray(j + 1); return l.replace(/\r$/, ''); }
      const o = b.length > 0 ? new Uint8Array(b) : null;
      const { value: v, done: d } = await r.readAtLeast(1, new Uint8Array(rb, 0, 65536));
      if (d) throw 0; rb = v.buffer; b = o ? f1(o, v) : v;
    }
  };
  const g3 = async (m = 10000) => {
    let x; const p = new Promise((_, y) => { x = setTimeout(() => y('T'), m); });
    try { const k = await Promise.race([g1(4), p]); clearTimeout(x); const l = f2(k, 2) & 0xFFF;
      return { c: (k[1] & 1) !== 0, b: l > 4 ? await g1(l - 4) : e1 }; } catch (e) { clearTimeout(x); throw e; }
  };
  const g4 = x => { const n = 6 + x.length, p = new Uint8Array(n); p.set([0x10, 0, ((n >> 8) & 0xF) | 0x80, n & 0xFF, 0xFF, 0x03]); p.set(x, 6); return p; };
  const g5 = (m, a = []) => {
    let l = 0; for(let i=0; i<a.length; i++) l += 4 + a[i].d.length;
    const p = new Uint8Array(8 + l), v = new DataView(p.buffer);
    p[0] = 0x10; p[1] = 0x01; v.setUint16(2, (8 + l) | 0x8000); v.setUint16(4, m); v.setUint16(6, a.length);
    let offset = 8;
    for(let i=0; i<a.length; i++) {
        p[offset+1] = a[i].i; v.setUint16(offset+2, 4+a[i].d.length); p.set(a[i].d, offset+4); offset += 4+a[i].d.length;
    }
    return p;
  };
  const g6 = (p, c, i, a = []) => {
    let l = 0; for(let k=0; k<a.length; k++) l += 2 + a[k].d.length;
    const k_arr = new Uint8Array(6 + l), v = new DataView(k_arr.buffer);
    v.setUint16(0, p); k_arr[2] = c; k_arr[3] = i; v.setUint16(4, 4 + l);
    let offset = 6;
    for(let k=0; k<a.length; k++) {
        k_arr[offset] = a[k].t; k_arr[offset+1] = 2+a[k].d.length; k_arr.set(a[k].d, offset+2); offset += 2+a[k].d.length;
    }
    return k_arr;
  };
  const g7 = j => { const ul = u.length, pl = w.length, tl = 6 + ul + pl, k = new Uint8Array(2 + tl), v = new DataView(k.buffer);
    v.setUint16(0, 0xc023); k[2] = 1; k[3] = j; v.setUint16(4, tl); k[6] = ul; k.set(e2(u), 7); k[7 + ul] = pl; k.set(e2(w), 8 + ul); return k; };
  const g8 = d => { let o = d.length >= 2 && d[0] === 0xFF && d[1] === 0x03 ? 2 : 0; if (d.length - o < 4) return null;
    const p = f2(d, o); return p === 0x0021 ? { p, i: d.subarray(o + 2) } : d.length - o >= 6 ? { p, c: d[o + 2], i: d[o + 3], l: d.subarray(o + 6), r: d.subarray(o) } : null; };
  const g9 = d => { const r = []; for (let j = 0; j + 2 <= d.length;) { const t = d[j], l = d[j + 1]; if (l < 2 || j + l > d.length) break; r.push({ t, d: d.subarray(j + 2, j + l) }); j += l; } return r; };
  const g10 = async (x, y) => { s = c0({ hostname: x, port: y }, { secureTransport: 'on' }); await s.opened; r = s.readable.getReader({ mode: 'byob' }); t = s.writable.getWriter(); h = x; };
  const g11 = async () => {
    const z = e2(`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\nHost: ${h}\r\nContent-Length: 18446744073709551615\r\nSSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`);
    const pa = new Uint8Array(2); new DataView(pa.buffer).setUint16(0, 1); const mru = new Uint8Array(2); new DataView(mru.buffer).setUint16(0, 1500);
    await t.write(f1(z, g5(0x0001, [{ i: 1, d: pa }]), g4(g6(0xc021, 1, i++, [{ t: 1, d: mru }]))));
    const st = await g2(); while ((await g2()) !== ''); if (!st.includes('200')) throw 0;
    let sa = false, ld = false, au = false, dn = false, mi = null;
    for (let k = 0; k < 25 && !dn; k++) {
      const pk = await g3(); if (pk.c) { if (!sa && pk.b.length >= 2 && f2(pk.b, 0) === 2) sa = true; continue; }
      const pp = g8(pk.b); if (!pp) continue;
      if (pp.p === 0xc021) {
        if (pp.c === 1) { const a = new Uint8Array(pp.r); a[2] = 2; await t.write(ld && !au ? f1(g4(a), g4(g7(i++))) : g4(a)); if (ld) au = true; } 
        else if (pp.c === 2) { ld = true; if (!au) { await t.write(g4(g7(i++))); au = true; } }
      } else if (pp.p === 0xc023 && pp.c === 2) await t.write(g4(g6(0x8021, 1, i++, [{ t: 3, d: new Uint8Array(4) }])));
      else if (pp.p === 0x8021) {
        if (pp.c === 1) { const a = new Uint8Array(pp.r); a[2] = 2; await t.write(g4(a)); }
        else if (pp.c === 3) { const o = g9(pp.l).find(x => x.t === 3); if (o) { mi = [...o.d].join('.'); await t.write(g4(g6(0x8021, 1, i++, [{ t: 3, d: o.d }]))); } }
        else if (pp.c === 2) { const o = g9(pp.l).find(x => x.t === 3); if (o) mi = [...o.d].join('.'); dn = true; }
      }
    }
    if (!mi) throw 0; return mi;
  };
  const g12 = () => { [r, t, s].forEach(x => { try { x?.cancel?.() ?? x?.close?.(); } catch {} }); };
  return { c: g10, e: g11, r: g3, p: g8, get b() { return b; }, get w() { return t; }, q: g12 };
};

const f17 = (s, si, di, dp) => {
  const sp = 10000 + (f5() % 50000), sb = f7(si), db = f7(di); let sq = f6(), ak = 0;
  const ip = new Uint8Array(20); ip.set([0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6]); ip.set(sb, 12); ip.set(db, 16);
  const ps = new Uint8Array(1432); ps.set(sb); ps.set(db, 4); ps[9] = 6;
  const g1 = (f, d = e1) => {
    const pl = d.length, tl = 20 + pl, il = 20 + tl, st = 8 + il, k = new Uint8Array(st), v = new DataView(k.buffer);
    k.set([0x10, 0, ((st >> 8) & 0xF) | 0x80, st & 0xFF, 0xFF, 0x03, 0, 0x21]); k.set(ip, 8);
    v.setUint16(10, il); v.setUint16(12, f5()); v.setUint16(18, f8(k, 8, 20));
    v.setUint16(28, sp); v.setUint16(30, dp); v.setUint32(32, sq); v.setUint32(36, ak);
    k[40] = 0x50; k[41] = f; v.setUint16(42, 65535); if (pl) k.set(d, 48);
    ps[10] = tl >> 8; ps[11] = tl & 0xFF; ps.set(k.subarray(28, 28 + tl), 12);
    v.setUint16(44, f8(ps, 0, 12 + tl)); return k;
  };
  const g2 = i => { if (i.length < 40 || i[9] !== 6) return null; const hl = (i[0] & 0xF) * 4;
    if (f2(i, hl) !== dp || f2(i, hl + 2) !== sp) return null;
    return { f: i[hl + 13], s: f3(i, hl + 4), o: hl + ((i[hl + 12] >> 4) & 0xF) * 4 }; };
  const g3 = async () => {
    await s.w.write(g1(0x02)); sq++;
    for (let i = 0; i < 30; i++) { const pk = await s.r(); if (pk.c) continue; const pp = s.p(pk.b); if (!pp || pp.p !== 0x0021) continue;
      const m = g2(pp.i); if (!m || (m.f & 0x12) !== 0x12) continue; ak = (m.s + 1) >>> 0; s.w.write(g1(0x10)); return true; } throw 0;
  };
  return { f: g1, m: g2, h: g3, get s() { return sq; }, set s(v) { sq = v; }, get a() { return ak; }, set a(v) { ak = v; } };
};

const f18 = async ({ h, p, u, w }, pi, tp) => {
  const s = f16(u, w), c = () => s.q();
  try {
    await s.c(h, p); const [mi, ti] = await Promise.all([s.e(), pi]); if (!ti) { c(); return null; }
    const t = f17(s, mi, ti, tp); await t.h(); let cl = null;
    const rd = new ReadableStream({ start: x => { cl = x; }, cancel: c });
    (async () => {
      try { let pd = [], pl = 0;
        const fl = () => { if (!pl) return; cl.enqueue(pd.length === 1 ? pd[0] : f1(...pd)); pd = []; pl = 0; s.w.write(t.f(0x10)).catch(() => {}); };
        for (;;) { const pk = await s.r(60000); if (pk.c) continue; const pp = s.p(pk.b); if (!pp || pp.p !== 0x0021) continue;
          const m = t.m(pp.i); if (!m) continue;
          if (m.o < pp.i.length) { const d = pp.i.subarray(m.o); if (d.length) { t.a = (m.s + d.length) >>> 0; pd.push(new Uint8Array(d)); pl += d.length; } }
          if (m.f & 0x01) { fl(); t.a = (t.a + 1) >>> 0; s.w.write(t.f(0x11)).catch(() => {}); cl.close(); return; }
          if (s.b.length < 4 || pl >= 32768) fl(); }
      } catch { try { cl.close(); } catch {} }
    })();
    const wr = new WritableStream({
      async write(c) { const d = c instanceof Uint8Array ? c : new Uint8Array(c);
        if (d.length <= m1) { await s.w.write(t.f(0x18, d)); t.s = (t.s + d.length) >>> 0; return; }
        const fs = []; for (let o = 0; o < d.length; o += m1) { const g = d.subarray(o, Math.min(o + m1, d.length)); fs.push(t.f(0x18, g)); t.s = (t.s + g.length) >>> 0; }
        await s.w.write(f1(...fs));
      }, close: () => s.w.write(t.f(0x11)).catch(() => {}), abort: c
    });
    return { readable: rd, writable: wr, close: c };
  } catch { c(); return null; }
};

async function f19({ h, p, u, w }, th, tp, d) {
    let s; try {
        s = c0({ hostname: h, port: p });
        const wt = s.writable.getWriter(), rd = s.readable.getReader({ mode: 'byob' });
        const am = (u && w) ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
        await wt.write(am);
        let rb = new ArrayBuffer(1024), k1 = await rd.read(new Uint8Array(rb));
        if (k1.done || k1.value.byteLength < 2) throw 1;
        rb = k1.value.buffer; const sm = k1.value[1];
        if (sm === 0x02) {
            const ub = e2(u), pb = e2(w), ap = new Uint8Array(3 + ub.length + pb.length);
            ap[0] = 0x01; ap[1] = ub.length; ap.set(ub, 2); ap[2 + ub.length] = pb.length; ap.set(pb, 3 + ub.length);
            await wt.write(ap);
            let k2 = await rd.read(new Uint8Array(rb)); if (k2.done || k2.value[1] !== 0x00) throw 1; rb = k2.value.buffer;
        } else if (sm !== 0x00) throw 1;
        const hb = e2(th), cp = new Uint8Array(7 + hb.length);
        cp.set([0x05, 0x01, 0x00, 0x03, hb.length]); cp.set(hb, 5); new DataView(cp.buffer).setUint16(5 + hb.length, tp, false);
        await wt.write(cp);
        let k3 = await rd.read(new Uint8Array(rb)); if (k3.done || k3.value[1] !== 0x00) throw 1;
        if (d?.byteLength > 0) await wt.write(d);
        wt.releaseLock(); rd.releaseLock(); return s;
    } catch (e) { f11(s); throw e; }
}

async function f20({ t, h, p, u, w }, th, tp, id) {
    let s; try {
        s = c0({ hostname: h, port: p }, t === 'https' ? { secureTransport: 'on', allowHalfOpen: false } : {});
        const wt = s.writable.getWriter(), rd = s.readable.getReader({ mode: 'byob' });
        let rq = `CONNECT ${th}:${tp} HTTP/1.1\r\nHost: ${th}:${tp}\r\n`;
        if (u && w) rq += `Proxy-Authorization: Basic ${btoa(`${u}:${w}`)}\r\n`;
        rq += `User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
        await wt.write(e2(rq));
        
        let b = new Uint8Array(0), hi = -1, rb = new ArrayBuffer(8192);
        while (hi === -1 && b.length < 8192) {
            const { done: d, value: v } = await rd.read(new Uint8Array(rb)); if (d) throw 1; rb = v.buffer;
            const nb = new Uint8Array(b.length + v.length); nb.set(b); nb.set(v, b.length); b = nb;
            for (let i = 0; i < b.length - 3; i++) { if (b[i] === 13 && b[i+1] === 10 && b[i+2] === 13 && b[i+3] === 10) { hi = i + 4; break; } }
        }
        if (hi === -1) throw 1;
        const m = d1.decode(b.slice(0, hi)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
        if (!m || parseInt(m[1]) < 200 || parseInt(m[1]) >= 300) throw 1;
        if (id?.byteLength > 0) await wt.write(id);
        wt.releaseLock(); rd.releaseLock(); return s;
    } catch (e) { f11(s); throw e; }
}

async function f21(c, th, tp, id) {
    let ti = th;
    if (!r1.test(ti)) { const a = await f13(th, 'A'), i = a.filter(x => x.type === 1).map(x => x.data); if (i.length > 0) ti = i[0]; else throw 1; }
    const s = await f18(c, Promise.resolve(ti), tp); if (!s) throw 1;
    if (id?.byteLength > 0) { const w = s.writable.getWriter(); await w.write(id); w.releaseLock(); } return s;
}

async function f39({ t, h, p, u, w }, th, tp, id) {
    let cl, da;
    const c = () => { f11(cl); f11(da); };
    try {
        let ti = th;
        if (!r1.test(ti)) { const a = await f13(th, 'A'), i = a.filter(x => x.type === 1).map(x => x.data); if (i.length > 0) ti = i[0]; else throw 1; }
        cl = c0({ hostname: h, port: p }, t === 'turns' ? { secureTransport: 'on' } : {});
        await cl.opened;
        const cw = cl.writable.getWriter(), cr = cl.readable.getReader();
        const pr = f29(0x012, f31(ti, tp));
        const au = await f38(cw, cr, 6, { u, w }, (aa, sg) => [sg(f30(0x008, f4(12), [pr, ...aa])), sg(f30(0x00A, f4(12), [pr, ...aa]))]);
        if (!au) { c(); throw 1; }
        const { aa, sg } = au; let ex = au.ex;
        da = c0({ hostname: h, port: p }, t === 'turns' ? { secureTransport: 'on' } : {});
        await da.opened; const dw = da.writable.getWriter(), dr = da.readable.getReader();
        let r; [r, ex] = await f36(cr, ex); if (r?.t !== 0x108) { c(); throw 1; }
        [r, ex] = await f36(cr, ex); if (r?.t !== 0x10A || !r.a[0x02A]) { c(); throw 1; }
        await dw.write(await sg(f30(0x00B, f4(12), [f29(0x02A, r.a[0x02A]), ...aa])));
        let xt; [r, xt] = await f36(dr); if (r?.t !== 0x10B) { c(); throw 1; }
        cr.releaseLock(); cw.releaseLock(); dw.releaseLock();
        if (id?.byteLength > 0) { const w2 = da.writable.getWriter(); await w2.write(id); w2.releaseLock(); }
        const rdb = new ReadableStream({
            start(ctrl) { if (xt?.length) ctrl.enqueue(xt); },
            async pull(ctrl) { try { const { done: d, value: v } = await dr.read(); if (d) ctrl.close(); else ctrl.enqueue(new Uint8Array(v)); } catch(e) { ctrl.error(e); } },
            cancel() { dr.cancel(); c(); }
        });
        return { readable: rdb, writable: da.writable, close: c };
    } catch (e) { c(); throw e; }
}

const f46 = async ({ t, h, p, u, w }, ws) => {
    let sk = null, cl = false; const pm = new Set(), ss = new Map(), rv = {};
    const cls = () => { cl = true; f11(sk); };
    try {
        sk = c0({ hostname: h, port: p }, t === 'turns' ? { secureTransport: 'on' } : {}); await sk.opened;
        const wt = sk.writable.getWriter(), rd = sk.readable.getReader();
        const au = await f38(wt, rd, 17, { u, w }); if (!au) { cls(); return null; }
        const { aa, sg } = au; let bf = au.ex;
        (async () => {
            while (!cl) {
                const [m, nx] = await f36(rd, bf); bf = nx; if (!m) break;
                if (m.t === 0x017 && m.a[0x012] && m.a[0x013]) {
                    const [ip, pt] = f34(m.a[0x012]), s = rv[`${ip}:${pt}`];
                    if (ws.readyState === 1) ws.send(f45(s?.h ?? ip, s?.p ?? pt, m.a[0x013]));
                }
            }
        })();
        const ep = ip => { if (pm.has(ip)) return; pm.add(ip); sg(f30(0x008, f4(12), [f29(0x012, f31(ip, 0)), ...aa])).then(m => wt.write(m)); };
        const su = (ip, pt, dt) => wt.write(f30(0x016, f4(12), [f29(0x012, f31(ip, pt)), f29(0x013, dt)]));
        const gi = (ho, po) => { const k = `${ho}:${po}`, c = ss.get(k); if (c) return c.i; const ft = f43(ho); if (ft) for (const s of ss.values()) if (s.p === po && s.v === (ft === 6)) { const ns = { i: s.i, h: ho, p: po, v: s.v }; ss.set(k, ns); rv[`${s.i}:${po}`] = ns; return s.i; } return null; };
        const ra = async (ho, po, k) => { let ip = ho; if (!r1.test(ho)) { const a = await f13(ho, 'A'), i = a.filter(x => x.type === 1).map(x => x.data); if (i.length > 0) ip = i[0]; else return; } const s = { i: ip, h: ho, p: po, v: ip.includes(':') }; ss.set(k, s); rv[`${ip}:${po}`] = s; };
        const px = dt => {
            while (dt.length >= 6) {
                const f = f44(dt); if (!f) break;
                if (f.n === 2 && f.pl?.length && f.h) { const k = `${f.h}:${f.p}`, ip = gi(f.h, f.p); if (ip) { ep(ip); su(ip, f.p, f.pl); } else { if (!ss.has(k)) ra(f.h, f.p, k); } }
                dt = dt.subarray(f.tl);
            }
        };
        return { p: px, c: cls };
    } catch { cls(); return null; }
};

function f22(c, t) {
    if (c.byteLength < 24) return { e: 1, m: '1' };
    const v = new Uint8Array(c.slice(0, 1)); if (f9(new Uint8Array(c.slice(1, 17))) !== t) return { e: 1, m: '2' };
    const l = new Uint8Array(c.slice(17, 18))[0], cmd = new Uint8Array(c.slice(18 + l, 19 + l))[0];
    if (cmd !== 1 && cmd !== 2 && cmd !== 3) return { e: 1, m: '3' };
    if (cmd === 3) return { e: 0, u: true, x: true, r: 19 + l, v };
    const p = 19 + l, pt = new DataView(c.slice(p, p + 2)).getUint16(0);
    let a = p + 3, al = 0, hn = ''; const at = new Uint8Array(c.slice(p + 2, a))[0];
    switch (at) {
        case 1: al = 4; hn = new Uint8Array(c.slice(a, a + al)).join('.'); break;
        case 2: al = new Uint8Array(c.slice(a, a + 1))[0]; a += 1; hn = d1.decode(c.slice(a, a + al)); break;
        case 3: al = 16; const iv = new DataView(c.slice(a, a + al)); hn = Array.from({ length: 8 }, (_, i) => iv.getUint16(i * 2).toString(16)).join(':'); break;
        default: return { e: 1, m: '4' };
    }
    if (!hn) return { e: 1, m: '5' };
    return { e: 0, at, pt, hn, u: cmd === 2, r: a + al, v };
}

function f23(s, eh) {
    let c = false;
    return new ReadableStream({
        start(k) {
            s.addEventListener('message', e => { if (!c) k.enqueue(e.data); });
            s.addEventListener('close', () => { if (!c) { k.close(); } });
            s.addEventListener('error', e => k.error(e));
            const { d, e } = f10(eh); if (e) k.error(e); else if (d) k.enqueue(d);
        }, cancel() { c = true; }
    });
}

async function f24(rs, ws, h, rf) {
    let hd = h, hdS = false;
    try {
        let rd, isB = false;
        try { rd = rs.readable.getReader({ mode: 'byob' }); isB = true; } catch (e) { rd = rs.readable.getReader(); }
        let b = new ArrayBuffer(32768);
        while (true) {
            let d, v;
            if (isB) { const k = await rd.read(new Uint8Array(b)); d = k.done; v = k.value; if (v) b = v.buffer; }
            else { const k = await rd.read(); d = k.done; v = k.value; }
            if (d) break;
            hdS = true;
            if (ws.readyState === 1) {
                if (hd) { const r = new Uint8Array(hd.length + v.byteLength); r.set(hd, 0); r.set(new Uint8Array(v), hd.length); ws.send(r.buffer); hd = null; }
                else { ws.send(v); }
            }
        }
    } catch (e) {} finally {
        if (!hdS && rf) await rf();
    }
}

async function f25(at, hn, pt, rd, ws, rh, rc, cf) {
    const cd = async (a, p, d) => { const s = c0({ hostname: a, port: p }); const w = s.writable.getWriter(); await w.write(d); w.releaseLock(); return s; };
    let cp = cf || v1, pc = cp ? f12(cp) : null, sp = false;
    if (!pc) pc = { t: 'direct', h: v1, p: 443 };
    if (pc.t === 'direct' && cp) { try { const l = await f15(cp, hn, v2); if (l?.length > 0) [pc.h, pc.p] = l[0]; } catch (e) {} }
    else if (['socks5', 'http', 'https', 'sstp', 'turn', 'turns'].includes(pc.t)) sp = true;

    const cwp = async () => {
        let ns;
        if (pc.t === 'socks5') ns = await f19(pc, hn, pt, rd); 
        else if (['http', 'https'].includes(pc.t)) ns = await f20(pc, hn, pt, rd);
        else if (pc.t === 'sstp') ns = await f21(pc, hn, pt, rd); 
        else if (['turn', 'turns'].includes(pc.t)) ns = await f39(pc, hn, pt, rd);
        else ns = await cd(pc.h, pc.p, rd);
        rc.s = ns;
        f24(ns, ws, rh, null);
    };
    if (sp) { await cwp(); } else { try { const is = await cd(hn, pt, rd); rc.s = is; f24(is, ws, rh, cwp); } catch (e) { await cwp(); } }
}

async function f26(uc, ws, rh) {
    try {
        const ts = c0({ hostname: '8.8.4.4', port: 53 }); let vh = rh;
        const w = ts.writable.getWriter(); await w.write(uc); w.releaseLock();
        const r = ts.readable.getReader({ mode: 'byob' }); let b = new ArrayBuffer(8192);
        while (true) {
            const { done: d, value: v } = await r.read(new Uint8Array(b)); if (d) break; b = v.buffer;
            if (ws.readyState === 1) {
                if (vh) { const rs = new Uint8Array(vh.length + v.byteLength); rs.set(vh, 0); rs.set(new Uint8Array(v), vh.length); ws.send(rs.buffer); vh = null; }
                else { ws.send(v); }
            }
        }
    } catch (e) {}
}

async function f27(rq, cf) {
    const wp = new WebSocketPair(), [cs, ss] = Object.values(wp); ss.accept();
    let rc = { s: null }, iq = false, xu = null; const ed = rq.headers.get('sec-websocket-protocol') || '', rd = f23(ss, ed);
    rd.pipeTo(new WritableStream({
        async write(c) {
            if (xu) return xu.p(c);
            if (iq) return await f26(c, ss, null);
            if (rc.s) { const w = rc.s.writable.getWriter(); await w.write(c); w.releaseLock(); return; }
            const { e, m, at, pt, hn, r, v, u, x } = f22(c, v2); if (e) throw new Error(m);
            
            const cp = cf || v1, pc = cp ? f12(cp) : { t: 'direct', h: v1, p: 443 };
            
            if (x) {
                const rh = new Uint8Array([v[0], 0]); if (ss.readyState === 1) ss.send(rh);
                if (['turn', 'turns'].includes(pc.t)) { xu = await f46(pc, ss); if (xu) xu.p(c.slice(r)); else f11(ss); }
                else f11(ss);
                return;
            }
            
            if (u) { if (pt === 53) iq = true; else throw new Error('U'); }
            const rh = new Uint8Array([v[0], 0]), cd = c.slice(r);
            if (iq) return f26(cd, ss, rh);
            await f25(at, hn, pt, cd, ss, rh, rc, cf);
        }
    })).catch(() => {});
    return new Response(null, { status: 101, webSocket: cs });
}

export default {
    async fetch(rq, ev, cx) {
        try {
            const u = new URL(rq.url), iu = rq.headers.get('Upgrade') === 'websocket'; let cf = null;
            if (u.pathname.startsWith('/fdip=')) {
                try { cf = decodeURIComponent(u.pathname.substring(9)).trim(); } catch (e) {}
                if (cf && !iu) { v1 = cf; return new Response(`set fdIP to: ${v1}\n\n`, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0' } }); }
            }
            if (iu) return await f27(rq, cf || u.searchParams.get('fdip') || rq.headers.get('fdip'));
            return new Response('Snippets Ready', { status: 200 });
        } catch (e) { return new Response('Err', { status: 500 }); }
    }
};
