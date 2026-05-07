import { connect as c1 } from 'cloudflare:sockets';

const v1 = 'proxyip.example.com!txt';
const v2 = '495c7195-85b8-498a-bf20-2ea9ce9175b5';

let v3 = null;
let v4 = null;

function f1(s) {
    try { if (s.readyState === WebSocket.OPEN || s.readyState === WebSocket.CLOSING) s.close(); } catch (e) {}
}

function f2(s) {
    if (!s) return { e: null };
    try {
        const b = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
        const y = new Uint8Array(b.length);
        for (let i = 0; i < b.length; i++) y[i] = b.charCodeAt(i);
        return { d: y.buffer, e: null };
    } catch (e) { return { e }; }
}

function f3(s) {
    if (!s) return null;
    s = s.trim();
    if (s.startsWith('[')) {
        const i = s.indexOf(']');
        if (i > 0) {
            const h = s.substring(1, i), r = s.substring(i + 1);
            if (r.startsWith(':')) {
                const p = parseInt(r.substring(1), 10);
                if (!isNaN(p) && p > 0 && p <= 65535) return { h, p };
            }
            return { h, p: 443 };
        }
    }
    const i = s.lastIndexOf(':');
    if (i > 0) {
        const h = s.substring(0, i), p = parseInt(s.substring(i + 1), 10);
        if (!isNaN(p) && p > 0 && p <= 65535) return { h, p };
    }
    return { h: s, p: 443 };
}

async function f4(d) {
    const f = async (u) => {
        try {
            const r = await fetch(`${u}?name=${d}&type=TXT`, { headers: { 'Accept': 'application/dns-json' } });
            if (r.ok) {
                const j = await r.json();
                return j.Answer || [];
            }
        } catch (e) {}
        return null;
    };
    const r = await f('https://1.1.1.1/dns-query');
    return r || (await f('https://dns.google/dns-query')) || [];
}

function f5(n, t, u) {
    if (!n || n.length === 0) return null;
    const tr = t.includes('.') ? t.split('.').slice(-2).join('.') : t;
    let sd = [...(tr + u)].reduce((a, c) => a + c.charCodeAt(0), 0);
    let sh = [...n].sort(() => {
        sd = (sd * 1103515245 + 12345) & 0x7fffffff;
        return (sd / 0x7fffffff) - 0.5;
    });
    return sh[0];
}

async function f6(ps, th, u) {
    const rs = ps.trim();
    if (v3 === rs && v4) return f5(v4, th, u);

    const d = rs.slice(0, -4).trim();
    const tr = await f4(d);
    if (!tr) return null;
    
    const tx = tr.filter(r => r.type === 16).map(r => r.data);
    let n = [];
    if (tx.length > 0) {
        let x = tx[0].replace(/^"|"$/g, '');
        const p = x.replace(/\\010|\n/g, ',').split(',').map(y => y.trim()).filter(Boolean);
        n = p.map(x => f3(x)).filter(Boolean);
    }

    if (n.length === 0) return null;

    v4 = n.sort((x, y) => x.h.localeCompare(y.h));
    v3 = rs;

    return f5(v4, th, u);
}

function f7(c) {
    if (c.byteLength < 7) return { e: true, m: '1' };
    try {
        const v = new Uint8Array(c);
        const t = v[0];
        let i = 1, l = 0, x = i, h = '';
        switch (t) {
            case 1: l = 4; h = new Uint8Array(c.slice(x, x + l)).join('.'); x += l; break;
            case 3: l = v[i]; x += 1; h = new TextDecoder().decode(c.slice(x, x + l)); x += l; break;
            case 4: l = 16; const a = []; const d = new DataView(c.slice(x, x + l)); for (let j = 0; j < 8; j++) a.push(d.getUint16(j * 2).toString(16)); h = a.join(':'); x += l; break;
            default: return { e: true, m: '2' };
        }
        if (!h) return { e: true, m: '3' };
        const p = new DataView(c.slice(x, x + 2)).getUint16(0);
        return { e: false, t, p, h, r: x + 2 };
    } catch (e) { return { e: true, m: '4' }; }
}

async function f8(sck, ws, hd, rf) {
    let h = hd, hd2 = false;
    try {
        const rd = sck.readable.getReader({ mode: 'byob' });
        let b = new ArrayBuffer(20480);
        while (true) {
            const { done, value } = await rd.read(new Uint8Array(b));
            if (done) break;
            b = value.buffer; 
            hd2 = true;
            if (ws.readyState !== WebSocket.OPEN) break;
            if (h) {
                const r = new Uint8Array(h.length + value.byteLength);
                r.set(h, 0); 
                r.set(new Uint8Array(value.buffer, value.byteOffset, value.byteLength), h.length);
                ws.send(r.buffer);
                h = null;
            } else {
                ws.send(value);
            }
        }
    } catch (e) { 
        if (hd2 || !rf) {
            f1(ws); 
        }
    }
    
    if (!hd2 && rf) await rf();
}

async function f9(h, p, d, w, r, cw, k) {
    async function cd(a, o, c) {
        const s = c1({ hostname: a, port: o });
        const x = s.writable.getWriter();
        await x.write(c); x.releaseLock(); return s;
    }
    
    let pc = f3(k) || f3(v1) || { h: v1, p: 443 };
    let fb = k || v1;
    
    if (fb && fb.toLowerCase().endsWith('!txt')) {
        try {
            const tn = await f6(fb, h, v2);
            if (tn) pc = tn;
        } catch (e) {}
    }

    async function cp() {
        let ns = await cd(pc.h, pc.p, d);
        cw.s = ns;
        ns.closed.catch(() => {}).finally(() => f1(w));
        f8(ns, w, r, null);
    }
    try {
        const is = await cd(h, p, d);
        cw.s = is; f8(is, w, r, cp);
    } catch (e) { await cp(); }
}

function f10(s, h) {
    let c = false;
    return new ReadableStream({
        start(ctrl) {
            s.addEventListener('message', e => { if (!c) ctrl.enqueue(e.data); });
            s.addEventListener('close', () => { if (!c) { f1(s); ctrl.close(); } });
            s.addEventListener('error', e => ctrl.error(e));
            const { d, e } = f2(h);
            if (e) ctrl.error(e); else if (d) ctrl.enqueue(d);
        },
        cancel() { c = true; f1(s); }
    });
}

async function f11(u, w, r) {
    try {
        const t = c1({ hostname: '8.8.4.4', port: 53 });
        let v = r; 
        const x = t.writable.getWriter();
        await x.write(u); x.releaseLock();
        
        const rd = t.readable.getReader({ mode: 'byob' });
        let b = new ArrayBuffer(20480);
        while (true) {
            const { done, value } = await rd.read(new Uint8Array(b));
            if (done) break;
            b = value.buffer;
            if (w.readyState === WebSocket.OPEN) {
                if (v) {
                    const s = new Uint8Array(v.length + value.byteLength);
                    s.set(v, 0); 
                    s.set(new Uint8Array(value.buffer, value.byteOffset, value.byteLength), v.length);
                    w.send(s.buffer); 
                    v = null;
                } else w.send(value);
            }
        }
    } catch (e) {}
}

async function f12(r, k) {
    const pair = new WebSocketPair();
    const [c, s] = Object.values(pair);
    s.accept();
    
    let cw = { s: null }, q = false;
    const ed = r.headers.get('sec-websocket-protocol') || '';
    const rd = f10(s, ed);
    
    rd.pipeTo(new WritableStream({
        async write(chunk) {
            if (q) return await f11(chunk, s, null);
            if (cw.s) {
                const w = cw.s.writable.getWriter();
                await w.write(chunk); w.releaseLock(); return;
            }
            const { e, t, p, h, r: i } = f7(chunk);
            if (e) throw new Error('e');
            if (t === 2) {
                if (p === 53) q = true; else throw new Error('g');
            }
            const rp = chunk.slice(i);
            if (q) return f11(rp, s, null);
            await f9(h, p, rp, s, null, cw, k);
        }
    })).catch(() => {});
    
    return new Response(null, { status: 101, webSocket: c });
}

export default {
    async fetch(r) {
        try {
            const u = new URL(r.url);
            if (r.headers.get('Upgrade') !== 'websocket') return new Response(null, { status: 404 });
            if (!u.pathname.toLowerCase().startsWith(`/${v2}`.toLowerCase())) return new Response(null, { status: 401 });
            
            const k = u.searchParams.get('fdip') || r.headers.get('fdip');
            return await f12(r, k);
        } catch (e) {
            return new Response(null, { status: 500 });
        }
    }
};
