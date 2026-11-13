// Line-oriented JSON harness around jkurwa, used by uakep's interop tests.
// Each input line is {"op": ..., ...}; each output line is the matching result, or
// {"error": "..."} if jkurwa threw. Hex strings carry all binary values.
import readline from "node:readline";
import * as jk from "jkurwa";
import gost89 from "gost89";
import dstu7564 from "dstu7564";

const hex = (buf) => Buffer.from(buf).toString("hex");
const bin = (text) => Buffer.from(text, "hex");

const gostHash = gost89.compat.algos().hash;
const kupynaHash = (data) => dstu7564.computeHash(32, data);
const algo = {
  hash: gostHash,
  hashes: {
    Gost34311: gostHash,
    Dstu4145le: gostHash,
    "Dstu7564-256": kupynaHash,
    Dstu4145leWithDstu7564: kupynaHash,
  },
};

const ops = {
  pub({ curve, d }) {
    const priv = jk.std_curve(curve).pkey(d);
    return { pub: priv.pub_compress().toString(true) };
  },

  sign({ curve, d, hash }) {
    const priv = jk.std_curve(curve).pkey(d);
    return { sig: hex(priv.sign(bin(hash), "le")) };
  },

  async cms_verify({ data }) {
    const box = new jk.Box({ algo });
    const info = await box.unwrap(bin(data));
    const step = info.pipe[0] || {};
    return { ok: step.signed === true && !info.error, reason: info.error || null, content: hex(info.content) };
  },

  async cms_sign({ curve, d, cert, data }) {
    const box = new jk.Box({ algo });
    box.load({ priv: jk.std_curve(curve).pkey(d), cert: jk.Certificate.from_asn1(bin(cert)) });
    const message = await box.sign(bin(data), null, null, {});
    return { signed: hex(message.as_asn1()) };
  },

  verify({ curve, pub, hash, sig }) {
    const key = jk.std_curve(curve).pubkey(pub);
    try {
      return { ok: key.verify(bin(hash), bin(sig), "le") === true };
    } catch (e) {
      return { ok: false, reason: e.message };
    }
  },
};

const rl = readline.createInterface({ input: process.stdin, terminal: false });
for await (const line of rl) {
  if (!line.trim()) continue;
  let out;
  try {
    const request = JSON.parse(line);
    const fn = ops[request.op];
    out = fn ? await fn(request) : { error: `unknown op ${request.op}` };
  } catch (e) {
    out = { error: String(e && e.stack ? e.stack : e) };
  }
  process.stdout.write(JSON.stringify(out) + "\n");
}
