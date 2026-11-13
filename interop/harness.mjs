// Line-oriented JSON harness around jkurwa, used by uakep's interop tests.
// Each input line is {"op": ..., ...}; each output line is the matching result, or
// {"error": "..."} if jkurwa threw. Hex strings carry all binary values.
import readline from "node:readline";
import * as jk from "jkurwa";

const hex = (buf) => Buffer.from(buf).toString("hex");
const bin = (text) => Buffer.from(text, "hex");

const ops = {
  pub({ curve, d }) {
    const priv = jk.std_curve(curve).pkey(d);
    return { pub: priv.pub_compress().toString(true) };
  },

  sign({ curve, d, hash }) {
    const priv = jk.std_curve(curve).pkey(d);
    return { sig: hex(priv.sign(bin(hash), "le")) };
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
    out = fn ? fn(request) : { error: `unknown op ${request.op}` };
  } catch (e) {
    out = { error: String(e && e.stack ? e.stack : e) };
  }
  process.stdout.write(JSON.stringify(out) + "\n");
}
