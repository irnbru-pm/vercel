import { readSync, writeSync } from "node:fs";

const originals = new Map<string, string | null>();

function transfer(buffer: Buffer, write: boolean): void {
  const bytes = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let offset = 0;
  while (offset < buffer.length) {
    const n = write ? writeSync(3, bytes, offset, buffer.length - offset) : readSync(3, bytes, offset, buffer.length - offset, null);
    if (n <= 0) throw new Error("IrnBru credential service disconnected");
    offset += n;
  }
}

function exchange(request: object): string | null {
  const payload = Buffer.from(JSON.stringify(request));
  if (payload.length > 262144) throw new Error("Credential request too large");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length);
  transfer(header, true);
  transfer(payload, true);
  transfer(header, false);
  const length = header.readUInt32BE();
  if (!length || length > 262144) throw new Error("Invalid IrnBru response");
  const data = Buffer.alloc(length);
  transfer(data, false);
  const reply = JSON.parse(data.toString());
  if (reply.ok !== true || !(reply.value === null || typeof reply.value === "string")) {
    throw new Error("IrnBru denied the credential operation");
  }
  return reply.value;
}

export function readSession(profile: string): string | null {
  const value = exchange({ op: "use", profile });
  originals.set(profile, value);
  return value;
}

export function writeSession(profile: string, value: string | null): void {
  if (!originals.has(profile)) readSession(profile);
  exchange({ op: value === null ? "delete" : "save", profile, expected: originals.get(profile), value });
  originals.set(profile, value);
}
