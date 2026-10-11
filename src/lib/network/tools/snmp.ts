import dgram from "node:dgram";
import { randomInt } from "node:crypto";
import * as snmpV3 from "net-snmp";

/**
 * Cliente SNMP v1/v2c mínimo (GET e GETNEXT/walk) com codificação BER própria — o protocolo é
 * simples o bastante para não justificar uma dependência. Cobre o que um inventário precisa:
 * identificação (system), interfaces e suprimentos de impressoras.
 */

// ---------------------------------------------------------------- BER encode

function encodeLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes: number[] = [];
  for (let n = len; n > 0; n >>= 8) bytes.unshift(n & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

function encodeInteger(value: number): Buffer {
  const bytes: number[] = [];
  let n = value;
  do {
    bytes.unshift(n & 0xff);
    n >>= 8;
  } while (n !== 0 && n !== -1);
  // Garante que o bit de sinal do primeiro byte corresponda ao sinal do número.
  if (value >= 0 && bytes[0] & 0x80) bytes.unshift(0);
  if (value < 0 && !(bytes[0] & 0x80)) bytes.unshift(0xff);
  return tlv(0x02, Buffer.from(bytes));
}

function encodeOid(oid: string): Buffer {
  const parts = oid.replace(/^\./, "").split(".").map(Number);
  if (parts.length < 2 || parts.some((p) => !Number.isInteger(p) || p < 0)) throw new Error(`OID inválido: ${oid}`);
  const bytes = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const chunk: number[] = [part & 0x7f];
    for (let n = Math.floor(part / 128); n > 0; n = Math.floor(n / 128)) chunk.unshift((n & 0x7f) | 0x80);
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}

const PDU_GET = 0xa0;
const PDU_GETNEXT = 0xa1;
const PDU_RESPONSE = 0xa2;

/** Exportada para testes. */
export function buildRequest(version: SnmpVersion, community: string, pduType: number, requestId: number, oids: string[]): Buffer {
  const varbinds = tlv(0x30, Buffer.concat(oids.map((oid) => tlv(0x30, Buffer.concat([encodeOid(oid), Buffer.from([0x05, 0x00])])))));
  const pdu = tlv(pduType, Buffer.concat([encodeInteger(requestId), encodeInteger(0), encodeInteger(0), varbinds]));
  return tlv(0x30, Buffer.concat([encodeInteger(version === "1" ? 0 : 1), tlv(0x04, Buffer.from(community)), pdu]));
}

// ---------------------------------------------------------------- BER decode

interface Tlv {
  tag: number;
  value: Buffer;
  end: number;
}

function readTlv(buf: Buffer, offset: number): Tlv {
  const tag = buf[offset];
  let len = buf[offset + 1];
  let pos = offset + 2;
  if (len & 0x80) {
    const count = len & 0x7f;
    len = 0;
    for (let i = 0; i < count; i++) len = len * 256 + buf[pos++];
  }
  if (pos + len > buf.length) throw new Error("Resposta SNMP truncada");
  return { tag, value: buf.subarray(pos, pos + len), end: pos + len };
}

function readChildren(buf: Buffer): Tlv[] {
  const children: Tlv[] = [];
  for (let offset = 0; offset < buf.length; ) {
    const child = readTlv(buf, offset);
    children.push(child);
    offset = child.end;
  }
  return children;
}

function decodeSigned(buf: Buffer): number {
  let n = buf[0] & 0x80 ? -1 : 0;
  for (const b of buf) n = n * 256 + b;
  return n;
}

function decodeUnsigned(buf: Buffer): bigint {
  let n = BigInt(0);
  for (const b of buf) n = (n << BigInt(8)) | BigInt(b);
  return n;
}

function decodeOid(buf: Buffer): string {
  const parts = [Math.floor(buf[0] / 40), buf[0] % 40];
  let n = 0;
  for (const b of buf.subarray(1)) {
    n = n * 128 + (b & 0x7f);
    if (!(b & 0x80)) {
      parts.push(n);
      n = 0;
    }
  }
  return parts.join(".");
}

function formatTimeTicks(ticks: bigint): string {
  let seconds = Number(ticks / BigInt(100));
  const days = Math.floor(seconds / 86400);
  seconds %= 86400;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${days}d ${hours}h ${minutes}m`;
}

function formatOctetString(buf: Buffer): string {
  if (buf.length === 6 && !/^[\x20-\x7e]{6}$/.test(buf.toString("latin1"))) {
    return buf.toString("hex").toUpperCase().match(/../g)!.join(":");
  }
  const text = buf.toString("utf8").replace(/\0+$/, "");
  return /^[\x09\x0a\x0d\x20-\x7e -￿]*$/.test(text) ? text : buf.toString("hex").toUpperCase();
}

/** Valores "ausentes" de SNMPv2 (exceções no varbind), não são dados reais. */
const EXCEPTION_TAGS: Record<number, string> = { 0x80: "noSuchObject", 0x81: "noSuchInstance", 0x82: "endOfMibView" };

interface VarBind {
  oid: string;
  value: string;
  exception?: string;
}

function decodeValue({ tag, value }: Tlv): Omit<VarBind, "oid"> {
  if (tag in EXCEPTION_TAGS) return { value: "", exception: EXCEPTION_TAGS[tag] };
  switch (tag) {
    case 0x02:
      return { value: String(decodeSigned(value)) };
    case 0x04:
      return { value: formatOctetString(value) };
    case 0x05:
      return { value: "" };
    case 0x06:
      return { value: decodeOid(value) };
    case 0x40:
      return { value: Array.from(value).join(".") };
    case 0x43:
      return { value: formatTimeTicks(decodeUnsigned(value)) };
    case 0x41: // Counter32
    case 0x42: // Gauge32
    case 0x46: // Counter64
    case 0x47: // UInteger32
      return { value: decodeUnsigned(value).toString() };
    default:
      return { value: value.toString("hex") };
  }
}

const SNMP_ERRORS: Record<number, string> = {
  1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly", 5: "genErr", 6: "noAccess",
};

/** Exportada para testes. */
export function parseResponse(buf: Buffer, expectedId: number): VarBind[] | null {
  let fields: Tlv[];
  try {
    const [, , pdu] = readChildren(readTlv(buf, 0).value);
    if (!pdu || pdu.tag !== PDU_RESPONSE) return null;
    fields = readChildren(pdu.value);
  } catch {
    return null; // pacote malformado ou de outra origem: ignora e segue aguardando a resposta certa
  }
  const [reqId, errStatus, , varbinds] = fields;
  if (!reqId || !errStatus || !varbinds || decodeSigned(reqId.value) !== expectedId) return null;

  const status = decodeSigned(errStatus.value);
  // Em v1, OID inexistente vem como erro noSuchName em vez de exceção no varbind.
  if (status === 2) return [];
  if (status !== 0) throw new Error(`Agente SNMP retornou erro: ${SNMP_ERRORS[status] ?? status}`);

  return readChildren(varbinds.value).map((vb) => {
    const [oid, value] = readChildren(vb.value);
    return { oid: decodeOid(oid.value), ...decodeValue(value) };
  });
}

// ---------------------------------------------------------------- transporte

export type SnmpVersion = "1" | "2c";

export interface SnmpCommunityTarget {
  host: string;
  community: string;
  version: SnmpVersion;
}

export interface SnmpV3Target {
  host: string;
  version: "3";
  username: string;
  authPassword: string;
  authProtocol: "md5" | "sha";
  privacyProtocol?: "des" | "aes";
  privacyPassword?: string;
}

export type SnmpTarget = SnmpCommunityTarget | SnmpV3Target;

const TIMEOUT_MS = 2000;
const RETRIES = 1;

async function requestV3(target: SnmpV3Target, pduType: number, oids: string[]): Promise<VarBind[]> {
  const user = createV3User(target);
  const session = snmpV3.createV3Session(target.host, user, { version: 3, timeout: TIMEOUT_MS, retries: RETRIES, transport: "udp4" });
  session.on("error", () => {});
  try {
    const bindings = await new Promise<snmpV3.Varbind[]>((resolve, reject) => {
      const callback: snmpV3.GetSetCallback = (error, result) => error ? reject(error) : resolve(result ?? []);
      if (pduType === PDU_GET) session.get(oids, callback);
      else session.getNext(oids, callback);
    });
    return bindings.map((binding) => {
      if (snmpV3.isVarbindError(binding)) return { oid: binding.oid, value: "", exception: snmpV3.varbindError(binding) };
      const value = binding.value;
      if (binding.type === snmpV3.ObjectType.TimeTicks && typeof value === "number") {
        const totalSeconds = Math.floor(value / 100);
        const days = Math.floor(totalSeconds / 86400);
        const hours = Math.floor((totalSeconds % 86400) / 3600);
        const minutes = Math.floor((totalSeconds % 3600) / 60);
        return { oid: binding.oid, value: `${days}d ${hours}h ${minutes}m` };
      }
      return { oid: binding.oid, value: Buffer.isBuffer(value) ? formatOctetString(value) : String(value ?? "") };
    });
  } finally {
    session.close();
  }
}

/** Monta o nível e os algoritmos de segurança do usuário SNMPv3. */
export function createV3User(target: SnmpV3Target): snmpV3.User {
  if (Boolean(target.privacyProtocol) !== Boolean(target.privacyPassword)) {
    throw new Error("A privacidade SNMPv3 requer algoritmo e senha de privacidade.");
  }
  return {
    name: target.username,
    level: target.privacyProtocol ? snmpV3.SecurityLevel.authPriv : snmpV3.SecurityLevel.authNoPriv,
    authProtocol: target.authProtocol === "md5" ? snmpV3.AuthProtocols.md5 : snmpV3.AuthProtocols.sha,
    authKey: target.authPassword,
    ...(target.privacyProtocol && target.privacyPassword ? {
      privProtocol: target.privacyProtocol === "des" ? snmpV3.PrivProtocols.des : snmpV3.PrivProtocols.aes,
      privKey: target.privacyPassword,
    } : {}),
  };
}

async function request(target: SnmpTarget, pduType: number, oids: string[]): Promise<VarBind[]> {
  if (target.version === "3") return requestV3(target, pduType, oids);
  const socket = dgram.createSocket("udp4");
  socket.on("error", () => {});
  try {
    for (let attempt = 0; attempt <= RETRIES; attempt++) {
      const requestId = randomInt(1, 0x7fffffff);
      const message = buildRequest(target.version, target.community, pduType, requestId, oids);

      const response = await new Promise<VarBind[] | null>((resolve, reject) => {
        const timer = setTimeout(() => {
          socket.removeListener("message", onMessage);
          resolve(null);
        }, TIMEOUT_MS);
        function onMessage(msg: Buffer) {
          try {
            const parsed = parseResponse(msg, requestId);
            if (!parsed) return;
            clearTimeout(timer);
            socket.removeListener("message", onMessage);
            resolve(parsed);
          } catch (err) {
            clearTimeout(timer);
            socket.removeListener("message", onMessage);
            reject(err);
          }
        }
        socket.on("message", onMessage);
        socket.send(message, 161, target.host, (err) => {
          if (err) {
            clearTimeout(timer);
            reject(err);
          }
        });
      });

      if (response) return response;
    }
  } finally {
    socket.close();
  }

  throw new Error(
      `Sem resposta SNMP de ${target.host}. Verifique se o SNMP está habilitado e confira a versão e as credenciais configuradas.`,
  );
}

/** Varbinds por GET: cabe com folga num datagrama de ~1.400 bytes mesmo com OIDs e valores longos. */
const GET_BATCH = 10;

/**
 * GET de vários OIDs agrupados em poucos pacotes (OID -> valor; ausentes ficam de fora). Bem mais rápido
 * que um walk por coluna quando já se conhecem os índices: o agente responde um pacote por vez.
 */
export async function snmpGetMany(target: SnmpTarget, oids: string[]): Promise<Map<string, string>> {
  const values = new Map<string, string>();
  for (let i = 0; i < oids.length; i += GET_BATCH) {
    const chunk = oids.slice(i, i + GET_BATCH).map((o) => o.replace(/^\./, ""));
    let vbs = await request(target, PDU_GET, chunk);
    // Em v1 um único OID inexistente derruba o pacote inteiro (noSuchName): repete um a um.
    if (!vbs.length && chunk.length > 1) vbs = (await Promise.all(chunk.map((o) => request(target, PDU_GET, [o])))).flat();
    for (const vb of vbs) if (!vb.exception) values.set(vb.oid, vb.value);
  }
  return values;
}

const MAX_WALK_ROWS = 500;

async function walk(target: SnmpTarget, rootOid: string): Promise<VarBind[]> {
  const root = rootOid.replace(/^\./, "");
  const rows: VarBind[] = [];
  let current = root;

  while (rows.length < MAX_WALK_ROWS) {
    const [vb] = await request(target, PDU_GETNEXT, [current]);
    if (!vb || vb.exception || !vb.oid.startsWith(`${root}.`) || vb.oid === current) break;
    rows.push(vb);
    current = vb.oid;
  }
  return rows;
}

// ---------------------------------------------------------------- consultas prontas

export const SNMP_MODES = ["system", "interfaces", "printer", "get", "walk"] as const;
export type SnmpMode = (typeof SNMP_MODES)[number];

export interface SnmpTable {
  columns: string[];
  rows: string[][];
}

/** Traduz descrições comuns da Printer-MIB sem expor números de série do fabricante. */
export function formatPrinterSupply(rawName: string, level: string): [name: string, description: string, level: string] {
  const cleaned = rawName.replace(/\s*(?:S\/N|Serial(?:\s+Number)?)\s*:\s*[^,;]+/gi, "").replace(/\s+/g, " ").trim();
  const normalized = cleaned.toLowerCase();
  const known: [RegExp, string, string][] = [
    [/black toner cartridge|toner cartridge.*black|cartucho.*toner.*preto/, "Toner preto", "Consumível de impressão; indica a quantidade estimada de toner restante."],
    [/^fuser$|fuser unit/, "Fusor", "Peça de manutenção que fixa o toner ao papel."],
    [/^t2 roller$/, "Rolo T2", "Peça de alimentação e transporte do papel."],
    [/tray\s*1.*retard roller/, "Rolo separador — bandeja 1", "Separa as folhas para evitar que mais de uma seja puxada por vez."],
    [/tray\s*1.*roller/, "Rolo de alimentação — bandeja 1", "Puxa o papel da bandeja principal para dentro da impressora."],
    [/mp.*retard roller|multi.?purpose.*retard roller/, "Rolo separador — bandeja multiuso", "Separa as folhas da bandeja multiuso durante a alimentação."],
    [/mp.*roller|multi.?purpose.*roller/, "Rolo de alimentação — bandeja multiuso", "Puxa papel da bandeja multiuso para dentro da impressora."],
  ];
  const match = known.find(([pattern]) => pattern.test(normalized));
  return match
    ? [match[1], match[2], level]
    : [cleaned || "Suprimento da impressora", "Componente reportado pela impressora via Printer-MIB.", level];
}

const SYSTEM_OIDS: [string, string][] = [
  ["1.3.6.1.2.1.1.5.0", "Nome (sysName)"],
  ["1.3.6.1.2.1.1.1.0", "Descrição (sysDescr)"],
  ["1.3.6.1.2.1.1.3.0", "Ligado há (sysUpTime)"],
  ["1.3.6.1.2.1.1.6.0", "Localização (sysLocation)"],
  ["1.3.6.1.2.1.1.4.0", "Contato (sysContact)"],
  ["1.3.6.1.2.1.1.2.0", "Fabricante/modelo (sysObjectID)"],
];

const IF_OPER_STATUS: Record<string, string> = { "1": "up", "2": "down", "3": "testing", "5": "dormant", "7": "lowerLayerDown" };

/** Executa um walk por coluna de tabela SNMP e junta as colunas pelo índice da linha. */
async function walkTable(target: SnmpTarget, columns: { oid: string; format?: (v: string) => string }[]): Promise<Map<string, string[]>> {
  const table = new Map<string, string[]>();
  for (let col = 0; col < columns.length; col++) {
    const { oid, format } = columns[col];
    for (const vb of await walk(target, oid)) {
      const index = vb.oid.slice(oid.length + 1);
      const row = table.get(index) ?? Array(columns.length).fill("");
      row[col] = format ? format(vb.value) : vb.value;
      table.set(index, row);
    }
  }
  return table;
}

function formatSpeed(bps: string): string {
  const n = Number(bps);
  if (!n) return "—";
  return n >= 1e9 ? `${n / 1e9} Gbps` : n >= 1e6 ? `${n / 1e6} Mbps` : `${n / 1e3} Kbps`;
}

export async function snmpQuery(target: SnmpTarget, mode: SnmpMode, oid?: string): Promise<SnmpTable> {
  switch (mode) {
    case "system": {
      const values = await request(target, PDU_GET, SYSTEM_OIDS.map(([o]) => o));
      return {
        columns: ["Campo", "Valor"],
        rows: SYSTEM_OIDS.map(([o, label]) => {
          const vb = values.find((v) => v.oid === o);
          return [label, vb && !vb.exception ? vb.value || "—" : "—"];
        }),
      };
    }

    case "interfaces": {
      const table = await walkTable(target, [
        { oid: "1.3.6.1.2.1.2.2.1.2" },
        { oid: "1.3.6.1.2.1.2.2.1.6" },
        { oid: "1.3.6.1.2.1.2.2.1.5", format: formatSpeed },
        { oid: "1.3.6.1.2.1.2.2.1.8", format: (v) => IF_OPER_STATUS[v] ?? v },
      ]);
      return {
        columns: ["Índice", "Interface", "MAC", "Velocidade", "Status"],
        rows: Array.from(table, ([index, row]) => [index, ...row]),
      };
    }

    case "printer": {
      // Printer-MIB (RFC 3805): descrição, capacidade máxima e nível atual de cada suprimento.
      const table = await walkTable(target, [
        { oid: "1.3.6.1.2.1.43.11.1.1.6" },
        { oid: "1.3.6.1.2.1.43.11.1.1.8" },
        { oid: "1.3.6.1.2.1.43.11.1.1.9" },
      ]);
      return {
        columns: ["Componente", "Descrição", "Nível restante"],
        rows: Array.from(table.values(), ([desc, max, level]) => {
          const pct = Number(max) > 0 && Number(level) >= 0 ? `${Math.round((Number(level) / Number(max)) * 100)}%` : level;
          return formatPrinterSupply(desc, pct);
        }),
      };
    }

    case "get": {
      if (!oid) throw new Error("Informe o OID.");
      const [vb] = await request(target, PDU_GET, [oid]);
      return { columns: ["OID", "Valor"], rows: [[oid.replace(/^\./, ""), !vb ? "noSuchName" : vb.exception ?? vb.value]] };
    }

    case "walk": {
      if (!oid) throw new Error("Informe o OID raiz.");
      const rows = await walk(target, oid);
      return { columns: ["OID", "Valor"], rows: rows.map((vb) => [vb.oid, vb.value]) };
    }
  }
}
