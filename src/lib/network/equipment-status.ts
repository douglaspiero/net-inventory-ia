import { snmpGetMany, snmpQuery, type SnmpTarget, type SnmpVersion } from "./tools/snmp";
import { mapWithConcurrency } from "./concurrency";
import { macFromOidSuffix, shortPortName } from "./switch-fdb";

// HH3C-ENTITY-EXT-MIB — OIDs testados na HP V1910-24G (Comware 5)
const OID_CPU       = "1.3.6.1.4.1.25506.2.6.1.1.1.1.6.8";
const OID_MEM       = "1.3.6.1.4.1.25506.2.6.1.1.1.1.8.8";
const OID_TEMP      = "1.3.6.1.4.1.25506.2.6.1.1.1.1.12.8";
const OID_TEMP_TH   = "1.3.6.1.4.1.25506.2.6.1.1.1.1.13.8";

// HH3C Device Fan/PSU MIB
const OID_FAN_ROOT  = "1.3.6.1.4.1.25506.8.35.9.1.1.1";
const OID_PSU_ROOT  = "1.3.6.1.4.1.25506.8.35.9.1.2.1";

// RFC standard MIBs
const OID_UPTIME    = "1.3.6.1.2.1.1.3.0";
const OID_SYSNAME   = "1.3.6.1.2.1.1.5.0";
const OID_SYSDESCR  = "1.3.6.1.2.1.1.1.0";
const OID_SYSLOC    = "1.3.6.1.2.1.1.6.0";

// Colunas por interface (IF-MIB, EtherLike-MIB, BRIDGE/Q-BRIDGE-MIB, HH3C-LswVLAN-MIB, LLDP-MIB).
// Todas indexadas por ifIndex, exceto as da bridge (porta da bridge) e as do LLDP (porta LLDP local).
const IF_COLUMNS = {
  name:        "1.3.6.1.2.1.31.1.1.1.1",   // ifName
  type:        "1.3.6.1.2.1.2.2.1.3",      // ifType
  mtu:         "1.3.6.1.2.1.2.2.1.4",      // ifMtu
  mac:         "1.3.6.1.2.1.2.2.1.6",      // ifPhysAddress
  admin:       "1.3.6.1.2.1.2.2.1.7",      // ifAdminStatus
  oper:        "1.3.6.1.2.1.2.2.1.8",      // ifOperStatus
  lastChange:  "1.3.6.1.2.1.2.2.1.9",      // ifLastChange (sysUpTime no momento da mudança)
  inDiscards:  "1.3.6.1.2.1.2.2.1.13",
  inErrors:    "1.3.6.1.2.1.2.2.1.14",
  outDiscards: "1.3.6.1.2.1.2.2.1.19",
  outErrors:   "1.3.6.1.2.1.2.2.1.20",
  inOctets:    "1.3.6.1.2.1.31.1.1.1.6",   // ifHCInOctets (64 bits)
  inUcast:     "1.3.6.1.2.1.31.1.1.1.7",
  inMcast:     "1.3.6.1.2.1.31.1.1.1.8",
  inBcast:     "1.3.6.1.2.1.31.1.1.1.9",
  outOctets:   "1.3.6.1.2.1.31.1.1.1.10",
  outUcast:    "1.3.6.1.2.1.31.1.1.1.11",
  outMcast:    "1.3.6.1.2.1.31.1.1.1.12",
  outBcast:    "1.3.6.1.2.1.31.1.1.1.13",
  speed:       "1.3.6.1.2.1.31.1.1.1.15",  // ifHighSpeed (Mbps)
  connector:   "1.3.6.1.2.1.31.1.1.1.17",  // ifConnectorPresent
  alias:       "1.3.6.1.2.1.31.1.1.1.18",  // ifAlias (descrição configurada)
  duplex:      "1.3.6.1.2.1.10.7.2.1.19",  // dot3StatsDuplexStatus
  vlanType:    "1.3.6.1.4.1.25506.8.35.1.1.1.5", // hh3cifVLANType
} as const;

const OID_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2";   // dot1dBasePortIfIndex
const OID_PVID              = "1.3.6.1.2.1.17.7.1.4.5.1.1"; // dot1qPvid
const OID_STP_STATE         = "1.3.6.1.2.1.17.2.15.1.3";   // dot1dStpPortState
const OID_VLAN_NAME         = "1.3.6.1.2.1.17.7.1.4.3.1.1"; // dot1qVlanStaticName
// Tabela de MACs aprendidos: Q-BRIDGE (switches com VLAN, ex: Comware) e BRIDGE-MIB clássica.
const OID_FDB               = ["1.3.6.1.2.1.17.7.1.2.2.1.2", "1.3.6.1.2.1.17.4.3.1.2"];

const OID_LLDP_LOC_PORT_ID  = "1.0.8802.1.1.2.1.3.7.1.3";
const LLDP_REM = {
  chassisId: "1.0.8802.1.1.2.1.4.1.1.5",
  portId:    "1.0.8802.1.1.2.1.4.1.1.7",
  portDesc:  "1.0.8802.1.1.2.1.4.1.1.8",
  sysName:   "1.0.8802.1.1.2.1.4.1.1.9",
  sysDesc:   "1.0.8802.1.1.2.1.4.1.1.10",
} as const;

// hh3cEntityExtStateTable: 1=notSupported, 2=normal, 3=prefailure, 4=failure, 5=powerOff, 6=present, 7=absent
const ENTITY_STATE: Record<string, string> = {
  "1": "—", "2": "Normal", "3": "Pré-falha", "4": "Falha", "5": "Desligado", "6": "Presente", "7": "Ausente",
};

const IF_STATUS: Record<string, string> = {
  "1": "up", "2": "down", "3": "testing", "4": "unknown", "5": "dormant", "6": "notPresent", "7": "lowerLayerDown",
};

const DUPLEX: Record<string, PortStatus["duplex"]> = { "2": "half", "3": "full" };
const VLAN_TYPE: Record<string, PortStatus["linkType"]> = { "1": "trunk", "2": "access", "3": "hybrid" };
const STP_STATE: Record<string, string> = {
  "1": "Desabilitado", "2": "Bloqueando", "3": "Escutando", "4": "Aprendendo", "5": "Encaminhando", "6": "Com defeito",
};

// Portas físicas: GE, XGE, FE, Eth — exclui Vlan-interface, NULL, InLoopBack, MGE, M-GE
const RE_PHYSICAL = /^(GigabitEthernet|Ten-?GigabitEthernet|FastEthernet|Ethernet)\d/i;

/** Quantos MACs aprendidos guardar por porta (o uplink aprende a rede inteira). */
const MAX_MACS_PER_PORT = 50;

export interface FanStatus { id: string; status: string; ok: boolean }
export interface PsuStatus { id: string; status: string; ok: boolean }

export interface LldpNeighbor {
  sysName: string | null;
  sysDesc: string | null;
  chassisId: string | null;
  portId: string | null;
  portDesc: string | null;
}

export interface PortCounters {
  /** Contadores de 64 bits como string (podem passar de Number.MAX_SAFE_INTEGER). */
  inOctets: string | null;
  outOctets: string | null;
  inUcast: string | null;
  outUcast: string | null;
  inMcast: string | null;
  outMcast: string | null;
  inBcast: string | null;
  outBcast: string | null;
  inErrors: string | null;
  outErrors: string | null;
  inDiscards: string | null;
  outDiscards: string | null;
}

export interface PortStatus {
  ifIndex: number;
  name: string;
  shortName: string;
  adminStatus: string;
  operStatus: string;
  speedMbps: number | null;
  duplex: "full" | "half" | null;
  /** ifAlias configurado; null quando é o texto padrão do Comware ("GigabitEthernet1/0/2 Interface"). */
  description: string | null;
  mac: string | null;
  mtu: number | null;
  ifType: number | null;
  connectorPresent: boolean | null;
  linkType: "access" | "trunk" | "hybrid" | null;
  pvid: number | null;
  vlanName: string | null;
  stpState: string | null;
  /** Minutos desde a última mudança de estado; null quando mudou antes do agente SNMP subir. */
  lastChangeMinutesAgo: number | null;
  counters: PortCounters;
  neighbor: LldpNeighbor | null;
  /** MACs aprendidos nesta porta (até MAX_MACS_PER_PORT) e o total. */
  learnedMacs: string[];
  learnedMacCount: number;
}

export interface EquipmentStatus {
  sysName: string;
  sysDescr: string | null;
  sysLocation: string | null;
  uptime: string;
  cpuPct: number | null;
  memPct: number | null;
  tempC: number | null;
  tempThresholdC: number | null;
  fans: FanStatus[];
  psus: PsuStatus[];
  ports: PortStatus[];
  printerSupplies: PrinterSupply[];
  readAt: string;
}

export interface PrinterSupply {
  name: string;
  description: string;
  level: string;
}

type Rows = string[][];

function isMissing(v: string | undefined): boolean {
  return !v || ["noSuchName", "noSuchObject", "noSuchInstance"].includes(v);
}


function walkToMap(rows: Rows, root: string): Map<string, string> {
  const map = new Map<string, string>();
  const prefix = root.replace(/^\./, "") + ".";
  for (const [oid, val] of rows) {
    const suffix = oid.startsWith(prefix) ? oid.slice(prefix.length) : oid;
    map.set(suffix, val);
  }
  return map;
}

/** "11d 19h 50m" (TimeTicks já formatado pelo cliente SNMP) -> minutos. */
export function ticksTextToMinutes(text: string | null | undefined): number | null {
  const m = /^(\d+)d (\d+)h (\d+)m$/.exec(text ?? "");
  return m ? Number(m[1]) * 1440 + Number(m[2]) * 60 + Number(m[3]) : null;
}

/** O Comware preenche o ifAlias com "<nome> Interface" quando ninguém configurou descrição. */
export function configuredDescription(alias: string | undefined, name: string): string | null {
  const v = alias?.trim();
  if (!v || v === `${name} Interface` || v === name) return null;
  return v;
}

const num = (v: string | undefined) => (v === undefined || v === "" || Number.isNaN(Number(v)) ? null : Number(v));
const str = (v: string | undefined) => (v === undefined || v === "" ? null : v);

export interface HealthMetrics {
  cpuPct: number | null;
  memPct: number | null;
  tempC: number | null;
  /** sysUpTime, em minutos. */
  uptimeMin: number | null;
}

/** Só CPU, memória, temperatura e uptime, num único GET: leve o bastante para os alertas consultarem a cada minuto. */
export async function readHealthMetrics(target: SnmpTarget): Promise<HealthMetrics>;
export async function readHealthMetrics(ip: string, community: string, version?: SnmpVersion): Promise<HealthMetrics>;
export async function readHealthMetrics(targetOrIp: SnmpTarget | string, community?: string, version: SnmpVersion = "2c"): Promise<HealthMetrics> {
  const target: SnmpTarget = typeof targetOrIp === "string" ? { host: targetOrIp, community: community ?? "public", version } : targetOrIp;
  const values = await snmpGetMany(target, [OID_CPU, OID_MEM, OID_TEMP, OID_UPTIME]);
  const read = (oid: string) => (isMissing(values.get(oid)) ? null : num(values.get(oid)));
  const uptime = values.get(OID_UPTIME);
  return { cpuPct: read(OID_CPU), memPct: read(OID_MEM), tempC: read(OID_TEMP), uptimeMin: isMissing(uptime) ? null : ticksTextToMinutes(uptime) };
}

export async function readEquipmentStatus(target: SnmpTarget): Promise<EquipmentStatus> {
  const ip = target.host;
  const empty = { columns: [] as string[], rows: [] as Rows };
  const w = (oid: string) => snmpQuery(target, "walk", oid).catch(() => empty);

  // Primeiro uma consulta simples: se o equipamento não responde, falha rápido com a mensagem do cliente SNMP
  // em vez de esperar o timeout de várias consultas.
  const identityOids = [OID_SYSNAME, OID_UPTIME, OID_SYSDESCR, OID_SYSLOC];
  const scalars = await snmpGetMany(target, identityOids);
  if (!scalars.size) throw new Error(`O equipamento ${ip} respondeu, mas não forneceu os dados básicos (system). Confira a versão e as credenciais SNMP.`);
  const scalar = (oid: string) => (isMissing(scalars.get(oid)) ? null : scalars.get(oid)!);
  const sysDescr = scalar(OID_SYSDESCR);

  // Impressoras expõem principalmente system + Printer-MIB; não consultamos MIBs de chassi/switch nelas.
  if (/printer|laser|samsung.*m\s?-?4070/i.test(sysDescr ?? "")) {
    const printerRows = (await snmpQuery(target, "printer").catch(() => ({ columns: [], rows: [] }))).rows;
    const printerSupplies = printerRows.map(([name, description, level]) => ({ name, description, level }));
    return {
      sysName: scalar(OID_SYSNAME) ?? "—", sysDescr, sysLocation: scalar(OID_SYSLOC), uptime: scalar(OID_UPTIME) ?? "—",
      cpuPct: null, memPct: null, tempC: null, tempThresholdC: null, fans: [], psus: [], ports: [],
      printerSupplies, readAt: new Date().toISOString(),
    };
  }

  const healthValues = await snmpGetMany(target, [OID_CPU, OID_MEM, OID_TEMP, OID_TEMP_TH]);
  for (const [oid, value] of healthValues) scalars.set(oid, value);

  // Tabelas esparsas ou de tamanho desconhecido vão por walk; o agente atende um pacote por vez, então
  // rodar em paralelo não acelera — só a sequência fica mais curta.
  const walks = [
    IF_COLUMNS.name, OID_FAN_ROOT, OID_PSU_ROOT, OID_BASE_PORT_IFINDEX, OID_VLAN_NAME,
    OID_LLDP_LOC_PORT_ID, ...Object.values(LLDP_REM),
  ];
  const walkResults = await mapWithConcurrency(walks, 4, w);
  const walked = (oid: string) => walkToMap(walkResults[walks.indexOf(oid)].rows, oid);

  // hh3cEntityExtStateTable devolve 1 (notSupported) em modelos sem ventoinha/fonte monitorável (ex: V1910-24G).
  const units = (oid: string) =>
    Array.from(walked(oid)).filter(([, v]) => v !== "1").map(([id, v]) => ({ id, status: ENTITY_STATE[v] ?? v, ok: v === "2" }));
  const fans: FanStatus[] = units(OID_FAN_ROOT);
  const psus: PsuStatus[] = units(OID_PSU_ROOT);

  const names = walked(IF_COLUMNS.name);
  const physical = Array.from(names.entries())
    .filter(([, name]) => RE_PHYSICAL.test(name))
    .sort(([a], [b]) => Number(a) - Number(b));

  // Porta da bridge -> ifIndex (PVID e STP são indexados pela porta da bridge).
  const bridgeToIf = walked(OID_BASE_PORT_IFINDEX);
  const ifToBridge = new Map(Array.from(bridgeToIf, ([bridge, ifIndex]) => [ifIndex, bridge]));
  const vlanNames = walked(OID_VLAN_NAME);

  // Todas as colunas das portas físicas num GET agrupado por porta, em vez de um walk por coluna.
  const columns = Object.entries(IF_COLUMNS).filter(([k]) => k !== "name") as [keyof typeof IF_COLUMNS, string][];
  const perPortOids = physical.flatMap(([idx]) => {
    const bridge = ifToBridge.get(idx);
    return [
      ...columns.map(([, oid]) => `${oid}.${idx}`),
      ...(bridge ? [`${OID_PVID}.${bridge}`, `${OID_STP_STATE}.${bridge}`] : []),
    ];
  });
  const values = await snmpGetMany(target, perPortOids);
  const colValue = (key: keyof typeof IF_COLUMNS, idx: string) => values.get(`${IF_COLUMNS[key]}.${idx}`);

  // LLDP: porta local LLDP -> ifIndex pelo nome (lldpLocPortId = nome da interface no Comware); se não
  // casar, assume que o número da porta LLDP é o ifIndex.
  const ifByName = new Map(Array.from(names, ([idx, name]) => [name, idx]));
  const lldpPortToIf = new Map<string, string>();
  for (const [portNum, portId] of walked(OID_LLDP_LOC_PORT_ID)) lldpPortToIf.set(portNum, ifByName.get(portId) ?? portNum);
  const neighbors = new Map<string, LldpNeighbor>();
  for (const field of Object.keys(LLDP_REM) as (keyof typeof LLDP_REM)[]) {
    for (const [suffix, value] of walked(LLDP_REM[field])) {
      // Índice: timeMark.localPortNum.remIndex — fica só o primeiro vizinho de cada porta.
      const [, portNum] = suffix.split(".");
      if (!portNum) continue;
      const ifIndex = lldpPortToIf.get(portNum) ?? portNum;
      const n = neighbors.get(ifIndex) ?? { sysName: null, sysDesc: null, chassisId: null, portId: null, portDesc: null };
      if (n[field] === null && value) n[field] = value;
      neighbors.set(ifIndex, n);
    }
  }

  const learned = await readLearnedMacs(w, bridgeToIf);
  const uptimeText = scalar(OID_UPTIME);
  const uptimeMin = ticksTextToMinutes(uptimeText);

  const ports: PortStatus[] = physical.map(([idx, name]) => {
    const bridge = ifToBridge.get(idx);
    const pvid = bridge ? num(values.get(`${OID_PVID}.${bridge}`)) : null;
    const changedAt = ticksTextToMinutes(colValue("lastChange", idx));
    const macs = learned.get(idx) ?? [];
    const speed = num(colValue("speed", idx));
    const connector = colValue("connector", idx);
    const admin = colValue("admin", idx) ?? "";
    const oper = colValue("oper", idx) ?? "";
    const counter = (key: keyof typeof IF_COLUMNS) => str(colValue(key, idx));
    return {
      ifIndex: Number(idx),
      name,
      shortName: shortPortName(name),
      adminStatus: IF_STATUS[admin] ?? admin,
      operStatus: IF_STATUS[oper] ?? oper,
      speedMbps: speed || null,
      duplex: DUPLEX[colValue("duplex", idx) ?? ""] ?? null,
      description: configuredDescription(colValue("alias", idx), name),
      mac: str(colValue("mac", idx)),
      mtu: num(colValue("mtu", idx)),
      ifType: num(colValue("type", idx)),
      connectorPresent: connector === "1" ? true : connector === "2" ? false : null,
      linkType: VLAN_TYPE[colValue("vlanType", idx) ?? ""] ?? null,
      pvid,
      vlanName: pvid !== null ? str(vlanNames.get(String(pvid))) : null,
      stpState: bridge ? STP_STATE[values.get(`${OID_STP_STATE}.${bridge}`) ?? ""] ?? null : null,
      lastChangeMinutesAgo: uptimeMin !== null && changedAt ? Math.max(0, uptimeMin - changedAt) : null,
      counters: {
        inOctets: counter("inOctets"),
        outOctets: counter("outOctets"),
        inUcast: counter("inUcast"),
        outUcast: counter("outUcast"),
        inMcast: counter("inMcast"),
        outMcast: counter("outMcast"),
        inBcast: counter("inBcast"),
        outBcast: counter("outBcast"),
        inErrors: counter("inErrors"),
        outErrors: counter("outErrors"),
        inDiscards: counter("inDiscards"),
        outDiscards: counter("outDiscards"),
      },
      neighbor: neighbors.get(idx) ?? null,
      learnedMacs: macs.slice(0, MAX_MACS_PER_PORT),
      learnedMacCount: macs.length,
    };
  });

  const printerSupplies: PrinterSupply[] = [];

  const cpu = scalar(OID_CPU);
  const mem = scalar(OID_MEM);
  const tmp = scalar(OID_TEMP);
  const tth = scalar(OID_TEMP_TH);

  return {
    sysName: scalar(OID_SYSNAME) ?? "—",
    sysDescr: scalar(OID_SYSDESCR),
    sysLocation: scalar(OID_SYSLOC),
    uptime: uptimeText ?? "—",
    cpuPct: cpu !== null ? Number(cpu) : null,
    memPct: mem !== null ? Number(mem) : null,
    tempC: tmp !== null ? Number(tmp) : null,
    tempThresholdC: tth !== null ? Number(tth) : null,
    fans,
    psus,
    ports,
    printerSupplies,
    readAt: new Date().toISOString(),
  };
}

/** ifIndex -> MACs aprendidos naquela porta (sem repetir o mesmo MAC visto em VLANs diferentes). */
async function readLearnedMacs(
  w: (oid: string) => Promise<{ rows: Rows }>,
  bridgeToIf: Map<string, string>,
): Promise<Map<string, string[]>> {
  const byIf = new Map<string, string[]>();
  for (const oid of OID_FDB) {
    // Porta 0 = o próprio MAC do equipamento (ou entrada sem porta), não um dispositivo pendurado.
    const rows = (await w(oid)).rows.filter(([, port]) => port && port !== "0");
    if (!rows.length) continue;
    const seen = new Set<string>();
    for (const [rowOid, port] of rows) {
      const mac = macFromOidSuffix(rowOid);
      const ifIndex = bridgeToIf.get(port) ?? port;
      if (seen.has(`${mac}|${ifIndex}`)) continue;
      seen.add(`${mac}|${ifIndex}`);
      byIf.set(ifIndex, [...(byIf.get(ifIndex) ?? []), mac]);
    }
    break;
  }
  return byIf;
}
