"use server";

import net from "node:net";
import { prisma } from "@/lib/prisma";
import { requirePermission, requireSession } from "@/lib/auth/server";
import { decrypt, encrypt } from "@/lib/ai/settings";
import { displayName } from "@/lib/device-name";
import { ALLOWED_INTERVAL_MINUTES } from "@/lib/auto-interval";
import { readEquipmentStatus, type EquipmentStatus } from "@/lib/network/equipment-status";
import { snmpQuery, type SnmpTarget, type SnmpVersion } from "@/lib/network/tools/snmp";
import type { ToolResult } from "./tool-actions";

/** O que vai para o navegador: a community fica no servidor, só se informa se há uma cadastrada. */
export interface EquipmentRow {
  id: string;
  name: string;
  ip: string;
  snmpVersion: EquipmentSnmpVersion;
  credentialsConfigured: boolean;
  snmpAuthProtocol: "md5" | "sha" | null;
  snmpPrivProtocol: "des" | "aes" | null;
  privacyConfigured: boolean;
  notes: string | null;
  /** Leitura automática na página (minutos); null = desligada. */
  pollIntervalMinutes: number | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface EquipmentInput {
  name: string;
  ip: string;
  /** Vazio na edição = manter a community atual. */
  community: string;
  snmpVersion: string;
  snmpUsername: string;
  snmpAuthPassword: string;
  snmpAuthProtocol: string;
  snmpPrivPassword: string;
  snmpPrivProtocol: string;
  notes: string;
}

/** Dispositivo do inventário dono de um MAC aprendido numa porta. */
export interface KnownDevice {
  id: string;
  name: string;
  ip: string;
}

export interface EquipmentDetail extends EquipmentStatus {
  devicesByMac: Record<string, KnownDevice>;
}

export interface ConnectionTest {
  sysName: string | null;
  sysDescr: string | null;
}

export type EquipmentSnmpVersion = SnmpVersion | "3";

const VERSIONS: EquipmentSnmpVersion[] = ["2c", "1", "3"];
const ROW_FIELDS = { id: true, name: true, ip: true, snmpVersion: true, snmpUsername: true, snmpAuthPassword: true, snmpAuthProtocol: true, snmpPrivPassword: true, snmpPrivProtocol: true, notes: true, pollIntervalMinutes: true, createdAt: true, updatedAt: true } as const;
const HOSTNAME_RE = /^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$/;

async function run<T>(fn: () => Promise<T>): Promise<ToolResult<T>> {
  try {
    return { ok: true, data: await fn() };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

function assertHost(host: string): string {
  const v = host.trim();
  if (net.isIP(v) || HOSTNAME_RE.test(v)) return v;
  throw new Error("Endereço inválido. Use um IP (ex: 192.168.0.3) ou um nome de host.");
}

function assertVersion(v: string): EquipmentSnmpVersion {
  if (!VERSIONS.includes(v as EquipmentSnmpVersion)) throw new Error("Versão SNMP não suportada. Use 1, 2c ou 3.");
  return v as EquipmentSnmpVersion;
}

function toRow(e: { snmpVersion: string; snmpUsername: string | null; snmpAuthPassword: string | null; snmpAuthProtocol: string | null; snmpPrivPassword: string | null; snmpPrivProtocol: string | null } & Omit<EquipmentRow, "snmpVersion" | "credentialsConfigured" | "snmpAuthProtocol" | "snmpPrivProtocol" | "privacyConfigured">): EquipmentRow {
  const { snmpUsername, snmpAuthPassword, snmpAuthProtocol, snmpPrivPassword, snmpPrivProtocol, ...safe } = e;
  const credentialsConfigured = e.snmpVersion === "3" ? Boolean(snmpUsername && snmpAuthPassword) : true;
  return {
    ...safe,
    snmpVersion: VERSIONS.includes(e.snmpVersion as EquipmentSnmpVersion) ? e.snmpVersion as EquipmentSnmpVersion : "2c",
    credentialsConfigured,
    snmpAuthProtocol: snmpAuthProtocol === "md5" || snmpAuthProtocol === "sha" ? snmpAuthProtocol : null,
    snmpPrivProtocol: snmpPrivProtocol === "des" || snmpPrivProtocol === "aes" ? snmpPrivProtocol : null,
    privacyConfigured: Boolean(snmpPrivPassword && (snmpPrivProtocol === "des" || snmpPrivProtocol === "aes")),
  };
}

/** Community guardada (criptografada); erro claro quando o AUTH_SECRET mudou e ela não abre mais. */
function openCommunity(stored: string): string {
  const plain = decrypt(stored);
  if (plain === null) throw new Error("Não foi possível ler a community salva (a chave do servidor mudou). Edite o equipamento e informe a community de novo.");
  return plain;
}

function validate(input: EquipmentInput, requireCredentials: boolean) {
  const name = input.name.trim();
  if (!name) throw new Error("Informe um nome para o equipamento.");
  if (name.length > 80) throw new Error("Nome longo demais (máximo 80 caracteres).");
  const snmpVersion = assertVersion(input.snmpVersion);
  const community = input.community.trim();
  const snmpUsername = input.snmpUsername.trim();
  const snmpAuthPassword = input.snmpAuthPassword.trim();
  const snmpAuthProtocol = input.snmpAuthProtocol === "sha" ? "sha" : input.snmpAuthProtocol === "md5" ? "md5" : "";
  const snmpPrivPassword = input.snmpPrivPassword.trim();
  const snmpPrivProtocol = input.snmpPrivProtocol === "none" ? "none" : input.snmpPrivProtocol === "des" || input.snmpPrivProtocol === "aes" ? input.snmpPrivProtocol : "";
  if (snmpVersion !== "3" && requireCredentials && !community) throw new Error("Informe a community SNMP.");
  if (snmpVersion === "3") {
    if (snmpUsername.length > 64) throw new Error("Nome de usuário SNMPv3 longo demais.");
    if (requireCredentials && (!snmpUsername || !snmpAuthPassword)) throw new Error("Informe o usuário e a senha de autenticação SNMPv3.");
    if (snmpAuthPassword && snmpAuthPassword.length < 8) throw new Error("A senha de autenticação SNMPv3 deve ter pelo menos 8 caracteres.");
    if (!snmpAuthProtocol) throw new Error("Escolha o algoritmo de autenticação SNMPv3.");
    if (snmpPrivPassword && snmpPrivPassword.length < 8) throw new Error("A senha de privacidade SNMPv3 deve ter pelo menos 8 caracteres.");
    if (snmpPrivProtocol === "none" && snmpPrivPassword) throw new Error("Remova a senha de privacidade ou selecione DES/AES.");
    if (requireCredentials && (snmpPrivProtocol === "des" || snmpPrivProtocol === "aes") && !snmpPrivPassword) throw new Error("Informe a senha de privacidade SNMPv3.");
    if (!snmpPrivProtocol && snmpPrivPassword) throw new Error("Escolha DES ou AES para usar a senha de privacidade SNMPv3.");
  }
  const notes = input.notes.trim();
  if (notes.length > 1000) throw new Error("Observações longas demais (máximo 1000 caracteres).");
  return { name, ip: assertHost(input.ip), community, snmpVersion, snmpUsername, snmpAuthPassword, snmpAuthProtocol, snmpPrivPassword, snmpPrivProtocol, notes: notes || null };
}

async function assertIpFree(ip: string, exceptId?: string) {
  const other = await prisma.equipment.findUnique({ where: { ip }, select: { id: true, name: true } });
  if (other && other.id !== exceptId) throw new Error(`O endereço ${ip} já está cadastrado como "${other.name}".`);
}

export async function listEquipment(): Promise<ToolResult<EquipmentRow[]>> {
  return run(async () => {
    await requireSession();
    const rows = await prisma.equipment.findMany({ select: ROW_FIELDS, orderBy: { name: "asc" } });
    return rows.map(toRow);
  });
}

export async function createEquipment(input: EquipmentInput): Promise<ToolResult<EquipmentRow>> {
  return run(async () => {
    await requirePermission("inventory.edit");
    const data = validate(input, true);
    await assertIpFree(data.ip);
    const { snmpUsername, snmpAuthPassword, snmpAuthProtocol, snmpPrivPassword, snmpPrivProtocol, ...base } = data;
    const row = await prisma.equipment.create({
      data: {
        ...base,
        community: encrypt(data.snmpVersion === "3" ? "" : data.community),
        snmpUsername: data.snmpVersion === "3" ? encrypt(snmpUsername) : null,
        snmpAuthPassword: data.snmpVersion === "3" ? encrypt(snmpAuthPassword) : null,
        snmpAuthProtocol: data.snmpVersion === "3" ? snmpAuthProtocol : null,
        snmpPrivPassword: data.snmpVersion === "3" && (snmpPrivProtocol === "des" || snmpPrivProtocol === "aes") ? encrypt(snmpPrivPassword) : null,
        snmpPrivProtocol: data.snmpVersion === "3" && (snmpPrivProtocol === "des" || snmpPrivProtocol === "aes") ? snmpPrivProtocol : null,
      },
      select: ROW_FIELDS,
    });
    return toRow(row);
  });
}

export async function updateEquipment(id: string, input: EquipmentInput): Promise<ToolResult<EquipmentRow>> {
  return run(async () => {
    await requirePermission("inventory.edit");
    const existing = await prisma.equipment.findUnique({ where: { id } });
    if (!existing) throw new Error("Equipamento não encontrado.");
    const data = validate(input, false);
    await assertIpFree(data.ip, id);
    const oldWasV3 = existing.snmpVersion === "3";
    const { snmpUsername, snmpAuthPassword, snmpAuthProtocol, snmpPrivPassword, snmpPrivProtocol, community, ...base } = data;
    let encryptedCommunity: string | undefined;
    let encryptedUsername: string | null = null;
    let encryptedAuthPassword: string | null = null;
    let authProtocol: string | null = null;
    let encryptedPrivPassword: string | null = null;
    let privProtocol: string | null = null;
    if (data.snmpVersion === "3") {
      const username = snmpUsername || (oldWasV3 && existing.snmpUsername ? decrypt(existing.snmpUsername) ?? "" : "");
      const password = snmpAuthPassword || (oldWasV3 && existing.snmpAuthPassword ? decrypt(existing.snmpAuthPassword) ?? "" : "");
      if (!username || !password) throw new Error("Informe o usuário e a senha de autenticação SNMPv3.");
      if (password.length < 8) throw new Error("A senha de autenticação SNMPv3 deve ter pelo menos 8 caracteres.");
      const protocol = snmpAuthProtocol || (oldWasV3 ? existing.snmpAuthProtocol ?? "" : "");
      if (protocol !== "md5" && protocol !== "sha") throw new Error("Escolha o algoritmo de autenticação SNMPv3.");
      encryptedUsername = encrypt(username);
      encryptedAuthPassword = snmpAuthPassword ? encrypt(snmpAuthPassword) : existing.snmpAuthPassword;
      authProtocol = protocol;
      privProtocol = snmpPrivProtocol === "none" ? null : snmpPrivProtocol || (oldWasV3 ? existing.snmpPrivProtocol ?? "" : "") || null;
      if (privProtocol) {
        const password = snmpPrivPassword || (oldWasV3 && existing.snmpPrivPassword ? decrypt(existing.snmpPrivPassword) ?? "" : "");
        if (!password) throw new Error("Informe a senha de privacidade SNMPv3.");
        if (password.length < 8) throw new Error("A senha de privacidade SNMPv3 deve ter pelo menos 8 caracteres.");
        encryptedPrivPassword = snmpPrivPassword ? encrypt(snmpPrivPassword) : existing.snmpPrivPassword;
      }
    } else {
      if (community) encryptedCommunity = encrypt(community);
      else if (oldWasV3) throw new Error("Informe a community SNMP para mudar para v1/v2c.");
    }
    const row = await prisma.equipment.update({
      where: { id },
      data: {
        ...base,
        ...(encryptedCommunity ? { community: encryptedCommunity } : {}),
        snmpUsername: encryptedUsername,
        snmpAuthPassword: encryptedAuthPassword,
        snmpAuthProtocol: authProtocol,
        snmpPrivPassword: encryptedPrivPassword,
        snmpPrivProtocol: privProtocol,
      },
      select: ROW_FIELDS,
    });
    return toRow(row);
  });
}

export async function getEquipment(id: string): Promise<ToolResult<EquipmentRow>> {
  return run(async () => {
    await requireSession();
    const row = await prisma.equipment.findUnique({ where: { id }, select: ROW_FIELDS });
    if (!row) throw new Error("Equipamento não encontrado.");
    return toRow(row);
  });
}

export async function deleteEquipment(id: string): Promise<ToolResult<{ id: string }>> {
  return run(async () => {
    await requirePermission("inventory.edit");
    await prisma.equipment.delete({ where: { id } });
    return { id };
  });
}

/** Frequência da leitura automática do equipamento na página; null desliga. */
export async function updateEquipmentPollInterval(id: string, minutes: number | null): Promise<ToolResult<EquipmentRow>> {
  return run(async () => {
    await requirePermission("inventory.edit");
    if (minutes !== null && !ALLOWED_INTERVAL_MINUTES.includes(minutes)) throw new Error("Intervalo inválido.");
    const row = await prisma.equipment.update({ where: { id }, data: { pollIntervalMinutes: minutes }, select: ROW_FIELDS });
    return toRow(row);
  });
}

/**
 * Testa o acesso SNMP antes de salvar. Na edição, community em branco usa a já cadastrada (id).
 * Devolve sysName/sysDescr para o formulário sugerir o nome.
 */
export async function testEquipmentConnection(input: { ip: string; community: string; snmpVersion: string; snmpUsername?: string; snmpAuthPassword?: string; snmpAuthProtocol?: string; snmpPrivPassword?: string; snmpPrivProtocol?: string; id?: string }): Promise<ToolResult<ConnectionTest>> {
  return run(async () => {
    await requirePermission("network.operate");
    const host = assertHost(input.ip);
    const version = assertVersion(input.snmpVersion);
    let target: SnmpTarget;
    if (version === "3") {
      let username = input.snmpUsername?.trim() ?? "";
      let authPassword = input.snmpAuthPassword?.trim() ?? "";
      let authProtocol = input.snmpAuthProtocol === "sha" ? "sha" : input.snmpAuthProtocol === "md5" ? "md5" : "";
      let privacyPassword = input.snmpPrivPassword?.trim() ?? "";
      const explicitlyNoPrivacy = input.snmpPrivProtocol === "none";
      let privacyProtocol = input.snmpPrivProtocol === "des" || input.snmpPrivProtocol === "aes" ? input.snmpPrivProtocol : "";
      if ((!username || !authPassword || !authProtocol || (!privacyPassword && !privacyProtocol)) && input.id) {
        const stored = await prisma.equipment.findUnique({ where: { id: input.id }, select: { snmpVersion: true, snmpUsername: true, snmpAuthPassword: true, snmpAuthProtocol: true, snmpPrivPassword: true, snmpPrivProtocol: true } });
        if (stored?.snmpVersion === "3") {
          username ||= stored.snmpUsername ? decrypt(stored.snmpUsername) ?? "" : "";
          authPassword ||= stored.snmpAuthPassword ? decrypt(stored.snmpAuthPassword) ?? "" : "";
          authProtocol ||= stored.snmpAuthProtocol ?? "";
          if (!explicitlyNoPrivacy) {
            privacyPassword ||= stored.snmpPrivPassword ? decrypt(stored.snmpPrivPassword) ?? "" : "";
            privacyProtocol ||= stored.snmpPrivProtocol ?? "";
          }
        }
      }
      if (!username || !authPassword || (authProtocol !== "md5" && authProtocol !== "sha")) throw new Error("Informe o usuário, a senha de autenticação e o algoritmo SNMPv3.");
      if ((privacyPassword && !privacyProtocol) || (privacyProtocol && !privacyPassword)) throw new Error("Para SNMPv3 com privacidade, informe o algoritmo e a senha de privacidade.");
      target = { host, version: "3", username, authPassword, authProtocol, ...(privacyProtocol ? { privacyProtocol: privacyProtocol as "des" | "aes", privacyPassword } : {}) };
    } else {
      let community = input.community.trim();
      if (!community && input.id) {
        const stored = await prisma.equipment.findUnique({ where: { id: input.id }, select: { community: true } });
        if (stored) community = openCommunity(stored.community);
      }
      if (!community) throw new Error("Informe a community SNMP.");
      target = { host, community, version };
    }
    const sys = await snmpQuery(target, "system");
    const value = (label: string) => {
      const v = sys.rows.find(([l]) => l.startsWith(label))?.[1];
      return v && v !== "—" ? v : null;
    };
    const sysName = value("Nome");
    const sysDescr = value("Descrição");
    if (!sysName && !sysDescr) throw new Error("O equipamento respondeu, mas sem os dados de identificação (system). Confira a community.");
    return { sysName, sysDescr };
  });
}

/** Leitura completa e ao vivo do equipamento cadastrado, com os MACs das portas cruzados com o inventário. */
export async function readEquipmentDetail(id: string): Promise<ToolResult<EquipmentDetail>> {
  return run(async () => {
    await requirePermission("network.operate");
    const eq = await prisma.equipment.findUnique({ where: { id } });
    if (!eq) throw new Error("Equipamento não encontrado. Ele pode ter sido removido.");
    const target: SnmpTarget = eq.snmpVersion === "3"
      ? {
          host: eq.ip,
          version: "3",
          username: eq.snmpUsername ? decrypt(eq.snmpUsername) ?? "" : "",
          authPassword: eq.snmpAuthPassword ? decrypt(eq.snmpAuthPassword) ?? "" : "",
          authProtocol: eq.snmpAuthProtocol === "sha" ? "sha" : "md5",
          ...(eq.snmpPrivProtocol && eq.snmpPrivPassword ? { privacyProtocol: eq.snmpPrivProtocol === "aes" ? "aes" as const : "des" as const, privacyPassword: decrypt(eq.snmpPrivPassword) ?? "" } : {}),
        }
      : { host: eq.ip, community: openCommunity(eq.community), version: eq.snmpVersion === "1" ? "1" : "2c" };
    if (target.version === "3" && (!target.username || !target.authPassword)) throw new Error("As credenciais SNMPv3 estão incompletas ou não puderam ser abertas. Edite o equipamento e informe-as novamente.");
    const status = await readEquipmentStatus(target);

    const macs = Array.from(new Set(status.ports.flatMap((p) => p.learnedMacs)));
    const devices = macs.length
      ? await prisma.device.findMany({ where: { mac: { in: macs } }, select: { id: true, mac: true, ip: true, alias: true, hostname: true } })
      : [];
    const devicesByMac: Record<string, KnownDevice> = {};
    for (const d of devices) if (d.mac) devicesByMac[d.mac] = { id: d.id, name: displayName(d, d.ip), ip: d.ip };
    return { ...status, devicesByMac };
  });
}
