import { prisma } from "@/lib/prisma";
import { isValidIp, matchesIpPattern } from "./ip-rules";

/**
 * IPs que o scan deve ignorar por completo: não cadastra, não atualiza e não marca como offline.
 * Útil para aparelhos que nunca respondem de forma confiável (ex: um modem atrás de outro roteador)
 * e só geram eventos de "online/offline" sem sentido.
 */
export interface IgnoredIp {
  id: string;
  /** Mesmos formatos das regras de classificação: IP, faixa, CIDR ou curinga. */
  pattern: string;
  note?: string;
}

const SETTING_KEY = "network.ignoredIps";

/** Aceita "192.168.0.50", "192.168.0.10-192.168.0.30", "192.168.0.0/28" e "192.168.0.*". */
export function isValidIpPattern(raw: string): boolean {
  const pattern = raw.trim();
  if (!pattern) return false;
  if (pattern.includes("-")) {
    const parts = pattern.split("-").map((s) => s.trim());
    return parts.length === 2 && parts.every(isValidIp);
  }
  if (pattern.includes("/")) {
    const [base, prefix] = pattern.split("/").map((s) => s.trim());
    return isValidIp(base) && /^\d{1,2}$/.test(prefix) && Number(prefix) <= 32;
  }
  if (pattern.includes("*")) {
    // Curinga só no fim e sobre octetos inteiros: "192.168.0.*", "10.*".
    return /^(\d{1,3}\.){1,3}\*$/.test(pattern) && pattern.slice(0, -2).split(".").every((o) => Number(o) <= 255);
  }
  return isValidIp(pattern);
}

export function isIgnoredIp(ip: string, list: IgnoredIp[]): boolean {
  return list.some((entry) => matchesIpPattern(ip, entry.pattern));
}

export async function getIgnoredIps(): Promise<IgnoredIp[]> {
  const setting = await prisma.appSetting.findUnique({ where: { key: SETTING_KEY } });
  if (!setting?.value) return [];
  try {
    const parsed = JSON.parse(setting.value);
    return Array.isArray(parsed) ? parsed.filter((e) => e && typeof e.pattern === "string") : [];
  } catch {
    return [];
  }
}

export async function saveIgnoredIps(list: IgnoredIp[]): Promise<void> {
  const invalid = list.find((e) => !isValidIpPattern(e.pattern));
  if (invalid) throw new Error(`Padrão de IP inválido: "${invalid.pattern}".`);
  const value = JSON.stringify(list.map((e) => ({ id: e.id, pattern: e.pattern.trim(), ...(e.note?.trim() ? { note: e.note.trim() } : {}) })));
  await prisma.appSetting.upsert({ where: { key: SETTING_KEY }, create: { key: SETTING_KEY, value }, update: { value } });
}

/** Dispositivos já no inventário cujo IP atual está na lista (para o usuário decidir se remove). */
export async function devicesOnIgnoredIps(list: IgnoredIp[]): Promise<{ id: string; ip: string }[]> {
  if (!list.length) return [];
  const devices = await prisma.device.findMany({ select: { id: true, ip: true } });
  return devices.filter((d) => isIgnoredIp(d.ip, list));
}
