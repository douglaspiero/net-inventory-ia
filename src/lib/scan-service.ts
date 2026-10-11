import { prisma } from "@/lib/prisma";
import { scanNetwork } from "@/lib/network/scanner";
import { classifyDevice } from "@/lib/network/classify";
import { findMatchingRule, getIpRules } from "@/lib/network/ip-rules";
import { getIgnoredIps, isIgnoredIp } from "@/lib/network/ignored-ips";
import { dedupeHostsByMac, hostnamesCompatible, normalizeMac } from "@/lib/device-identity";
import { mergeDuplicateDevices } from "@/lib/device-merge";
import type { Prisma } from "@prisma/client";

export interface ScanResult {
  devicesFound: number;
  newDevices: number;
}

/** Um scan por vez: dois em paralelo (agendado + manual) disputariam a tabela ARP e duplicariam eventos. */
const state = globalThis as typeof globalThis & { __scanRunning?: boolean };

export class ScanInProgressError extends Error {
  constructor() {
    super("Já existe um scan em andamento. Aguarde ele terminar.");
  }
}

export function isScanRunning(): boolean {
  return !!state.__scanRunning;
}

export async function runScanAndPersist(cidr: string): Promise<ScanResult> {
  if (state.__scanRunning) throw new ScanInProgressError();
  state.__scanRunning = true;
  try {
    return await scanAndPersist(cidr);
  } finally {
    state.__scanRunning = false;
  }
}

async function scanAndPersist(cidr: string): Promise<ScanResult> {
  const scanRun = await prisma.scanRun.create({ data: { cidr } });

  try {
    const [rawScanned, allRules, ignored] = await Promise.all([
      scanNetwork(cidr),
      getIpRules().catch(() => []),
      getIgnoredIps().catch(() => []),
    ]);
    // IPs ignorados (Configurações): não entram no inventário nem geram eventos.
    const scanned = rawScanned.filter((h) => !isIgnoredIp(h.ip, ignored));
    const ipRules = allRules.filter((r) => r.enabled);
    const now = new Date();
    const seenDeviceIds = new Set<string>();
    let newDevices = 0;

    // Limpa duplicados antigos antes de casar o scan com o inventário.
    await mergeDuplicateDevices().catch((err) => console.error("[device-merge] falha ao fundir duplicados:", err));

    const known = await prisma.device.findMany({ select: { ip: true, mac: true } });
    const knownIpByMac = new Map(known.flatMap((d) => (d.mac ? [[d.mac, d.ip] as const] : [])));
    // O MAC identifica o aparelho: um host por MAC, e quem tem MAC é casado antes de quem não tem,
    // para que a associação por IP (mais fraca) não "roube" um registro que o MAC vai reivindicar.
    const discovered = dedupeHostsByMac(
      scanned.map((h) => ({ ...h, mac: normalizeMac(h.mac) })),
      knownIpByMac,
    ).sort((a, b) => Number(!a.mac) - Number(!b.mac));

    for (const host of discovered) {
      const existing = await findExistingDevice(host, seenDeviceIds);

      const matchedRule = findMatchingRule(host.ip, ipRules);

      if (!existing) {
        const initialType = matchedRule ? matchedRule.type : host.type;
        const initialLocked = matchedRule ? matchedRule.lock : false;

        const device = await prisma.device.create({
          data: {
            ip: host.ip,
            mac: host.mac,
            ipv6: host.ipv6.join(",") || null,
            hostname: host.hostname,
            vendor: host.vendor,
            type: initialType,
            typeLocked: initialLocked,
            openPorts: host.openPorts.join(","),
            status: "ONLINE",
            firstSeenAt: now,
            lastSeenAt: now,
          },
        });
        await prisma.deviceEvent.create({
          data: {
            deviceId: device.id,
            type: "DEVICE_DISCOVERED",
            message: `Novo dispositivo encontrado na rede (${host.ip})`,
          },
        });
        newDevices++;
        seenDeviceIds.add(device.id);
        continue;
      }

      seenDeviceIds.add(existing.id);
      const updates: Prisma.DeviceUpdateInput = { lastSeenAt: now };
      // Registro visto antes sem MAC: passa a ser identificado por ele.
      if (host.mac && !existing.mac) updates.mac = host.mac;
      const events: Array<{ type: "IP_CHANGED" | "HOSTNAME_CHANGED" | "WENT_ONLINE"; message: string; previousValue?: string | null; newValue?: string | null }> = [];

      if (existing.ip !== host.ip) {
        events.push({
          type: "IP_CHANGED",
          message: `IP mudou de ${existing.ip} para ${host.ip}`,
          previousValue: existing.ip,
          newValue: host.ip,
        });
        updates.ip = host.ip;
      }

      if (host.hostname && existing.hostname !== host.hostname) {
        events.push({
          type: "HOSTNAME_CHANGED",
          message: `Hostname mudou de "${existing.hostname ?? "desconhecido"}" para "${host.hostname}"`,
          previousValue: existing.hostname,
          newValue: host.hostname,
        });
        updates.hostname = host.hostname;
      }

      if (existing.status !== "ONLINE") {
        events.push({ type: "WENT_ONLINE", message: "Dispositivo voltou a ficar online" });
        updates.status = "ONLINE";
      }

      if (host.vendor && existing.vendor !== host.vendor) updates.vendor = host.vendor;
      if (host.openPorts.length) updates.openPorts = host.openPorts.join(",");
      // Só substitui quando o dispositivo respondeu via IPv6 neste scan: aparelhos em repouso
      // (ex: celular com tela apagada) nem sempre respondem, e não queremos apagar o que já sabíamos.
      if (host.ipv6.length && host.ipv6.join(",") !== existing.ipv6) updates.ipv6 = host.ipv6.join(",");
      if (matchedRule) {
        if (!existing.typeLocked || existing.type === "UNKNOWN") {
          updates.type = matchedRule.type;
        }
        if (matchedRule.lock && !existing.typeLocked) {
          updates.typeLocked = true;
        }
      } else {
        let type = classifyDevice({
          ip: host.ip,
          hostname: host.hostname ?? existing.hostname,
          vendor: host.vendor ?? existing.vendor,
          openPorts: host.openPorts,
        });
        if (type === "UNKNOWN" && host.type !== "UNKNOWN") {
          type = host.type;
        }
        // Tipo travado pelo usuário (identificação manual) nunca é alterado pelo scan.
        if (!existing.typeLocked && type !== "UNKNOWN" && existing.type !== type) updates.type = type;
      }

      await prisma.device.update({ where: { id: existing.id }, data: updates });

      for (const event of events) {
        await prisma.deviceEvent.create({ data: { deviceId: existing.id, ...event } });
      }
    }

    const offlineCandidates = await prisma.device.findMany({
      where: { status: "ONLINE", id: { notIn: Array.from(seenDeviceIds) } },
    });

    for (const device of offlineCandidates) {
      // Ainda no inventário mas num IP ignorado: fica como está, sem virar offline a cada scan.
      if (isIgnoredIp(device.ip, ignored)) continue;
      await prisma.device.update({ where: { id: device.id }, data: { status: "OFFLINE" } });
      await prisma.deviceEvent.create({
        data: { deviceId: device.id, type: "WENT_OFFLINE", message: "Dispositivo não respondeu ao scan" },
      });
    }

    await prisma.scanRun.update({
      where: { id: scanRun.id },
      data: {
        status: "COMPLETED",
        devicesFound: discovered.length,
        newDevices,
        finishedAt: new Date(),
      },
    });

    return { devicesFound: discovered.length, newDevices };
  } catch (error) {
    await prisma.scanRun.update({
      where: { id: scanRun.id },
      data: { status: "FAILED", error: String(error), finishedAt: new Date() },
    });
    throw error;
  }
}

/**
 * Acha o registro do inventário que corresponde a um host do scan. Com MAC: o registro com esse MAC;
 * senão, um registro sem MAC no mesmo IP (visto antes do ARP responder), que é adotado. Sem MAC: o
 * registro que está nesse IP, com ou sem MAC, desde que ainda não tenha sido casado neste scan.
 */
async function findExistingDevice(
  host: { ip: string; mac: string | null; hostname: string | null },
  seenDeviceIds: Set<string>,
) {
  if (host.mac) {
    const byMac = await prisma.device.findUnique({ where: { mac: host.mac } });
    if (byMac) return byMac;
  }

  const sameIp = await prisma.device.findMany({
    where: { ip: host.ip, id: { notIn: Array.from(seenDeviceIds) }, ...(host.mac ? { mac: null } : {}) },
    orderBy: { firstSeenAt: "asc" },
  });
  // Sem MAC dos dois lados o IP é a única identidade (como sempre foi); entre registro com e sem MAC,
  // hostnames diferentes indicam aparelhos diferentes.
  const candidates = sameIp.filter((d) => (!d.mac && !host.mac) || hostnamesCompatible(d.hostname, host.hostname));
  // Prefere o registro sem MAC (associação antiga por IP); senão o aparelho visto mais recentemente ali.
  return (
    candidates.find((d) => !d.mac) ??
    [...candidates].sort((a, b) => b.lastSeenAt.getTime() - a.lastSeenAt.getTime())[0] ??
    null
  );
}

export const DEFAULT_CIDR = "192.168.1.0/24";

/** Escaneia a faixa configurada e registra quando rodou (usado pelo botão e pelo agendador). */
export async function runConfiguredScan(): Promise<ScanResult> {
  const config = await prisma.scanConfig.findFirst();
  const cidr = config?.cidr ?? DEFAULT_CIDR;
  const result = await runScanAndPersist(cidr);
  if (config) {
    await prisma.scanConfig.update({ where: { id: config.id }, data: { lastRunAt: new Date() } });
  } else {
    await prisma.scanConfig.create({ data: { cidr, lastRunAt: new Date() } });
  }
  return result;
}
