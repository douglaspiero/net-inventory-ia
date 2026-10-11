"use server";

import { revalidatePath } from "next/cache";
import { prisma } from "@/lib/prisma";
import { requirePermission, requireSession } from "@/lib/auth/server";
import { devicesOnIgnoredIps, getIgnoredIps, saveIgnoredIps, type IgnoredIp } from "@/lib/network/ignored-ips";
import type { ToolResult } from "./tool-actions";

async function run<T>(fn: () => Promise<T>): Promise<ToolResult<T>> {
  try {
    return { ok: true, data: await fn() };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

export interface IgnoredIpsState {
  list: IgnoredIp[];
  /** Quantos dispositivos do inventário estão hoje em IPs da lista. */
  devicesInInventory: number;
}

async function state(): Promise<IgnoredIpsState> {
  const list = await getIgnoredIps();
  return { list, devicesInInventory: (await devicesOnIgnoredIps(list)).length };
}

export async function getIgnoredIpsAction(): Promise<ToolResult<IgnoredIpsState>> {
  return run(async () => {
    await requireSession();
    return state();
  });
}

export async function saveIgnoredIpsAction(list: IgnoredIp[]): Promise<ToolResult<IgnoredIpsState>> {
  return run(async () => {
    await requirePermission("settings.manage");
    await saveIgnoredIps(list);
    revalidatePath("/settings");
    return state();
  });
}

/** Remove do inventário (com eventos e posição no mapa) os dispositivos que estão em IPs ignorados. */
export async function removeDevicesOnIgnoredIpsAction(): Promise<ToolResult<{ removed: number }>> {
  return run(async () => {
    await requirePermission("settings.manage");
    const ids = (await devicesOnIgnoredIps(await getIgnoredIps())).map((d) => d.id);
    if (ids.length) {
      await prisma.$transaction([
        prisma.mapPosition.deleteMany({ where: { nodeId: { in: ids } } }),
        prisma.device.deleteMany({ where: { id: { in: ids } } }),
      ]);
    }
    revalidatePath("/");
    revalidatePath("/topology");
    return { removed: ids.length };
  });
}
