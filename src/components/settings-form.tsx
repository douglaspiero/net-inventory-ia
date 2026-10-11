"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { cleanupEphemeralDevices, countEphemeralDevices } from "@/app/actions/device-actions";
import { Field, SimpleSelect } from "@/components/tools/tool-shell";
import { NotificationSettings } from "@/components/notification-settings";
import { EmailAlertsCard } from "@/components/email-alerts-card";
import { AiSettingsCard } from "@/components/ai/ai-settings-card";
import { IpRulesCard } from "@/components/ip-rules-card";
import { IgnoredIpsCard } from "@/components/ignored-ips-card";
import { useCan } from "@/components/auth/user-provider";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useScanConfig, useScanRuns, useUpdateScanConfig } from "@/hooks/use-devices";
import { AUTO_INTERVALS, intervalKey, intervalMinutes, type AutoIntervalKey } from "@/lib/auto-interval";
import { formatDateTime } from "@/lib/format-time";
import { MAX_SCAN_HOSTS, MIN_SCAN_PREFIX, parseScanCidr } from "@/lib/network/subnet";

const CLEANUP_DAYS = { "1": "1 dia", "7": "7 dias", "30": "30 dias" };
type CleanupKey = keyof typeof CLEANUP_DAYS;

const count = (n: number) => n.toLocaleString("pt-BR");

/** Resumo, recalculado a cada tecla, do que o CIDR digitado vai escanear. */
function describeScanRange(cidr: string): { text: string; error: boolean } {
  if (!cidr.trim()) {
    return { text: `Ex: 192.168.1.0/24 escaneia 254 endereços, de 192.168.1.1 a 192.168.1.254. Aceita de /${MIN_SCAN_PREFIX} (${count(MAX_SCAN_HOSTS)} endereços) a /32 (1 endereço).`, error: false };
  }
  try {
    const info = parseScanCidr(cidr);
    const network = info.baseAdjusted ? ` Endereço de rede: ${info.network}/${info.prefix}.` : "";
    if (info.hostCount === 1) return { text: `Escaneia 1 endereço: ${info.firstHost}.${network}`, error: false };
    const details = info.broadcast === null ? "enlace ponto a ponto, RFC 3021" : `máscara ${info.mask}, broadcast ${info.broadcast}`;
    return {
      text: `Escaneia ${count(info.hostCount)} endereços, de ${info.firstHost} a ${info.lastHost} (${details}).${network}`,
      error: false,
    };
  } catch (err) {
    return { text: (err as Error).message, error: true };
  }
}

function EphemeralCleanup() {
  const queryClient = useQueryClient();
  const [days, setDays] = useState<CleanupKey>("7");
  const { data: count } = useQuery({ queryKey: ["ephemeral-count", days], queryFn: () => countEphemeralDevices(Number(days)) });
  const cleanup = useMutation({
    mutationFn: () => cleanupEphemeralDevices(Number(days)),
    onSuccess: (removed) => {
      toast.success(`${removed} dispositivo(s) efêmero(s) removido(s)`);
      queryClient.invalidateQueries({ queryKey: ["devices"] });
      queryClient.invalidateQueries({ queryKey: ["ephemeral-count"] });
    },
    onError: (err) => toast.error(err.message),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Limpar dispositivos efêmeros</CardTitle>
        <CardDescription>
          Celulares trocam de MAC por privacidade e reaparecem como &ldquo;novos&rdquo; dispositivos. Remove os registros antigos: MAC aleatório,
          offline há mais do período escolhido e sem apelido (dispositivos que você nomeou nunca são removidos).
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <Field label="Offline há mais de" htmlFor="cleanup-days">
          <SimpleSelect id="cleanup-days" value={days} onChange={setDays} options={CLEANUP_DAYS} className="sm:w-36" />
        </Field>
        <Button variant="outline" onClick={() => cleanup.mutate()} disabled={!count || cleanup.isPending} className="w-fit">
          {cleanup.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
          {count ? `Remover ${count} dispositivo(s)` : "Nada para remover"}
        </Button>
      </CardContent>
    </Card>
  );
}

export function SettingsForm() {
  const canManage = useCan("settings.manage");
  const { data: config, isLoading } = useScanConfig();
  const { data: runs } = useScanRuns();
  const { mutate, isPending } = useUpdateScanConfig();
  const [cidr, setCidr] = useState("");
  const [scanInterval, setScanInterval] = useState<AutoIntervalKey>("off");
  const range = describeScanRange(cidr);

  useEffect(() => {
    if (config?.cidr) setCidr(config.cidr);
    if (config) setScanInterval(intervalKey(config.intervalMinutes));
  }, [config]);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    mutate(
      { cidr, intervalMinutes: intervalMinutes(scanInterval) },
      {
        onSuccess: () => toast.success("Configuração salva"),
        onError: () => toast.error("Não foi possível salvar a configuração"),
      },
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Scan da rede</CardTitle>
          <CardDescription>Faixa escaneada e frequência do scan automático (roda no servidor, mesmo com o app fechado).</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="flex flex-col gap-3">
            <fieldset disabled={!canManage} className="flex flex-col gap-3 sm:flex-row sm:items-end">
              <Field label="Faixa de IP (CIDR)" htmlFor="cidr">
                <Input
                  id="cidr"
                  placeholder="192.168.1.0/24"
                  value={cidr}
                  onChange={(e) => setCidr(e.target.value)}
                  disabled={isLoading}
                  aria-invalid={range.error || undefined}
                  aria-describedby="cidr-range"
                  className="sm:w-56"
                />
              </Field>
              <Field label="Scan automático" htmlFor="interval">
                <SimpleSelect id="interval" value={scanInterval} onChange={setScanInterval} options={AUTO_INTERVALS} className="sm:w-52" />
              </Field>
              {canManage && (
                <Button type="submit" disabled={isPending || !cidr || range.error} className="w-fit">
                  Salvar
                </Button>
              )}
            </fieldset>
            <p id="cidr-range" aria-live="polite" className="text-xs text-muted-foreground">
              <span className={range.error ? "text-destructive" : undefined}>{range.text}</span>
              {config?.lastRunAt && ` Último scan: ${formatDateTime(config.lastRunAt)}.`}
              {!canManage && " Somente administradores alteram esta configuração."}
            </p>
          </form>
        </CardContent>
      </Card>

      <IpRulesCard />

      <IgnoredIpsCard />

      <NotificationSettings />

      {/* Alertas por e-mail, chave da IA e limpeza do inventário: só administradores. */}
      {canManage && <EmailAlertsCard />}

      {canManage && <AiSettingsCard />}

      {canManage && <EphemeralCleanup />}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Histórico de scans</CardTitle>
        </CardHeader>
        <CardContent>
          {!runs?.length && <p className="text-sm text-muted-foreground">Nenhum scan executado ainda.</p>}
          {!!runs?.length && (
            <ul className="flex flex-col gap-2 text-sm">
              {runs.map((run) => (
                <li key={run.id} className="flex items-center justify-between rounded-md border px-3 py-2">
                  <span className="font-mono text-xs text-muted-foreground">{run.cidr}</span>
                  <span>
                    {run.devicesFound} dispositivo(s), {run.newDevices} novo(s)
                  </span>
                  <span
                    className={
                      run.status === "COMPLETED" ? "text-emerald-600" : run.status === "FAILED" ? "text-destructive" : "text-amber-600"
                    }
                  >
                    {run.status}
                  </span>
                  <span className="text-xs text-muted-foreground">{formatDateTime(run.startedAt)}</span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
