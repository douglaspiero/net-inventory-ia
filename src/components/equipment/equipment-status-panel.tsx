"use client";

import { Fragment, type ReactNode } from "react";
import { Loader2, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { parsePortName } from "@/lib/network/port-name";
import type { FanStatus, PortStatus, PsuStatus } from "@/lib/network/equipment-status";
import type { EquipmentDetail, KnownDevice } from "@/app/actions/equipment-actions";
import { PortPopover, formatSpeed, linkLabel } from "./port-popover";

// ---------------------------------------------------------------- estilos de estado

const OK_STYLE = "border-emerald-900 bg-emerald-950 text-emerald-400";
const ERR_STYLE = "border-red-900 bg-red-950 text-red-400";
const UNK_STYLE = "border-amber-900 bg-amber-950 text-amber-400";

function linkStyle(port: PortStatus) {
  if (port.adminStatus === "down") return ERR_STYLE;
  if (port.operStatus === "up") return OK_STYLE;
  if (port.operStatus === "down") return "border-border text-muted-foreground";
  return UNK_STYLE;
}

function entityStyle(ok: boolean, status: string) {
  if (ok) return OK_STYLE;
  if (status === "—") return UNK_STYLE;
  return ERR_STYLE;
}

/**
 * ifInErrors/ifOutErrors acumulam desde que o switch ligou (o `reset counters` da CLI não zera o SNMP),
 * então uma porta em shutdown só carrega erros antigos: ela não recebe nem envia nada e não precisa de atenção.
 */
function portHasErrors(port: PortStatus) {
  if (port.adminStatus === "down") return false;
  return [port.counters.inErrors, port.counters.outErrors].some((v) => v !== null && v !== "0");
}

// ---------------------------------------------------------------- sub-componentes

function MetricItem({ label, value, unit }: { label: string; value: number | null; unit?: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="text-2xl font-semibold tabular-nums">
        {value !== null ? (
          <>
            {value}
            {unit && <span className="ml-0.5 text-sm font-normal text-muted-foreground">{unit}</span>}
          </>
        ) : (
          <span className="text-base font-normal text-muted-foreground">—</span>
        )}
      </span>
    </div>
  );
}

function UnitBadges({ items, label }: { items: (FanStatus | PsuStatus)[]; label: string }) {
  return (
    <div className="flex flex-wrap gap-2">
      {items.map((item) => (
        <Badge key={item.id} variant="outline" className={cn("w-fit gap-1.5 font-normal", entityStyle(item.ok, item.status))}>
          <span className={cn("h-1.5 w-1.5 rounded-full", item.ok ? "bg-emerald-500" : item.status === "—" ? "bg-amber-500" : "bg-red-500")} />
          {label} {item.id} — {item.status}
        </Badge>
      ))}
    </div>
  );
}

/** Número da porta no painel frontal (último número do nome: GE1/0/7 -> 7). */
function portNumber(port: PortStatus): number {
  return parsePortName(port.name)?.numbers.at(-1) ?? port.ifIndex;
}

/** Desenho do painel frontal: ímpares em cima, pares embaixo, em blocos de 12 como no chassi. */
function Faceplate({ ports, devicesByMac }: { ports: PortStatus[]; devicesByMac: Record<string, KnownDevice> }) {
  const blocks: PortStatus[][] = [];
  for (let i = 0; i < ports.length; i += 12) blocks.push(ports.slice(i, i + 12));

  const square = (port: PortStatus) => (
    <PortPopover key={port.name} port={port} devicesByMac={devicesByMac}>
      <button
        type="button"
        aria-label={`Porta ${port.shortName}: ${linkLabel(port)}`}
        className={cn(
          "relative flex h-7 w-8 items-center justify-center rounded-sm border font-mono text-[11px] tabular-nums transition-colors outline-none hover:ring-2 hover:ring-primary/50 focus-visible:ring-2 focus-visible:ring-primary data-popup-open:ring-2 data-popup-open:ring-primary",
          linkStyle(port),
          port.operStatus === "up" && "bg-emerald-500/15",
        )}
      >
        {portNumber(port)}
        {portHasErrors(port) && <span className="absolute -top-1 -right-1 h-2 w-2 rounded-full bg-amber-500" />}
        {port.description && <span className="absolute -bottom-1 left-1/2 h-1 w-3 -translate-x-1/2 rounded-full bg-primary" />}
      </button>
    </PortPopover>
  );

  return (
    <div className="flex flex-col gap-3">
      <div className="overflow-x-auto rounded-md border bg-muted/20 p-3">
        <div className="flex w-fit gap-4">
          {blocks.map((block, b) => (
            <div key={b} className="flex flex-col gap-1.5">
              <div className="flex gap-1.5">{block.filter((_, i) => i % 2 === 0).map(square)}</div>
              <div className="flex gap-1.5">{block.filter((_, i) => i % 2 === 1).map(square)}</div>
            </div>
          ))}
        </div>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm border border-emerald-900 bg-emerald-500/30" /> Link ativo</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm border border-border" /> Sem link</span>
        <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm border border-red-900 bg-red-950" /> Desabilitada</span>
        <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-amber-500" /> Com erros desde que o switch ligou</span>
        <span className="flex items-center gap-1.5"><span className="h-1 w-3 rounded-full bg-primary" /> Com descrição</span>
        <span>Passe o mouse ou clique numa porta para ver tudo sobre ela.</span>
      </div>
    </div>
  );
}

function attachedLabel(port: PortStatus, devicesByMac: Record<string, KnownDevice>): string {
  if (port.neighbor?.sysName) return port.neighbor.sysName;
  if (port.learnedMacCount === 0) return "—";
  const first = port.learnedMacs.map((m) => devicesByMac[m]).find(Boolean);
  if (port.learnedMacCount === 1) return first ? first.name : port.learnedMacs[0];
  return first ? `${first.name} e mais ${port.learnedMacCount - 1}` : `${port.learnedMacCount} MACs`;
}

function PortsTable({ ports, devicesByMac }: { ports: PortStatus[]; devicesByMac: Record<string, KnownDevice> }) {
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Porta</TableHead>
            <TableHead>Link</TableHead>
            <TableHead>Velocidade</TableHead>
            <TableHead>VLAN</TableHead>
            <TableHead>Descrição</TableHead>
            <TableHead>Ligado a</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {ports.map((port) => (
            <TableRow key={port.name}>
              <TableCell>
                <PortPopover port={port} devicesByMac={devicesByMac}>
                  <button type="button" className="font-mono text-xs text-primary underline-offset-4 outline-none hover:underline focus-visible:underline">
                    {port.shortName}
                  </button>
                </PortPopover>
              </TableCell>
              <TableCell>
                <Badge variant="outline" className={cn("w-fit gap-1.5 text-xs font-normal", linkStyle(port))}>
                  <span className={cn("h-1.5 w-1.5 rounded-full", port.operStatus === "up" ? "bg-emerald-500" : port.adminStatus === "down" ? "bg-red-500" : "bg-muted-foreground/50")} />
                  {linkLabel(port)}
                </Badge>
              </TableCell>
              <TableCell className="text-xs text-muted-foreground">
                {formatSpeed(port.speedMbps)}
                {port.speedMbps && port.duplex ? ` · ${port.duplex === "full" ? "full" : "half"}` : ""}
              </TableCell>
              <TableCell className="text-xs text-muted-foreground">{port.pvid ?? "—"}</TableCell>
              <TableCell className="text-xs text-muted-foreground">{port.description ?? "—"}</TableCell>
              <TableCell className="max-w-56 truncate text-xs">{attachedLabel(port, devicesByMac)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

// ---------------------------------------------------------------- painel

export function EquipmentStatusPanel({
  data,
  isFetching,
  onRefresh,
  controls,
}: {
  data: EquipmentDetail;
  isFetching: boolean;
  onRefresh: () => void;
  /** Controles extras ao lado de "Atualizar agora" (a leitura automática). */
  controls?: ReactNode;
}) {
  const readAt = new Date(data.readAt).toLocaleTimeString("pt-BR");
  const up = data.ports.filter((p) => p.operStatus === "up").length;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <p className="text-xs text-muted-foreground">
          {isFetching ? (
            <span className="flex items-center gap-2">
              <Loader2 className="h-3.5 w-3.5 animate-spin" /> Lendo o equipamento…
            </span>
          ) : (
            <>
              Lido às {readAt} · {data.sysName}
              {data.sysLocation ? ` · ${data.sysLocation}` : ""}
            </>
          )}
        </p>
        <div className="flex flex-wrap items-end gap-3">
          {controls}
          <Button variant="outline" size="sm" onClick={onRefresh} disabled={isFetching} className="w-fit gap-2">
            <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} />
            Atualizar agora
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Hardware</CardTitle>
          <CardDescription>{data.sysDescr?.split(/\r?\n/)[0] ?? "Utilização do processador, memória e temperatura do chassi."}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-8">
          <MetricItem label="CPU" value={data.cpuPct} unit="%" />
          <MetricItem label="Memória" value={data.memPct} unit="%" />
          <MetricItem label="Temperatura" value={data.tempC} unit="°C" />
          {data.tempThresholdC !== null && <MetricItem label="Limite" value={data.tempThresholdC} unit="°C" />}
          <div className="flex flex-col gap-0.5">
            <span className="text-xs text-muted-foreground">Ligado há</span>
            <span className="text-base font-medium">{data.uptime}</span>
          </div>
        </CardContent>
      </Card>

      {(data.fans.length > 0 || data.psus.length > 0) && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Ventoinhas e fontes</CardTitle>
            <CardDescription>Estado de cada unidade de arrefecimento e de alimentação.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {data.fans.length > 0 && <UnitBadges items={data.fans} label="Ventoinha" />}
            {data.psus.length > 0 && <UnitBadges items={data.psus} label="Fonte" />}
          </CardContent>
        </Card>
      )}

      {data.printerSupplies.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Suprimentos</CardTitle>
            <CardDescription>Consumíveis e peças de manutenção identificados pela impressora.</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow><TableHead>Componente</TableHead><TableHead>Descrição</TableHead><TableHead>Nível restante</TableHead></TableRow>
              </TableHeader>
              <TableBody>
                {data.printerSupplies.map((supply, index) => (
                  <TableRow key={`${supply.name}-${index}`}>
                    <TableCell className="font-medium">{supply.name || `Componente ${index + 1}`}</TableCell>
                    <TableCell className="text-muted-foreground">{supply.description}</TableCell>
                    <TableCell className="font-mono tabular-nums">{supply.level || "—"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Portas</CardTitle>
          <CardDescription>
            {data.ports.length ? `${up} de ${data.ports.length} portas com link ativo.` : "Nenhuma porta física detectada."}
          </CardDescription>
        </CardHeader>
        {data.ports.length > 0 && (
          <CardContent className="flex flex-col gap-5">
            <Faceplate ports={data.ports} devicesByMac={data.devicesByMac} />
            <PortsTable ports={data.ports} devicesByMac={data.devicesByMac} />
          </CardContent>
        )}
      </Card>

      <HowToRead />
    </div>
  );
}

const SOURCES: [string, string][] = [
  ["CPU, memória e temperatura", "HH3C-ENTITY-EXT-MIB (1.3.6.1.4.1.25506.2.6.1.1.1.1), índice 8 = chassi principal. O limite é o máximo seguro configurado no switch."],
  ["Ventoinhas e fontes", "Tabela de estado HH3C (1.3.6.1.4.1.25506.8.35.9). Estado 2 = Normal; outros valores indicam problema."],
  ["Estado, velocidade, MAC, MTU e contadores", "IF-MIB: ifAdminStatus, ifOperStatus, ifHighSpeed, ifPhysAddress, ifMtu, ifLastChange e os contadores de 64 bits (ifHC*). Os contadores zeram quando o switch reinicia."],
  ["Duplex", "EtherLike-MIB dot3StatsDuplexStatus."],
  ["VLAN e Spanning Tree", "Q-BRIDGE-MIB dot1qPvid (VLAN sem tag da porta), modo access/trunk/hybrid da HH3C-LswVLAN-MIB e BRIDGE-MIB dot1dStpPortState."],
  ["MACs aprendidos", "Tabela de encaminhamento da Q-BRIDGE-MIB, cruzada com o inventário pelo MAC."],
  ["Vizinho LLDP", "LLDP-MIB lldpRemTable: aparece quando o equipamento ligado na porta também anuncia LLDP (switches, APs, telefones IP)."],
];

function HowToRead() {
  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">De onde vêm os dados</CardTitle>
        <CardDescription>Tudo é lido ao vivo via SNMP no momento da consulta; nada é alterado no equipamento.</CardDescription>
      </CardHeader>
      <CardContent>
        <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
          {SOURCES.map(([title, text]) => (
            <Fragment key={title}>
              <dt className="font-medium">{title}</dt>
              <dd className="text-muted-foreground">{text}</dd>
            </Fragment>
          ))}
        </dl>
      </CardContent>
    </Card>
  );
}
