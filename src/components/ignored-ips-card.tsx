"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { EyeOff, Loader2, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import {
  getIgnoredIpsAction,
  removeDevicesOnIgnoredIpsAction,
  saveIgnoredIpsAction,
} from "@/app/actions/ignored-ip-actions";
import type { ToolResult } from "@/app/actions/tool-actions";
import type { IgnoredIp } from "@/lib/network/ignored-ips";
import { useCan } from "@/components/auth/user-provider";
import { Field } from "@/components/tools/tool-shell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";

async function unwrap<T>(promise: Promise<ToolResult<T>>): Promise<T> {
  const result = await promise;
  if (!result.ok) throw new Error(result.error);
  return result.data;
}

export function IgnoredIpsCard() {
  const canManage = useCan("settings.manage");
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["ignored-ips"], queryFn: () => unwrap(getIgnoredIpsAction()) });
  const list = data?.list ?? [];
  const [pattern, setPattern] = useState("");
  const [note, setNote] = useState("");
  const [confirmRemove, setConfirmRemove] = useState(false);

  const save = useMutation({
    mutationFn: (next: IgnoredIp[]) => unwrap(saveIgnoredIpsAction(next)),
    onSuccess: (state) => {
      queryClient.setQueryData(["ignored-ips"], state);
      toast.success("Lista de IPs ignorados salva. Vale a partir do próximo scan.");
    },
    onError: (err) => toast.error(err.message),
  });

  const remove = useMutation({
    mutationFn: () => unwrap(removeDevicesOnIgnoredIpsAction()),
    onSuccess: ({ removed }) => {
      toast.success(`${removed} dispositivo(s) removido(s) do inventário.`);
      queryClient.invalidateQueries({ queryKey: ["ignored-ips"] });
      queryClient.invalidateQueries({ queryKey: ["devices"] });
      setConfirmRemove(false);
    },
    onError: (err) => toast.error(err.message),
  });

  function add(e: React.FormEvent) {
    e.preventDefault();
    const clean = pattern.trim();
    if (!clean) return;
    if (list.some((entry) => entry.pattern === clean)) {
      toast.error(`${clean} já está na lista.`);
      return;
    }
    save.mutate([...list, { id: crypto.randomUUID(), pattern: clean, note: note.trim() || undefined }]);
    setPattern("");
    setNote("");
  }

  const inInventory = data?.devicesInInventory ?? 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <EyeOff className="h-4 w-4 text-primary" />
          IPs ignorados
        </CardTitle>
        <CardDescription>
          O scan deixa estes endereços de fora: não cadastra, não atualiza e não registra que ficaram offline. Use para aparelhos que não
          respondem de forma confiável e só geram alertas sem sentido.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4 text-sm">
        {canManage && (
          <form onSubmit={add} className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <Field label="IP, faixa ou CIDR" htmlFor="ignored-pattern" className="sm:w-64">
              <Input id="ignored-pattern" value={pattern} onChange={(e) => setPattern(e.target.value)} placeholder="192.168.0.113" className="font-mono" />
            </Field>
            <Field label="Motivo (opcional)" htmlFor="ignored-note" className="sm:flex-1">
              <Input id="ignored-note" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Ex: modem Arcadyan atrás do D-Link" maxLength={120} />
            </Field>
            <Button type="submit" disabled={save.isPending || !pattern.trim()} className="w-fit">
              {save.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
              Ignorar
            </Button>
          </form>
        )}

        {isLoading ? (
          <p className="text-xs text-muted-foreground">Carregando…</p>
        ) : list.length === 0 ? (
          <p className="rounded-md border border-dashed p-4 text-center text-xs text-muted-foreground">Nenhum IP ignorado.</p>
        ) : (
          <ul className="divide-y rounded-md border">
            {list.map((entry) => (
              <li key={entry.id} className="flex items-center justify-between gap-3 px-3 py-2">
                <div className="flex min-w-0 flex-col">
                  <span className="font-mono text-xs font-medium">{entry.pattern}</span>
                  {entry.note && <span className="truncate text-xs text-muted-foreground">{entry.note}</span>}
                </div>
                {canManage && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => save.mutate(list.filter((e) => e.id !== entry.id))}
                    disabled={save.isPending}
                    aria-label={`Parar de ignorar ${entry.pattern}`}
                    className="text-muted-foreground hover:text-destructive"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}

        {inInventory > 0 && (
          <div className="flex flex-col gap-2 rounded-md border border-amber-900 bg-amber-950/40 px-3 py-2 text-xs text-amber-400 sm:flex-row sm:items-center sm:justify-between">
            <span>
              {inInventory === 1 ? "1 dispositivo do inventário está" : `${inInventory} dispositivos do inventário estão`} num IP ignorado. Ele continua
              na lista, só para de ser atualizado.
            </span>
            {canManage && (
              <Button variant="outline" size="sm" className="w-fit shrink-0" onClick={() => setConfirmRemove(true)}>
                Remover do inventário
              </Button>
            )}
          </div>
        )}
      </CardContent>

      <Dialog open={confirmRemove} onOpenChange={(open) => !open && setConfirmRemove(false)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remover {inInventory === 1 ? "1 dispositivo" : `${inInventory} dispositivos`}?</DialogTitle>
            <DialogDescription>
              Some do inventário junto com o histórico de eventos e a posição no mapa. Como o IP está na lista de ignorados, ele não volta no
              próximo scan.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmRemove(false)}>
              Cancelar
            </Button>
            <Button variant="destructive" onClick={() => remove.mutate()} disabled={remove.isPending}>
              {remove.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              Remover
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
