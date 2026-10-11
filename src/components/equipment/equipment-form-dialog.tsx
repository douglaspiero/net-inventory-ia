"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, Loader2, PlugZap } from "lucide-react";
import { toast } from "sonner";
import {
  createEquipment,
  testEquipmentConnection,
  updateEquipment,
  type EquipmentInput,
  type EquipmentRow,
  type EquipmentSnmpVersion,
} from "@/app/actions/equipment-actions";
import type { ToolResult } from "@/app/actions/tool-actions";
import { useCan } from "@/components/auth/user-provider";
import { Field, SimpleSelect } from "@/components/tools/tool-shell";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";

const VERSION_OPTIONS = { "2c": "v2c", "1": "v1", "3": "v3 (autenticação e privacidade opcionais)" } as const;
const AUTH_OPTIONS = { md5: "MD5", sha: "SHA" } as const;
const PRIVACY_OPTIONS = { none: "Sem privacidade", des: "DES", aes: "AES" } as const;
type Version = EquipmentSnmpVersion;

/** Executa uma action que devolve ToolResult e transforma { ok: false } em erro para o useMutation. */
async function unwrap<T>(promise: Promise<ToolResult<T>>): Promise<T> {
  const result = await promise;
  if (!result.ok) throw new Error(result.error);
  return result.data;
}

/**
 * Formulário de cadastro e edição. `editing` null + open = novo equipamento. Na edição a community fica
 * em branco: o servidor não devolve a atual, e deixar vazio mantém a que está salva.
 */
export function EquipmentFormDialog({
  open,
  editing,
  onClose,
  onSaved,
}: {
  open: boolean;
  editing: EquipmentRow | null;
  onClose: () => void;
  onSaved: (row: EquipmentRow) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-lg">
        {/* key: remonta o formulário a cada abertura para começar com os valores certos */}
        {open && <EquipmentForm key={editing?.id ?? "new"} editing={editing} onClose={onClose} onSaved={onSaved} />}
      </DialogContent>
    </Dialog>
  );
}

function EquipmentForm({ editing, onClose, onSaved }: { editing: EquipmentRow | null; onClose: () => void; onSaved: (row: EquipmentRow) => void }) {
  const queryClient = useQueryClient();
  const canTest = useCan("network.operate");
  const [name, setName] = useState(editing?.name ?? "");
  const [ip, setIp] = useState(editing?.ip ?? "");
  const [community, setCommunity] = useState(editing ? "" : "public");
  const [version, setVersion] = useState<Version>(editing?.snmpVersion ?? "2c");
  const [snmpUsername, setSnmpUsername] = useState("");
  const [snmpAuthPassword, setSnmpAuthPassword] = useState("");
  const [snmpAuthProtocol, setSnmpAuthProtocol] = useState<"md5" | "sha">(editing?.snmpAuthProtocol ?? "md5");
  const [snmpPrivPassword, setSnmpPrivPassword] = useState("");
  const [snmpPrivProtocol, setSnmpPrivProtocol] = useState<"none" | "des" | "aes">(editing?.snmpPrivProtocol ?? "none");
  const [notes, setNotes] = useState(editing?.notes ?? "");

  const input = (): EquipmentInput => ({ name, ip, community, snmpVersion: version, snmpUsername, snmpAuthPassword, snmpAuthProtocol, snmpPrivPassword, snmpPrivProtocol, notes });

  const save = useMutation({
    mutationFn: () => unwrap(editing ? updateEquipment(editing.id, input()) : createEquipment(input())),
    onSuccess: (row) => {
      toast.success(editing ? `${row.name} atualizado` : `${row.name} cadastrado`);
      queryClient.invalidateQueries({ queryKey: ["equipment"] });
      queryClient.invalidateQueries({ queryKey: ["equipment-detail", row.id] });
      onSaved(row);
    },
    onError: (err) => toast.error(err.message),
  });

  const test = useMutation({
    mutationFn: () => unwrap(testEquipmentConnection({ ip, community, snmpVersion: version, snmpUsername, snmpAuthPassword, snmpAuthProtocol, snmpPrivPassword, snmpPrivProtocol, id: editing?.id })),
    onSuccess: (sys) => {
      // Sugere o nome anunciado pelo próprio equipamento quando o campo ainda está vazio.
      if (!name.trim() && sys.sysName) setName(sys.sysName);
    },
  });

  return (
    <>
      <DialogHeader>
        <DialogTitle>{editing ? `Editar ${editing.name}` : "Novo equipamento"}</DialogTitle>
        <DialogDescription>
          Switches, roteadores e impressoras. As credenciais SNMP ficam criptografadas no servidor e nunca voltam para o navegador.
        </DialogDescription>
      </DialogHeader>
      <form
        id="equipment-form"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
        className="flex flex-col gap-3"
      >
        <Field label="Nome" htmlFor="eq-name">
          <Input id="eq-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Switch do CPD" maxLength={80} required />
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Endereço IP" htmlFor="eq-ip">
            <Input
              id="eq-ip"
              value={ip}
              onChange={(e) => {
                setIp(e.target.value);
                test.reset();
              }}
              placeholder="192.168.0.3"
              className="font-mono"
              required
            />
          </Field>
          <Field label="Versão SNMP" htmlFor="eq-version">
            <SimpleSelect
              id="eq-version"
              value={version}
              onChange={(v) => {
                setVersion(v);
                test.reset();
              }}
              options={VERSION_OPTIONS}
              className="sm:w-full"
            />
          </Field>
        </div>
        {version === "3" ? (
          <div className="flex flex-col gap-3 rounded-lg border p-3">
            <p className="text-xs text-muted-foreground">Configure a autenticação e, quando o equipamento exigir, a privacidade (authPriv). Use os algoritmos e senhas definidos no próprio equipamento.</p>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Usuário SNMPv3" htmlFor="eq-snmp-user">
                <Input id="eq-snmp-user" value={snmpUsername} onChange={(e) => { setSnmpUsername(e.target.value); test.reset(); }} placeholder={editing?.credentialsConfigured ? "Configurado (vazio mantém)" : "admin"} autoComplete="off" />
              </Field>
              <Field label="Autenticação" htmlFor="eq-snmp-auth-protocol">
                <SimpleSelect id="eq-snmp-auth-protocol" value={snmpAuthProtocol} onChange={(v) => setSnmpAuthProtocol(v as "md5" | "sha")} options={AUTH_OPTIONS} className="w-full" />
              </Field>
            </div>
            <Field label={editing?.credentialsConfigured ? "Senha de autenticação (vazio mantém a atual)" : "Senha de autenticação"} htmlFor="eq-snmp-auth-password">
              <Input id="eq-snmp-auth-password" type="password" value={snmpAuthPassword} onChange={(e) => { setSnmpAuthPassword(e.target.value); test.reset(); }} placeholder={editing?.credentialsConfigured ? "••••••••" : "Mínimo 8 caracteres"} autoComplete="new-password" className="font-mono" required={!editing || !editing.credentialsConfigured} />
            </Field>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Privacidade" htmlFor="eq-snmp-privacy-protocol">
                <SimpleSelect id="eq-snmp-privacy-protocol" value={snmpPrivProtocol} onChange={(v) => { setSnmpPrivProtocol(v as "none" | "des" | "aes"); test.reset(); }} options={PRIVACY_OPTIONS} className="w-full" />
              </Field>
              {snmpPrivProtocol !== "none" && (
                <Field label={editing?.privacyConfigured ? "Senha de privacidade (vazio mantém a atual)" : "Senha de privacidade"} htmlFor="eq-snmp-privacy-password">
                  <Input id="eq-snmp-privacy-password" type="password" value={snmpPrivPassword} onChange={(e) => { setSnmpPrivPassword(e.target.value); test.reset(); }} placeholder={editing?.privacyConfigured ? "••••••••" : "Mínimo 8 caracteres"} autoComplete="new-password" className="font-mono" required={!editing || !editing.privacyConfigured} />
                </Field>
              )}
            </div>
          </div>
        ) : (
          <Field label={editing ? "Community SNMP (em branco = manter a atual)" : "Community SNMP"} htmlFor="eq-community">
            <Input
              id="eq-community"
              type="password"
              value={community}
              onChange={(e) => { setCommunity(e.target.value); test.reset(); }}
              placeholder={editing ? "••••••" : "public"}
              autoComplete="off"
              className="font-mono"
              required={!editing}
            />
          </Field>
        )}
        <Field label="Observações (opcional)" htmlFor="eq-notes">
          <textarea
            id="eq-notes"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={3}
            maxLength={1000}
            placeholder="Ex: rack do CPD, patrimônio, portas reservadas…"
            className="w-full rounded-2xl border border-input bg-transparent px-3.5 py-2 text-sm outline-none transition-[border-color,box-shadow] duration-300 ease-out placeholder:text-muted-foreground hover:border-primary/50 focus-visible:border-primary/70 disabled:opacity-60"
          />
        </Field>

        {canTest && (
          <div className="flex flex-col gap-2">
            <Button type="button" variant="outline" size="sm" className="w-fit gap-2" onClick={() => test.mutate()} disabled={test.isPending || !ip.trim()}>
              {test.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <PlugZap className="h-3.5 w-3.5" />}
              Testar conexão
            </Button>
            {test.isSuccess && (
              <p className="flex items-start gap-2 rounded-md border border-emerald-900 bg-emerald-950 px-3 py-2 text-xs text-emerald-400">
                <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>
                  Respondeu: <strong className="font-medium">{test.data.sysName ?? "sem nome"}</strong>
                  {test.data.sysDescr && <span className="block text-emerald-400/80">{test.data.sysDescr.split(/\r?\n/)[0]}</span>}
                </span>
              </p>
            )}
            {test.isError && <p className="text-xs text-destructive">{test.error.message}</p>}
          </div>
        )}
      </form>
      <DialogFooter>
        <Button variant="outline" onClick={onClose}>
          Cancelar
        </Button>
        <Button type="submit" form="equipment-form" disabled={save.isPending}>
          {save.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
          {editing ? "Salvar" : "Cadastrar"}
        </Button>
      </DialogFooter>
    </>
  );
}
