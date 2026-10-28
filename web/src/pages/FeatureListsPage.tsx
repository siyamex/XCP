import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { ErrorAlert } from "../components/ErrorAlert";
import { Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";
import { useFeatureLists } from "./PackagesPage";

type FeatureList = components["schemas"]["FeatureList"];

export function FeatureListsPage() {
  const { t } = useTranslation();
  const lists = useFeatureLists();
  const [editing, setEditing] = useState<FeatureList | "new" | null>(null);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t("featureLists.title")}</h1>
        <Button onClick={() => setEditing("new")}>{t("featureLists.new")}</Button>
      </div>
      <p className="text-sm text-slate-500">{t("featureLists.help")}</p>
      <ErrorAlert error={lists.error} />
      {lists.isPending && <Spinner />}
      <div className="grid gap-3 md:grid-cols-2">
        {lists.data?.items.map((l) => (
          <Card key={l.id} className="flex items-center justify-between">
            <div>
              <div className="font-medium">{l.name}</div>
              <div className="text-sm text-slate-500">{t("featureLists.count", { count: l.features.length })}</div>
            </div>
            <Button variant="secondary" onClick={() => setEditing(l)}>{t("common.edit")}</Button>
          </Card>
        ))}
      </div>
      {editing && <Editor key={editing === "new" ? "new" : editing.id} list={editing === "new" ? null : editing} onDone={() => setEditing(null)} />}
    </div>
  );
}

function Editor({ list, onDone }: { list: FeatureList | null; onDone: () => void }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const catalog = useQuery({ queryKey: ["features"], queryFn: () => unwrap(api.GET("/features")) });
  const [name, setName] = useState(list?.name ?? "");
  const [selected, setSelected] = useState<Set<string>>(new Set(list?.features ?? []));

  const done = async () => {
    await qc.invalidateQueries({ queryKey: ["feature-lists"] });
    onDone();
  };
  const save = useMutation({
    mutationFn: () => {
      const body = { name, features: [...selected] };
      return list
        ? unwrap(api.PUT("/feature-lists/{id}", { params: { path: { id: list.id } }, body }))
        : unwrap(api.POST("/feature-lists", { body }));
    },
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: () => unwrap(api.DELETE("/feature-lists/{id}", { params: { path: { id: list!.id } } })),
    onSuccess: done,
  });

  const groups = new Map<string, string[]>();
  for (const f of catalog.data?.items ?? []) groups.set(f.group, [...(groups.get(f.group) ?? []), f.key]);
  const toggle = (k: string) => {
    const next = new Set(selected);
    if (next.has(k)) next.delete(k);
    else next.add(k);
    setSelected(next);
  };

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate();
  }

  return (
    <Card>
      <form onSubmit={submit} className="space-y-4">
        <CardTitle>{list ? list.name : t("featureLists.new")}</CardTitle>
        <ErrorAlert error={save.error ?? remove.error} />
        <div className="max-w-md">
          <Field id="fl-name" label={t("packages.name")}>
            <Input id="fl-name" required maxLength={64} value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
        </div>
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {[...groups.entries()].map(([group, keys]) => (
            <fieldset key={group}>
              <legend className="mb-2 text-sm font-semibold">{t(`featureGroups.${group}`)}</legend>
              {keys.map((k) => (
                <label key={k} className="flex items-center gap-2 py-0.5 text-sm">
                  <input type="checkbox" checked={selected.has(k)} onChange={() => toggle(k)} />
                  {t(`features.${k}`)}
                </label>
              ))}
            </fieldset>
          ))}
        </div>
        <div className="flex gap-2">
          <Button type="submit" disabled={save.isPending}>{t("common.save")}</Button>
          <Button type="button" variant="secondary" onClick={onDone}>{t("common.cancel")}</Button>
          {list && (
            <Button type="button" variant="danger" disabled={remove.isPending}
              onClick={() => window.confirm(t("common.confirmDelete", { name: list.name })) && remove.mutate()}>
              {t("common.delete")}
            </Button>
          )}
        </div>
      </form>
    </Card>
  );
}
