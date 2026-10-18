import type { Draft } from "../../shared/model/workbench";
export function fieldDifferences(
  before: Draft["entities"],
  after: Draft["entities"],
) {
  return Object.entries(after).flatMap(([collection, list]) => {
    const previous = before[
      collection as keyof typeof before
    ] as unknown as Record<string, unknown>[];
    const next = list as unknown as Record<string, unknown>[];
    return [
      ...new Set([...previous, ...next].map((r) => String(r.business_id))),
    ].flatMap((id) => {
      const a = previous.find((r) => r.business_id === id);
      const b = next.find((r) => r.business_id === id);
      return [...new Set([...Object.keys(a ?? {}), ...Object.keys(b ?? {})])]
        .filter(
          (f) =>
            !["id", "revision_version", "created_by", "updated_by"].includes(
              f,
            ) && JSON.stringify(a?.[f]) !== JSON.stringify(b?.[f]),
        )
        .map((field) => ({
          collection,
          id,
          field,
          before: a?.[field],
          after: b?.[field],
        }));
    });
  });
}
export function FieldComparison({
  before,
  after,
}: {
  before: Draft["entities"];
  after: Draft["entities"];
}) {
  const changes = fieldDifferences(before, after);
  const display = (v: unknown) =>
    v === undefined ? "—" : typeof v === "string" ? v : JSON.stringify(v);
  return (
    <div className="scroll-panel">
      <table className="report-table">
        <thead>
          <tr>
            <th>对象</th>
            <th>字段</th>
            <th>修改前</th>
            <th>修改后</th>
          </tr>
        </thead>
        <tbody>
          {changes.map((c) => (
            <tr key={`${c.collection}:${c.id}:${c.field}`}>
              <td>{c.id}</td>
              <td>{c.field}</td>
              <td>{display(c.before)}</td>
              <td>{display(c.after)}</td>
            </tr>
          ))}
          {!changes.length && (
            <tr>
              <td colSpan={4}>核心实体没有字段修改。</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
