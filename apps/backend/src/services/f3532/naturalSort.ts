export function compareNaturalBusinessIds(left: string, right: string): number {
  const tokenize = (value: string): Array<string | number> =>
    value
      .toUpperCase()
      .split(/(\d+(?:\.\d+)*)/)
      .filter(Boolean)
      .reduce<Array<string | number>>((tokens, part) => {
        if (!/^\d+(?:\.\d+)*$/.test(part)) {
          tokens.push(part);
          return tokens;
        }
        tokens.push(...part.split(".").map((item) => Number(item)));
        return tokens;
      }, []);

  const a = tokenize(left);
  const b = tokenize(right);
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const av = a[index];
    const bv = b[index];
    if (av === undefined) return -1;
    if (bv === undefined) return 1;
    if (typeof av === "number" && typeof bv === "number" && av !== bv) return av - bv;
    const compared = String(av).localeCompare(String(bv));
    if (compared !== 0) return compared;
  }
  return left.localeCompare(right);
}

export function naturalSortUnique(ids: string[]): string[] {
  return Array.from(new Set(ids.filter(Boolean))).sort(compareNaturalBusinessIds);
}

export function toDisplayBusinessId(id: string): string {
  const match = id.match(/^([A-Z]+)0*(\d+)$/i);
  return match ? `${match[1].toUpperCase()}${Number(match[2])}` : id;
}
