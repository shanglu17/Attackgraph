const megabyte = 1024 * 1024;

export function assertSafeLocalFile(
  file: Pick<File, "name" | "size">,
  allowedExtensions: string[],
  maximumMegabytes: number,
): void {
  const normalizedName = file.name.trim().toLowerCase();
  if (!allowedExtensions.some((extension) => normalizedName.endsWith(extension.toLowerCase()))) {
    throw new Error(`不支持的文件类型：${file.name}`);
  }
  if (file.size <= 0) throw new Error(`文件为空：${file.name}`);
  if (file.size > maximumMegabytes * megabyte) {
    throw new Error(`文件过大：${file.name}（上限 ${maximumMegabytes} MB）`);
  }
}
