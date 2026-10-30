import { readdir, readFile, stat } from 'fs/promises';
import { basename, dirname, extname, join, relative, resolve, sep } from 'path';
import type { Sensitivity } from '@uomp/core';
import { inferSensitivity } from '@uomp/core';
import type { MemoryStore } from '@uomp/store';

export interface MarkdownImportOptions {
  tag?: string;
  sensitivity?: Sensitivity;
  dryRun?: boolean;
}

export interface MarkdownNote {
  filePath: string;
  relativePath: string;
  key: string;
  title: string;
  content: string;
  tags: string[];
  sensitivity: Sensitivity;
  description?: string;
}

export interface SkippedMarkdownFile {
  path: string;
  reason: string;
}

export interface MarkdownImportResult {
  target: string;
  notes: MarkdownNote[];
  created: number;
  updated: number;
  skipped: SkippedMarkdownFile[];
  tags: string[];
}

interface Frontmatter {
  title?: string;
  tags?: string[];
  sensitivity?: string;
  description?: string;
}

/**
 * Import a Markdown file or an Obsidian-style vault directory.
 *
 * The directory path becomes the scope path: a note at `projects/uomp/plan.md`
 * is tagged `notes`, `notes/projects`, and `notes/projects/uomp` when the base
 * tag is `notes`. Frontmatter tags are added as-is.
 */
export async function importMarkdown(
  store: MemoryStore,
  target: string,
  options: MarkdownImportOptions = {}
): Promise<MarkdownImportResult> {
  const absolute = resolve(target);
  const info = await stat(absolute);
  const baseTag = normalizeTag(options.tag ?? 'notes');

  if (!baseTag) {
    throw new Error('Tag must not be empty');
  }

  let root: string;
  let files: string[];

  if (info.isDirectory()) {
    root = absolute;
    files = await collectMarkdownFiles(absolute);
  } else if (info.isFile() && isMarkdown(absolute)) {
    root = dirname(absolute);
    files = [absolute];
  } else {
    throw new Error(`Not a Markdown file or directory: ${target}`);
  }

  const notes: MarkdownNote[] = [];
  const skipped: SkippedMarkdownFile[] = [];

  for (const file of files) {
    try {
      notes.push(await parseNote(file, root, baseTag, options.sensitivity));
    } catch (error) {
      skipped.push({
        path: toPosix(relative(root, file)),
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }

  let created = 0;
  let updated = 0;
  const allTags = new Set<string>();

  for (const note of notes) {
    const exists = store.get(note.key) !== null;
    if (exists) updated += 1;
    else created += 1;

    for (const tag of note.tags) allTags.add(tag);

    if (!options.dryRun) {
      store.set({
        key: note.key,
        value: {
          path: note.relativePath,
          title: note.title,
          content: note.content,
        },
        tags: note.tags,
        sensitivity: note.sensitivity,
        source: 'user',
        description: note.description,
      });
    }
  }

  return {
    target: absolute,
    notes,
    created,
    updated,
    skipped,
    tags: [...allTags].sort(),
  };
}

export async function collectMarkdownFiles(root: string): Promise<string[]> {
  const files: string[] = [];

  async function walk(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;
      if (entry.isDirectory() && entry.name === 'node_modules') continue;

      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
      } else if (entry.isFile() && isMarkdown(entry.name)) {
        files.push(fullPath);
      }
    }
  }

  await walk(root);
  return files;
}

async function parseNote(
  filePath: string,
  root: string,
  baseTag: string,
  explicitSensitivity?: Sensitivity
): Promise<MarkdownNote> {
  const raw = await readFile(filePath, 'utf-8');
  const { data, body } = parseFrontmatter(raw);
  const relativePath = toPosix(relative(root, filePath));
  const withoutExtension = relativePath.slice(0, -extname(relativePath).length);
  const key = `note.${withoutExtension.split('/').join('.')}`;

  const frontmatterTags = normalizeTags(data.tags ?? []);
  const tags = buildTags(relativePath, baseTag, frontmatterTags);
  const title = firstNonEmpty(
    data.title,
    findHeading(body),
    basename(filePath, extname(filePath))
  );
  const sensitivity =
    explicitSensitivity ??
    normalizeSensitivity(data.sensitivity) ??
    highestSensitivity(tags);

  return {
    filePath,
    relativePath,
    key,
    title,
    content: body.trim(),
    tags,
    sensitivity,
    description: data.description ?? title,
  };
}

function buildTags(relativePath: string, baseTag: string, frontmatterTags: string[]): string[] {
  const directories = relativePath.split('/').slice(0, -1);
  const tags = [baseTag];
  let current = baseTag;

  for (const directory of directories) {
    const segment = normalizeTag(directory);
    if (!segment) continue;
    current = `${current}/${segment}`;
    tags.push(current);
  }

  tags.push(...frontmatterTags);
  return [...new Set(tags.filter(Boolean))];
}

function parseFrontmatter(raw: string): { data: Frontmatter; body: string } {
  const normalized = raw.replace(/^\uFEFF/, '');
  const lines = normalized.split(/\r?\n/);

  if (lines[0]?.trim() !== '---') {
    return { data: {}, body: normalized };
  }

  const end = lines.findIndex((line, index) => index > 0 && (line.trim() === '---' || line.trim() === '...'));
  if (end === -1) {
    return { data: {}, body: normalized };
  }

  return {
    data: parseFrontmatterLines(lines.slice(1, end)),
    body: lines.slice(end + 1).join('\n'),
  };
}

function parseFrontmatterLines(lines: string[]): Frontmatter {
  const data: Frontmatter = {};
  let currentKey: string | null = null;

  for (const rawLine of lines) {
    const line = rawLine.replace(/\s+$/, '');
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith('#')) continue;

    const item = /^\s*-\s*(.*)$/.exec(line);
    if (item && currentKey === 'tags') {
      data.tags = [...(data.tags ?? []), stripQuotes(item[1])];
      continue;
    }

    const field = /^([A-Za-z0-9_-]+):\s*(.*)$/.exec(line);
    if (!field) continue;

    const key = field[1].toLowerCase();
    const value = field[2].trim();
    currentKey = key;

    if (!value) continue;

    if (key === 'tags') {
      data.tags = parseInlineList(value);
      currentKey = null;
    } else if (key === 'title') {
      data.title = stripQuotes(value);
    } else if (key === 'sensitivity') {
      data.sensitivity = stripQuotes(value).toLowerCase();
    } else if (key === 'description') {
      data.description = stripQuotes(value);
    }
  }

  return data;
}

function parseInlineList(value: string): string[] {
  const inner = value.startsWith('[') && value.endsWith(']')
    ? value.slice(1, -1)
    : value;

  return inner
    .split(',')
    .map(item => stripQuotes(item))
    .filter(Boolean);
}

function findHeading(body: string): string | undefined {
  return /^#\s+(.+)$/m.exec(body)?.[1]?.trim();
}

function normalizeSensitivity(value?: string): Sensitivity | undefined {
  if (value === 'low' || value === 'medium' || value === 'high') return value;
  return undefined;
}

function highestSensitivity(tags: string[]): Sensitivity {
  let level: Sensitivity = 'low';
  for (const tag of tags) {
    const sensitivity = inferSensitivity(tag);
    if (sensitivity === 'high') return 'high';
    if (sensitivity === 'medium') level = 'medium';
  }
  return level;
}

function normalizeTags(tags: string[]): string[] {
  return tags.map(normalizeTag).filter(Boolean);
}

function normalizeTag(tag: string): string {
  return tag.trim().replace(/^#+/, '');
}

function stripQuotes(value: string): string {
  const trimmed = value.trim();
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function firstNonEmpty(...values: Array<string | undefined>): string {
  return values.find(value => Boolean(value?.trim()))!.trim();
}

function isMarkdown(path: string): boolean {
  return extname(path).toLowerCase() === '.md';
}

function toPosix(path: string): string {
  return path.split(sep).join('/');
}
