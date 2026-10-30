import { Command } from 'commander';
import chalk from 'chalk';
import { readFile, stat } from 'fs/promises';
import { parse } from 'csv-parse/sync';
import { UompConfig } from '../config.js';
import { MemoryStore } from '@uomp/store';
import type { MemoryItem, Sensitivity } from '@uomp/core';
import { inferSensitivity } from '@uomp/core';
import { importMarkdown } from '../utils/markdown.js';
import { printMarkdownImportResult } from '../utils/import-output.js';

interface ImportOptions {
  tag?: string;
  sensitivity?: string;
  keyField?: string;
  format?: string;
  map?: string[];
  dryRun?: boolean;
  replace?: boolean;
}

export class ImportCommands {
  static get(): Command {
    return new Command('import')
      .description('Import memory items from CSV, JSON, or a Markdown folder')
      .argument('[file]', 'File or directory path (omit for interactive)')
      .option('-t, --tag <tag>', 'Base memory tag (default: notes for Markdown)')
      .option('-s, --sensitivity <level>', 'Sensitivity level (low/medium/high)')
      .option('-k, --key-field <field>', 'Column to use as item key')
      .option('-f, --format <format>', 'File format (csv/json/markdown)')
      .option('-m, --map <mapping>', 'Field mapping e.g. key=symbol', collect, [])
      .option('--dry-run', 'Preview without writing')
      .option('--replace', 'Replace existing items for the tag (CSV/JSON)')
      .action(async (file: string | undefined, options: ImportOptions) => {
        const config = new UompConfig();
        await config.init();
        const store = new MemoryStore({ dbPath: config.memoryDbPath });
        try {
          const importer = new ImportCommands();
          await importer.run(store, file, options);
        } finally {
          store.close();
        }
      });
  }

  async run(store: MemoryStore, file: string | undefined, options: ImportOptions): Promise<void> {
    if (!file) {
      console.log(chalk.red('Interactive import not yet implemented'));
      return;
    }

    const fileInfo = await stat(file).catch(() => null);
    if (!fileInfo) {
      console.log(chalk.red(`File or directory not found: ${file}`));
      return;
    }

    const format = options.format ?? this.inferFormat(file);
    const markdownTarget =
      fileInfo.isDirectory() ||
      (fileInfo.isFile() && file.toLowerCase().endsWith('.md')) ||
      format === 'markdown' ||
      format === 'md';

    if (markdownTarget) {
      try {
        const result = await importMarkdown(store, file, {
          tag: options.tag,
          sensitivity: options.sensitivity as Sensitivity | undefined,
          dryRun: options.dryRun,
        });
        printMarkdownImportResult(result, options.dryRun === true);
      } catch (error) {
        console.log(chalk.red(error instanceof Error ? error.message : String(error)));
      }
      return;
    }

    let tag = options.tag;
    let sensitivity = options.sensitivity as Sensitivity | undefined;

    const content = await readFile(file, 'utf-8');

    let rawRecords: Record<string, unknown>[] = [];
    if (format === 'csv') {
      rawRecords = parse(content, {
        columns: true,
        skip_empty_lines: true,
        trim: true,
      }) as Record<string, unknown>[];
    } else if (format === 'json') {
      const parsed = JSON.parse(content) as Record<string, unknown> | Record<string, unknown>[];
      rawRecords = Array.isArray(parsed) ? parsed : [parsed];
    } else {
      console.log(chalk.red(`Unsupported format: ${format}`));
      return;
    }

    // For self-describing JSON records, allow the record to supply tag/sensitivity
    // when the user did not override them on the CLI.
    const inferredTag = await this.inferTag(file);
    if (!tag && rawRecords.length > 0) {
      const first = rawRecords[0];
      if (first.tags) {
        tag = Array.isArray(first.tags) ? first.tags[0] : String(first.tags);
      }
    }
    if (!sensitivity && rawRecords.length > 0) {
      const first = rawRecords[0];
      if (first.sensitivity && ['low', 'medium', 'high'].includes(String(first.sensitivity))) {
        sensitivity = String(first.sensitivity) as Sensitivity;
      }
    }
    tag = tag ?? inferredTag;
    if (!tag) {
      console.log(chalk.red('Please specify --tag'));
      return;
    }
    sensitivity = sensitivity ?? inferSensitivity(tag);

    const mappings = parseMappings(options.map ?? []);
    const items = rawRecords.map((record, idx) => this.recordToMemoryItem(record, idx, tag!, sensitivity, options.keyField, mappings));

    // Validation
    for (const item of items) {
      if (!item.key) {
        console.log(chalk.red(`Record missing key at index ${items.indexOf(item)}`));
        return;
      }
    }

    // Check duplicates
    if (!options.replace) {
      const existing = store.getByTag(tag);
      const existingKeys = new Set(existing.map(i => i.key));
      for (const item of items) {
        if (existingKeys.has(item.key)) {
          console.log(chalk.yellow(`Key "${item.key}" already exists in tag "${tag}". Use --replace to overwrite.`));
          return;
        }
      }
    }

    if (options.dryRun) {
      console.log(chalk.cyan(`Dry run: would import ${items.length} items into tag "${tag}"`));
      for (const item of items) {
        console.log(`  ${item.key}: ${JSON.stringify(item.value)}`);
      }
      return;
    }

    if (options.replace) {
      const existing = store.getByTag(tag);
      for (const item of existing) {
        store.delete(item.key);
      }
    }

    for (const item of items) {
      store.set(item);
    }

    console.log(chalk.green(`Imported ${items.length} items into tag "${tag}" (sensitivity: ${sensitivity})`));
  }

  private recordToMemoryItem(
    record: Record<string, unknown>,
    idx: number,
    tag: string,
    sensitivity: Sensitivity,
    keyField: string | undefined,
    mappings: Record<string, string>
  ): MemoryItem {
    // Reserved fields handling
    const reserved = new Set(['key', 'tags', 'sensitivity', 'source', 'description', 'created_at', 'updated_at']);
    let value: Record<string, unknown> = {};

    // If record has an explicit 'value' object, use it as the base value
    if (record.value && typeof record.value === 'object' && !Array.isArray(record.value)) {
      value = { ...record.value as Record<string, unknown> };
    }

    for (const [rawKey, rawVal] of Object.entries(record)) {
      const key = normalizeKey(rawKey);
      if (reserved.has(key) || key === 'value') continue;
      value[key] = rawVal;
    }

    // Determine key
    let key = record.key as string | undefined;
    if (!key && keyField) {
      key = String(record[keyField] ?? '');
    }
    if (!key) {
      // Try common key aliases
      for (const alias of ['id', 'symbol', 'code', '股票代码', '代码']) {
        if (record[alias] !== undefined) {
          key = String(record[alias]);
          break;
        }
      }
    }
    if (!key) {
      key = `item-${idx}`;
    }

    // Apply custom mappings to nested value fields
    for (const [target, sourceField] of Object.entries(mappings)) {
      if (target.startsWith('value.')) {
        const nestedKey = target.slice(6);
        value[nestedKey] = record[sourceField];
      }
    }

    const recordTags = record.tags
      ? (Array.isArray(record.tags) ? record.tags as string[] : [String(record.tags)])
      : [];
    const tags = [tag, ...recordTags.filter(t => t !== tag)];

    return {
      key,
      value,
      tags,
      sensitivity,
      source: (record.source as 'user' | 'agent') ?? 'user',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      description: record.description as string | undefined,
    };
  }

  private inferFormat(file?: string): string {
    if (!file) return 'json';
    if (file.endsWith('.csv')) return 'csv';
    if (file.endsWith('.json')) return 'json';
    return 'json';
  }

  private inferTag(file?: string): string | undefined {
    if (!file) return undefined;
    const base = file.split('/').pop()?.split('.')[0];
    return base;
  }
}

function collect(value: string, previous: string[]): string[] {
  return previous.concat([value]);
}

function parseMappings(maps: string[]): Record<string, string> {
  const result: Record<string, string> = {};
  for (const m of maps) {
    const idx = m.indexOf('=');
    if (idx > 0) {
      result[m.slice(0, idx).trim()] = m.slice(idx + 1).trim();
    }
  }
  return result;
}

function normalizeKey(key: string): string {
  return key.toLowerCase().trim().replace(/\s+/g, '_');
}
