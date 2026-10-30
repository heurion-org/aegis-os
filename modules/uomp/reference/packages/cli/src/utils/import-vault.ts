import { UompConfig } from '../config.js';
import { MemoryStore } from '@uomp/store';
import { importMarkdown } from './markdown.js';
import { printMarkdownImportResult } from './import-output.js';

export async function importVault(config: UompConfig, target: string, tag = 'notes'): Promise<void> {
  await config.init();

  const store = new MemoryStore({ dbPath: config.memoryDbPath });
  try {
    const result = await importMarkdown(store, target, { tag });
    printMarkdownImportResult(result);

    if (result.notes.length === 0) {
      throw new Error(`No Markdown notes found under ${target}.`);
    }
  } finally {
    store.close();
  }
}
