import { Command } from 'commander';
import chalk from 'chalk';
import { UompConfig } from '../config.js';
import { MemoryStore } from '@uomp/store';
import type { MemoryItem, Sensitivity } from '@uomp/core';
import { readFile } from 'fs/promises';

export class MemoryCommands {
  private static async getStore(): Promise<MemoryStore> {
    const config = new UompConfig();
    await config.init();
    return new MemoryStore({ dbPath: config.memoryDbPath });
  }

  static add(): Command {
    return new Command('add')
      .description('Add a memory item')
      .argument('<key>', 'Memory key')
      .argument('<value>', 'Memory value')
      .requiredOption('-t, --tags <tags>', 'Comma-separated tags')
      .option('-s, --sensitivity <level>', 'Sensitivity level (low/medium/high)', 'low')
      .option('-d, --description <text>', 'Description')
      .action(async (key: string, value: string, options: { tags: string; sensitivity: string; description?: string }) => {
        const store = await this.getStore();
        const tags = options.tags.split(',').map(t => t.trim()).filter(Boolean);
        const sensitivity = options.sensitivity as Sensitivity;

        try {
          store.set({
            key,
            value,
            tags,
            sensitivity,
            source: 'user',
            description: options.description,
          });
          console.log(chalk.green(`Added memory: ${key}`));
        } finally {
          store.close();
        }
      });
  }

  static list(): Command {
    return new Command('list')
      .description('List memory items')
      .option('-t, --tag <tag>', 'Filter by tag')
      .option('--source <source>', 'Filter by source (user/agent)')
      .action(async (options: { tag?: string; source?: string }) => {
        const store = await this.getStore();
        try {
          let items: MemoryItem[];
          if (options.tag) {
            items = store.getByTag(options.tag);
          } else {
            items = store.getAll();
          }

          if (options.source) {
            items = items.filter(i => i.source === options.source);
          }

          if (items.length === 0) {
            console.log(chalk.gray('No memory items found.'));
            return;
          }

          for (const item of items) {
            console.log(`${chalk.cyan(item.key)} = ${JSON.stringify(item.value)}`);
            console.log(`  tags: ${item.tags.join(', ')} | sensitivity: ${item.sensitivity} | source: ${item.source}`);
          }
        } finally {
          store.close();
        }
      });
  }

  static get(): Command {
    return new Command('get')
      .description('Get a memory item')
      .argument('<key>', 'Memory key')
      .action(async (key: string) => {
        const store = await this.getStore();
        try {
          const item = store.get(key);
          if (!item) {
            console.log(chalk.gray('Not found'));
            return;
          }
          console.log(JSON.stringify(item, null, 2));
        } finally {
          store.close();
        }
      });
  }

  static deleteCmd(): Command {
    return new Command('delete')
      .description('Delete a memory item')
      .argument('<key>', 'Memory key')
      .action(async (key: string) => {
        const store = await this.getStore();
        try {
          const deleted = store.delete(key);
          console.log(deleted ? chalk.green(`Deleted ${key}`) : chalk.gray('Not found'));
        } finally {
          store.close();
        }
      });
  }

  static importCmd(): Command {
    return new Command('import')
      .description('Import memory items from JSON file')
      .argument('<file>', 'JSON file path')
      .action(async (file: string) => {
        const store = await this.getStore();
        try {
          const data = JSON.parse(await readFile(file, 'utf-8')) as { items: Array<Partial<MemoryItem>> };
          for (const item of data.items) {
            if (!item.key || item.value === undefined) continue;
            store.set({
              key: item.key,
              value: item.value,
              tags: item.tags ?? [],
              sensitivity: item.sensitivity ?? 'low',
              source: item.source ?? 'user',
              description: item.description,
            });
          }
          console.log(chalk.green(`Imported ${data.items.length} memory items`));
        } finally {
          store.close();
        }
      });
  }
}
