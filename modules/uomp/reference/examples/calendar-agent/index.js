#!/usr/bin/env node
import { UserMemory } from '@uomp/sdk';

async function main() {
  const token = process.env.UOM_TOKEN;
  const baseUrl = process.env.UOMP_BASE_URL || 'http://127.0.0.1:9374';

  if (!token) {
    console.error('Error: UOM_TOKEN environment variable is required');
    process.exit(1);
  }

  const memory = new UserMemory({ token, baseUrl });

  try {
    console.log('Calendar Agent started');
    console.log('Reading user preferences...');

    // Read a specific preference
    const theme = await memory.get('preference.theme');
    console.log(`Theme preference: ${theme ? JSON.stringify(theme.value) : 'not set'}`);

    // Read all preferences by tag
    const preferences = await memory.getByTag('preference');
    console.log(`Found ${preferences.length} preference item(s):`);
    for (const item of preferences) {
      console.log(`  - ${item.key}: ${JSON.stringify(item.value)}`);
    }

    console.log('Calendar Agent finished');
  } catch (error) {
    console.error('Agent error:', error.message);
    if (error.code) {
      console.error('Error code:', error.code);
    }
    process.exit(1);
  }
}

main();
