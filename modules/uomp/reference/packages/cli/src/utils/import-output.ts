import chalk from 'chalk';
import type { MarkdownImportResult } from './markdown.js';

export function printMarkdownImportResult(result: MarkdownImportResult, dryRun = false): void {
  if (result.notes.length === 0) {
    console.log(chalk.yellow(`No Markdown notes found under ${result.target}`));
  } else {
    const count = `${result.notes.length} note${result.notes.length === 1 ? '' : 's'}`;
    console.log(chalk.green(`${dryRun ? 'Dry run: would import' : 'Imported'} ${count} from ${result.target}`));
    console.log(chalk.gray(
      `  new: ${result.created} · updated: ${result.updated}` +
      `${result.skipped.length ? ` · skipped: ${result.skipped.length}` : ''}`
    ));

    const visibleTags = result.tags.slice(0, 6);
    const moreTags = result.tags.length - visibleTags.length;
    console.log(chalk.gray(`  tags: ${visibleTags.join(', ')}${moreTags > 0 ? ` … (+${moreTags})` : ''}`));

    if (dryRun) {
      for (const note of result.notes.slice(0, 10)) {
        console.log(chalk.gray(`  ${note.key}  ${note.title}`));
      }
      if (result.notes.length > 10) {
        console.log(chalk.gray(`  … ${result.notes.length - 10} more`));
      }
    }
  }

  for (const skipped of result.skipped.slice(0, 5)) {
    console.log(chalk.yellow(`  skipped ${skipped.path}: ${skipped.reason}`));
  }
  if (result.skipped.length > 5) {
    console.log(chalk.yellow(`  … ${result.skipped.length - 5} more skipped`));
  }
}
