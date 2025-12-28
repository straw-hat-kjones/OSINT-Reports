#!/usr/bin/env python3
"""
Obsidian to GitHub Markdown Converter

Converts Obsidian-specific syntax to GitHub-compatible Markdown:
- Wiki-links [[path/name]] → [name](path/name.md)
- Wiki-links with aliases [[path/name|alias]] → [alias](path/name.md)
- Dataview blocks → Static "See Also" section or removal
- Embedded images ![[image.png]] → ![image](image.png)
- Internal embeds ![[note]] → Link to note

Author: Threat Intel Analyst
License: MIT
"""

import re
import argparse
import shutil
from pathlib import Path
from typing import Optional
from urllib.parse import quote


class ObsidianConverter:
    """Converts Obsidian markdown to GitHub-compatible format."""

    WIKILINK_PATTERN = re.compile(r'\[\[([^\]|]+?)(?:\|([^\]]+))?\]\]')
    EMBED_PATTERN = re.compile(r'!\[\[([^\]|]+?)(?:\|([^\]]+))?\]\]')
    DATAVIEW_PATTERN = re.compile(r'```dataview\n.*?```', re.DOTALL | re.MULTILINE)
    DATAVIEWJS_PATTERN = re.compile(r'```dataviewjs\n.*?```', re.DOTALL | re.MULTILINE)
    TEMPLATER_PATTERN = re.compile(r'<%[^%]*%>')
    IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.bmp'}

    def __init__(self, source_dir: Path, output_dir: Path, strip_dataview: bool = True,
                 convert_frontmatter_links: bool = False, verbose: bool = False):
        self.source_dir = Path(source_dir)
        self.output_dir = Path(output_dir)
        self.strip_dataview = strip_dataview
        self.convert_frontmatter_links = convert_frontmatter_links
        self.verbose = verbose
        self.stats = {'files_processed': 0, 'wikilinks_converted': 0, 
                      'embeds_converted': 0, 'dataview_blocks_removed': 0, 'errors': []}

    def log(self, message: str) -> None:
        if self.verbose:
            print(message)

    def convert_wikilink(self, match: re.Match, current_file: Path) -> str:
        target = match.group(1).strip()
        alias = match.group(2)
        header = ''
        if '#' in target:
            target, header = target.split('#', 1)
            header = '#' + header.lower().replace(' ', '-')
        display_text = alias.strip() if alias else Path(target).name
        if target:
            encoded_path = quote(target, safe='/')
            if not encoded_path.endswith('.md'):
                encoded_path += '.md'
            link = f'[{display_text}]({encoded_path}{header})'
        else:
            link = f'[{display_text}]({header})'
        self.stats['wikilinks_converted'] += 1
        return link

    def convert_embed(self, match: re.Match, current_file: Path) -> str:
        target = match.group(1).strip()
        alias = match.group(2)
        target_path = Path(target)
        if target_path.suffix.lower() in self.IMAGE_EXTENSIONS:
            alt_text = alias if alias else target_path.stem
            encoded_path = quote(target, safe='/')
            self.stats['embeds_converted'] += 1
            return f'![{alt_text}]({encoded_path})'
        display_text = alias if alias else target_path.name
        encoded_path = quote(target, safe='/')
        if not encoded_path.endswith('.md'):
            encoded_path += '.md'
        self.stats['embeds_converted'] += 1
        return f'📄 *See: [{display_text}]({encoded_path})*'

    def strip_dataview_blocks(self, content: str) -> str:
        dv_count = len(self.DATAVIEW_PATTERN.findall(content))
        dvjs_count = len(self.DATAVIEWJS_PATTERN.findall(content))
        if self.strip_dataview and (dv_count + dvjs_count > 0):
            content = self.DATAVIEW_PATTERN.sub('', content)
            content = self.DATAVIEWJS_PATTERN.sub('', content)
            self.stats['dataview_blocks_removed'] += dv_count + dvjs_count
        return content

    def strip_templater(self, content: str) -> str:
        return self.TEMPLATER_PATTERN.sub('', content)

    def convert_file(self, file_path: Path) -> Optional[str]:
        try:
            content = file_path.read_text(encoding='utf-8')
            frontmatter = ''
            body = content
            if not self.convert_frontmatter_links and content.startswith('---'):
                end_match = re.search(r'\n---\n', content[3:])
                if end_match:
                    fm_end = end_match.end() + 3
                    frontmatter = content[:fm_end]
                    body = content[fm_end:]
            body = self.EMBED_PATTERN.sub(lambda m: self.convert_embed(m, file_path), body)
            body = self.WIKILINK_PATTERN.sub(lambda m: self.convert_wikilink(m, file_path), body)
            body = self.strip_dataview_blocks(body)
            body = self.strip_templater(body)
            body = re.sub(r'\n{4,}', '\n\n\n', body)
            return frontmatter + body
        except Exception as e:
            self.stats['errors'].append(f"{file_path}: {str(e)}")
            return None

    def process_directory(self) -> None:
        self.log(f"Source: {self.source_dir}")
        self.log(f"Output: {self.output_dir}")
        self.log("-" * 50)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        md_files = list(self.source_dir.rglob('*.md'))
        self.log(f"Found {len(md_files)} markdown files")
        for md_file in md_files:
            if any(part.startswith('.') for part in md_file.parts):
                continue
            rel_path = md_file.relative_to(self.source_dir)
            output_path = self.output_dir / rel_path
            output_path.parent.mkdir(parents=True, exist_ok=True)
            converted = self.convert_file(md_file)
            if converted:
                output_path.write_text(converted, encoding='utf-8')
                self.stats['files_processed'] += 1
                self.log(f"✓ {rel_path}")
            else:
                self.log(f"✗ {rel_path} (error)")
        self._copy_assets()

    def _copy_assets(self) -> None:
        asset_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.pdf', '.csv', '.json', '.yaml', '.yml'}
        for ext in asset_extensions:
            for asset in self.source_dir.rglob(f'*{ext}'):
                if any(part.startswith('.') for part in asset.parts):
                    continue
                rel_path = asset.relative_to(self.source_dir)
                output_path = self.output_dir / rel_path
                output_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(asset, output_path)
                self.log(f"📎 {rel_path}")

    def print_summary(self) -> None:
        print("\n" + "=" * 50)
        print("CONVERSION SUMMARY")
        print("=" * 50)
        print(f"Files processed:      {self.stats['files_processed']}")
        print(f"Wiki-links converted: {self.stats['wikilinks_converted']}")
        print(f"Embeds converted:     {self.stats['embeds_converted']}")
        print(f"Dataview removed:     {self.stats['dataview_blocks_removed']}")
        if self.stats['errors']:
            print(f"\nErrors ({len(self.stats['errors'])}):")
            for error in self.stats['errors']:
                print(f"  ✗ {error}")


def main():
    parser = argparse.ArgumentParser(description='Convert Obsidian vault to GitHub-compatible Markdown')
    parser.add_argument('source', type=Path, help='Source Obsidian vault directory')
    parser.add_argument('output', type=Path, help='Output directory')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--keep-dataview', action='store_true', help='Keep Dataview blocks')
    parser.add_argument('--convert-frontmatter', action='store_true', help='Convert wiki-links in frontmatter')
    args = parser.parse_args()
    if not args.source.exists():
        print(f"Error: Source not found: {args.source}")
        return 1
    converter = ObsidianConverter(args.source, args.output, strip_dataview=not args.keep_dataview,
                                   convert_frontmatter_links=args.convert_frontmatter, verbose=args.verbose)
    converter.process_directory()
    converter.print_summary()
    return 0 if not converter.stats['errors'] else 1

if __name__ == '__main__':
    exit(main())
