#!/usr/bin/env python3
"""Generate docs/index.md from README.md.

Removes the first heading and manual Table of Contents section
since MkDocs Material provides these automatically.
"""

import re
from pathlib import Path


def gen_docs() -> None:
    root = Path(__file__).parent.parent
    readme = root / 'README.md'
    docs_dir = root / 'docs'
    index = docs_dir / 'index.md'

    content = readme.read_text()

    # remove first heading (justconf\n========)
    content = re.sub(r'^.+\n=+\n\n', '', content, count=1)

    # add front matter to hide navigation (single-page docs)
    front_matter = '---\nhide:\n  - navigation\n---\n\n'
    content = front_matter + content

    # remove manual Table of Contents section
    content = re.sub(
        r'## Table of Contents\n\n(?:- \[.+\]\(.+\)\n)+\n',
        '',
        content,
    )

    # remove Development section (not relevant for end users)
    content = re.sub(
        r'## Development\n\n.*?(?=## License|\Z)',
        '',
        content,
        flags=re.DOTALL,
    )

    docs_dir.mkdir(exist_ok=True)
    index.write_text(content)


if __name__ == '__main__':
    gen_docs()
