#!/usr/bin/env python3
# .site/fix-slugs.py — GitHub-exact duplicate-heading slugs for the built site.
#
# WHY THIS EXISTS
#   python-markdown's toc extension deduplicates repeated heading text by
#   appending "_1", "_2" … to the generated id. GitHub appends "-1", "-2" …
#   The corpus (and every GitHub page) links to the "-1" form, so after a
#   plain mkdocs build those links miss. This pass renames the suffixes on
#   heading ids and rewrites the matching in-page permalink anchors, without
#   touching anything else.
#
# USAGE
#   python3 .site/fix-slugs.py /tmp/site

import re
import sys

def fix_file(path):
    html = open(path, encoding='utf-8').read()

    heading_ids = set(re.findall(r'<h[1-6][^>]*\bid="([^"]+)"', html))
    # second and later occurrences of a heading: toc marks them "<base>_<n>"
    dup_ids = {i: re.match(r'^(.+)_(\d+)$', i) for i in heading_ids}
    dup_ids = {i: m for i, m in dup_ids.items() if m}

    if not dup_ids:
        return 0

    # rename "<base>_<n>" -> "<base>-<n>", keeping first-come order so that
    # "_1" becomes "-1" and "_2" becomes "-2", mirroring GitHub.
    order = sorted(dup_ids.items(), key=lambda kv: int(kv[1].group(2)))
    taken = heading_ids
    mapping = {}
    for old, m in order:
        new = f"{m.group(1)}-{m.group(2)}"
        if new in taken:          # pathological collision; leave untouched
            continue
        mapping[old] = new
        taken.add(new)

    if not mapping:
        return 0

    for old, new in mapping.items():
        html = html.replace(f'id="{old}"', f'id="{new}"')
        html = html.replace(f'href="#{old}"', f'href="#{new}"')
    open(path, 'w', encoding='utf-8').write(html)
    return len(mapping)

def main(site_dir):
    import os
    renamed = files = 0
    for r, _, fs in os.walk(site_dir):
        for f in fs:
            if f.endswith('.html'):
                n = fix_file(os.path.join(r, f))
                if n:
                    renamed += n
                    files += 1
    print(f"fix-slugs: renamed {renamed} ids in {files} files")

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'site')
