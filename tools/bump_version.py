#!/usr/bin/env python3
"""Porta il numero di versione ovunque (Directory.Build.props, README, guide, en.json, LEGGIMI). Uso: bump_version.py 1.4.1 1.4.2"""
import json, collections, re, sys, os
old, new = sys.argv[1], sys.argv[2]
def rep(p, pairs):
    s = open(p, encoding='utf-8').read()
    for a, b in pairs:
        assert a in s, (p, a); s = s.replace(a, b)
    open(p, 'w', encoding='utf-8').write(s)
o3 = old + '.0' if old.count('.') == 1 else old
n3 = new + '.0' if new.count('.') == 1 else new
rep('Directory.Build.props', [(f'<Version>{o3}</Version>', f'<Version>{n3}</Version>'), (f'<AssemblyVersion>{o3}.0</AssemblyVersion>', f'<AssemblyVersion>{n3}.0</AssemblyVersion>'), (f'<FileVersion>{o3}.0</FileVersion>', f'<FileVersion>{n3}.0</FileVersion>')])
for p in ('README.md', 'README.it.md'):
    rep(p, [(f'# PHP Vuln Scanner v{old}\n', f'# PHP Vuln Scanner v{new}\n')])
rep('src/PhpVulnScanner.App/Help/Guida.html', [(f'<div class="ver">Guida v{old}</div>', f'<div class="ver">Guida v{new}</div>')])
rep('src/PhpVulnScanner.App/Help/Guide.html', [(f'<div class="ver">Guide v{old}</div>', f'<div class="ver">Guide v{new}</div>')])
d = json.load(open('lang/en.json', encoding='utf-8'), object_pairs_hook=collections.OrderedDict); d['app_version'] = new
json.dump(d, open('lang/en.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=2); open('lang/en.json', 'a').write('\n')
if os.path.exists(f'LEGGIMI_v{old}.txt'):
    s = open(f'LEGGIMI_v{old}.txt', encoding='utf-8').read().replace(f'v{old}', f'v{new}').replace(f'_v{old}.', f'_v{new}.')
    open(f'LEGGIMI_v{new}.txt', 'w', encoding='utf-8').write(s); os.remove(f'LEGGIMI_v{old}.txt')
print('ok', old, '->', new)
