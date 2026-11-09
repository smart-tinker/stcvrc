import json, pathlib, sys
root=pathlib.Path(sys.argv[1]); mode=sys.argv[2]; name=sys.argv[3]
groups=json.loads(pathlib.Path(__file__).with_name('ablation.json').read_text())
selected=[name] if mode=='minus' else [g for g in groups if g!=name]
for group in selected:
    for change in groups[group]:
        p=root/change['file']; text=p.read_text()
        assert text.count(change['new'])==1, (group, change['file'], 'nonunique recipe')
        p.write_text(text.replace(change['new'],change['old'],1))
print('Applied', mode, name, '; inert API declarations retained for identical test compilation', flush=True)
