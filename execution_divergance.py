import re

def extract_commits(filename):
    commits = []
    pat = re.compile(r'(\d+): (cluster\d+-socket\d+-core\d+)-commit: wid=(\d+), sid=\d+, PC=(0x[0-9a-f]+), ex=\w+, tmask=([01]+), wb=\d+, rd=\d+, sop=\d+, eop=\d+, data=\{([^}]+)\}')
    with open(filename) as f:
        for line in f:
            m = pat.search(line)
            if m:
                cycle = int(m.group(1))
                core = m.group(2)
                wid = int(m.group(3))
                pc = m.group(4)
                tmask = m.group(5)
                data = m.group(6)
                if int(pc, 16) >= 0x80000000:  # skip garbage init commits
                    commits.append((core, wid, pc, tmask, data, cycle))
    return commits

if __name__ == '__main__':
    mmu = extract_commits('cta.log')
    orig = extract_commits('cta.log.original')
    
    print(f'MMU commits: {len(mmu)}, Original commits: {len(orig)}')
    
    # Compare sequences per core-wid
    from collections import defaultdict
    mmu_by_key = defaultdict(list)
    orig_by_key = defaultdict(list)
    for c in mmu:
        mmu_by_key[(c[0], c[1])].append(c)
    for c in orig:
        orig_by_key[(c[0], c[1])].append(c)
    
    print(f'\\nKeys in MMU: {sorted(mmu_by_key.keys())}')
    print(f'Keys in Orig: {sorted(orig_by_key.keys())}')
    
    for key in sorted(mmu_by_key.keys()):
        ml = mmu_by_key[key]
        ol = orig_by_key.get(key, [])
        if len(ml) != len(ol):
            print(f'\\n{key}: length mismatch MMU={len(ml)} vs Orig={len(ol)}')
        # find first PC divergence
        for i in range(min(len(ml), len(ol))):
            if ml[i][2] != ol[i][2]:
                print(f'\\n{key}: FIRST PC DIVERGENCE at index {i}:')
                print(f'  MMU:  PC={ml[i][2]} tmask={ml[i][3]} data={ml[i][4]} cycle={ml[i][5]}')
                print(f'  Orig: PC={ol[i][2]} tmask={ol[i][3]} data={ol[i][4]} cycle={ol[i][5]}')
                break
        # find first data divergence (same PC but different data)
        for i in range(min(len(ml), len(ol))):
            if ml[i][2] == ol[i][2] and ml[i][4] != ol[i][4]:
                print(f'\\n{key}: FIRST DATA DIVERGENCE at index {i}:')
                print(f'  MMU:  PC={ml[i][2]} tmask={ml[i][3]} data={ml[i][4]} cycle={ml[i][5]}')
                print(f'  Orig: PC={ol[i][2]} tmask={ol[i][3]} data={ol[i][4]} cycle={ol[i][5]}')
                # Show a few more
                count = 0
                for j in range(i+1, min(len(ml), len(ol))):
                    if ml[j][2] == ol[j][2] and ml[j][4] != ol[j][4]:
                        count += 1
                        if count <= 3:
                            print(f'  Also at idx {j}: PC={ml[j][2]}')
                            print(f'    MMU:  data={ml[j][4]} cycle={ml[j][5]}')
                            print(f'    Orig: data={ol[j][4]} cycle={ol[j][5]}')
                print(f'  Total data divergences: {count + 1}')
                break