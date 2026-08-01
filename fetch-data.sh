#!/usr/bin/env bash
# fetch-data.sh — download & condense the reference datasets Panopticon needs.
# These are large, regenerable, public datasets, so they're fetched on setup
# rather than committed. Run once before first use:  ./fetch-data.sh
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p data/static
echo "Panopticon :: fetching reference data into data/static/ ..."

# ── 1. Public Suffix List (correct domain parsing) ──
if [ ! -s data/static/public_suffix_list.dat ]; then
  echo "  [1/3] Public Suffix List ..."
  curl -sL --retry 3 "https://publicsuffix.org/list/public_suffix_list.dat" \
    -o data/static/public_suffix_list.dat
  echo "        $(wc -l < data/static/public_suffix_list.dat) rules"
else echo "  [1/3] PSL already present, skipping"; fi

# ── 2. DuckDuckGo Tracker Radar (broker attribution) ──
if [ ! -s data/static/trackers.tsv ]; then
  echo "  [2/3] Tracker Radar (domain -> owner) ..."
  curl -sL --retry 3 \
    "https://raw.githubusercontent.com/duckduckgo/tracker-radar/main/build-data/generated/domain_map.json" \
    -o /tmp/ddg.json
  python3 - <<'PY'
import json,re
d=json.load(open('/tmp/ddg.json'))
norm={'Google':'Google','Google LLC':'Google','Criteo':'Criteo','Criteo SA':'Criteo',
      'Meta':'Meta','Facebook':'Meta','Microsoft':'Microsoft','Microsoft Corporation':'Microsoft',
      'The Trade Desk':'TradeDesk','Amazon':'Amazon','Adobe':'Adobe','Comscore':'Comscore'}
def short(n):
    if n in norm: return norm[n]
    b=n.split(',')[0].split(' Inc')[0].split(' LLC')[0].split(' SA')[0].strip()
    return norm.get(b,b)
rows=[]
for dom,info in d.items():
    o=info.get('displayName') or info.get('entityName') if isinstance(info,dict) else info
    if o and o.strip(): rows.append(f"{dom}\t{short(o.strip())}")
open('data/static/trackers.tsv','w').write('\n'.join(sorted(set(rows)))+'\n')
print(f"        {len(rows)} tracker domains")
PY
else echo "  [2/3] trackers.tsv already present, skipping"; fi

# local overrides for trackers DDG misses (shipped in-repo, small)
if [ ! -s data/static/trackers_override.tsv ]; then
  cat > data/static/trackers_override.tsv <<'OVR'
html-load.com	Criteo
html-load.cc	Criteo
gum.criteo.com	Criteo
sslwidget.criteo.com	Criteo
static.criteo.net	Criteo
dis.criteo.com	Criteo
OVR
fi

# ── 3. ip2asn (network org resolution) ──
if [ ! -s data/static/asn_v4.tsv ] || [ ! -s data/static/asn_v6.tsv ]; then
  echo "  [3/3] ip2asn (IP range -> org) ..."
  curl -sL --retry 3 "https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz" -o /tmp/asn4.gz
  curl -sL --retry 3 "https://iptoasn.com/data/ip2asn-v6.tsv.gz"     -o /tmp/asn6.gz
  python3 - <<'PY'
import gzip,re
norm={'CLOUDFLARENET':'Cloudflare','GOOGLE':'Google','FACEBOOK':'Meta','AMAZON':'Amazon',
      'MICROSOFT':'Microsoft','FASTLY':'Fastly','AKAMAI':'Akamai','APPLE':'Apple',
      'CRITEO':'Criteo','GITHUB':'GitHub'}
def clean(o):
    up=o.upper()
    for k,v in norm.items():
        if k in up: return v
    o=re.sub(r'^AS\d+\s+','',o)
    o=re.sub(r'[-_](AS|AP|NA|EU|US|IN|APNIC|RIPE|ARIN)([-_](AP|NA|EU|US|IN))?\b','',o)
    o=o.strip(' -_')
    if o.isupper():
        o=' '.join(w.capitalize() if len(w)>2 else w for w in o.split())
    return o[:32]
def cond(src,dst):
    n=0
    with gzip.open(src,'rt') as f,open(dst,'w') as w:
        for l in f:
            p=l.rstrip('\n').split('\t')
            if len(p)<5: continue
            s,e,a,c,org=p[:5]
            if a=='0' or org=='Not routed': continue
            w.write(f"{s}\t{e}\t{clean(org)}\n"); n+=1
    return n
print(f"        v4: {cond('/tmp/asn4.gz','data/static/asn_v4.tsv')} ranges")
print(f"        v6: {cond('/tmp/asn6.gz','data/static/asn_v6.tsv')} ranges")
PY
else echo "  [3/3] ASN tables already present, skipping"; fi

echo "Done. Reference data ready in data/static/"
