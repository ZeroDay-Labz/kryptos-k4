# Does the solvekryptos "machine" (f card on cipher letter + g card per pass on helper letter + 1-bit gate)
# carry any evidence?  Count its freedom, and try to make it "decode" K4 into other texts.
import random, sys
sys.setrecursionlimit(10000)
from kryptos import CIPHERTEXT as C
SK = "THECOMPASSROSEISHEREXEASTNORTHEASTTHISISYOURPOSITIONXCOMMISSIONBERLINCLOCKWHICHISNORTHEASTOFHEREX"
HELP = "WXZK" + "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR" + "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY" + "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY"
PASS = [0]*4 + [1]*31 + [2]*31 + [3]*31
assert len(HELP) == 97
edges = [(("f", C[i]), ("g", PASS[i], HELP[i])) for i in range(97)]
nodes = {n for e in edges for n in e}
# components / independent cycles
par = {n: n for n in nodes}
def find(x):
    while par[x] != x:
        par[x] = par[par[x]]; x = par[x]
    return x
cyc = 0
for a, b in edges:
    ra, rb = find(a), find(b)
    if ra == rb: cyc += 1
    else: par[ra] = rb
comps = len({find(n) for n in nodes})
print(f"card cells (unknowns): {len(nodes)}   equations: 97   components: {comps}   independent cycles: {cyc}")
print(f"free numbers left after fitting ANY text: {comps} card values + up to 97 gate bits")

def fit(pt, gates_free=True):
    """Find f/g cards (and gate bits) making the machine output pt. Returns gate list or None."""
    R = [(ord(c) - ord(p)) % 26 for c, p in zip(C, pt)]
    adj = {n: [] for n in nodes}
    for i, (a, b) in enumerate(edges):
        adj[a].append((b, i)); adj[b].append((a, i))
    val, gate = {}, [None] * 97
    order = []            # edges in DFS order per component
    seen_n, seen_e = set(), set()
    for root in sorted(nodes, key=str):
        if root in seen_n: continue
        seen_n.add(root); stack = [root]; order.append(("root", root))
        while stack:
            n = stack.pop()
            for m, i in adj[n]:
                if i in seen_e: continue
                seen_e.add(i); order.append(("edge", i))
                if m not in seen_n:
                    seen_n.add(m); stack.append(m)
    # the stack order above may visit an edge before its far node has a value; do a proper recursive solve
    budget = [2_000_000]
    def solve(k):
        if k == len(order): return True
        budget[0] -= 1
        if budget[0] < 0: return False
        kind, x = order[k]
        if kind == "root":
            val[x] = 0
            if solve(k + 1): return True
            del val[x]; return False
        a, b = edges[x]
        for g in ((0, 1) if gates_free else (0,)):
            need = (R[x] - g) % 26          # f + g_card = need
            if a in val and b in val:
                if (val[a] + val[b]) % 26 == need:
                    gate[x] = g
                    if solve(k + 1): return True
            elif a in val or b in val:
                u, v = (a, b) if a in val else (b, a)
                val[v] = (need - val[u]) % 26; gate[x] = g
                if solve(k + 1): return True
                del val[v]
            else:
                raise RuntimeError("order")
        gate[x] = None
        return False
    return gate if solve(0) else None

print("solvekryptos text, no gate at all:", "fits" if fit(SK, False) else "does not fit")
g = fit(SK); print("solvekryptos text, free gate bits:", "fits" if g else "does not fit", "| gate=1 at", sum(g) if g else "-")
def mk(before, mid, after):
    assert (len(before), len(mid), len(after)) == (21, 29, 23), (len(before), len(mid), len(after))
    return before + "EASTNORTHEAST" + mid + "BERLINCLOCK" + after
# full sentences, exactly 97 letters, no filler letters
alts = {"other message": mk("GOSLOWLYTOWARDTHEDOOR", "ANDSTAYTHEREUNTILYOUSEETHEOLD", "STRIKEMIDNIGHTTHENLEAVE"),
        "opposite": mk("THEROSEISNOTHERELOOKX", "THISISNOTYOURPOSITIONXITISTHE", "THATISSOUTHWESTOFHEREXX"[:23])}
for name, t in alts.items():
    print("   ", t); assert len(t) == 97 and t[21:34] == "EASTNORTHEAST" and t[63:74] == "BERLINCLOCK", (name, len(t), t[21:34], t[63:74])
    print(name, "| no gate:", "fits" if fit(t, False) else "no", "| with gate:", "fits" if fit(t) else "no")
rng = random.Random(1); ok0 = ok1 = 0; T = 300
for _ in range(T):
    t = [chr(65 + rng.randrange(26)) for _ in range(97)]
    t[21:34] = "EASTNORTHEAST"; t[63:74] = "BERLINCLOCK"; t = "".join(t)
    ok0 += fit(t, False) is not None; ok1 += fit(t) is not None
print(f"random gibberish with the clue words in place: {ok0}/{T} fit with no gate, {ok1}/{T} fit with free gate bits")
