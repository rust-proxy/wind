RFC: The wind ACL Intermediate Representation (acl-ir)
Category: Informational
Date: June 2026

# The wind ACL Intermediate Representation (acl-ir)

## Abstract

`wind-acl` today compiles two surface dialects — Clash/Mihomo rule lines and
Hysteria-style ACL lines — down to a single flat `Vec<wind_core::rule::Rule>`
that is evaluated first-match-wins. This document specifies a richer
intermediate representation (IR), `acl-ir`, modeled on the *engine shape* of
nftables (typed match expressions, named sets, verdict maps, chains with
jump/goto, and statement-then-verdict rules) while keeping the layer-7 match
vocabulary (domain, geosite, process, inbound identity, sniffed protocol) that
nftables itself lacks.

The IR is designed so that the current flat engine is a **strict degenerate
subset** of it: a single base chain whose rules each carry one match and a
`Forward`/`Reject` verdict, with the default outbound as the chain policy,
reproduces the existing behavior byte-for-byte. Every optimization that
collapses ordered rules into the unordered constructs (sets, verdict maps) is
applied **only when it is provably order-invariant**, so the IR preserves
Mihomo's "declaration order = match order" semantics by construction.

This is a design document. No code in this repository is changed by it.

## 1. Introduction

A proxy routing ACL answers one question: *given a destination (and what we
know about the connection), which outbound — if any — serves it?* The reference
model for expressiveness is Mihomo (Clash.Meta), whose ~30 rule types
`wind_core::rule` already mirrors. Hysteria ACL is a strict subset of that
vocabulary. sing-box is a near-peer: it adds connection/environment matchers
(`clash_mode`, `wifi_ssid`, `network_type`, `auth_user`) that the Clash model
lacks, so no single existing dialect is a universal superset.

nftables provides a more general *engine* than any of them — typed expression
matching, named sets and maps with interval/longest-prefix lookup, verdict
maps for O(1) dispatch, chains with `jump`/`goto`/`return`, and a statement
vocabulary (counters, rate limits, marks, NAT/redirect) — but it operates at
L3/L4 and has no concept of domains, geosite, process names, or L7 identity.

`acl-ir` is the deliberate hybrid: **the nftables engine model, extended with
the L7 match vocabulary of Mihomo and sing-box.** It is intended both as the
internal evaluation form for `wind-acl` and as a common compile target into
which the Hysteria, Mihomo, and sing-box dialects can all be lowered.

## 2. Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119].

- **Match**: a boolean expression over a connection's `MatchContext`.
- **Verdict**: a terminal or chain-control decision (forward, reject, drop,
  jump, goto, return, or verdict-map lookup).
- **Statement**: a non-terminal action executed before the verdict when a rule
  matches (counter, log, limit, mark, dnat, sniff).
- **Rule**: `match → statement* → verdict`.
- **Chain**: an ordered list of rules plus a default policy verdict.
- **Set / Verdict map**: named, typed, unordered lookup structures.
- **first-match-wins**: for a connection `c`, the result is the verdict of the
  first rule (in declaration order) whose match contains `c`.
- **`[nft]` / `[L7]`**: marks each construct as a native nftables concept or as
  a layer-7 extension that nftables does not provide.

Notation in this document is illustrative Rust-flavored pseudocode; it is not a
normative API and field names MAY differ in the eventual `wind-acl-ir` crate.

## 3. Data Model

### 3.1. Sets and element types

```rust
// Element type of a named set — analogous to nft `type ipv4_addr` / `inet_service`.
enum ElemType {
    Ip,                    // [nft] CIDR / longest-prefix
    Port,                  // [nft] interval
    Asn,                   // [nft~]
    Domain,                // [L7] nft has no domain type
    GeoTag,                // [L7] geoip / geosite database tag
    Tuple(Vec<ElemType>),  // [nft] concatenation, e.g. `ip . port`
}

// A named set — the unified home for RULE-SET / rule_set / domain-set.
struct NamedSet { name: String, data: SetData }

enum SetData {
    Ips(IpLpmSet),                   // [nft] prefix trie
    Ports(Vec<RangeInclusive<u16>>), // [nft]
    Asns(HashSet<u32>),
    Domains(DomainSet),              // [L7] suffix trie + exact + keyword buckets
    Geo(Vec<String>),               // [L7] resolved against an external DB
    Tuple(Vec<SetData>),             // [nft] concatenated key
}
```

### 3.2. Match expressions

```rust
enum Match {
    // Logical composition
    // [nft anonymous concatenation / sing-box and|or|invert / Mihomo AND|OR|NOT]
    All(Vec<Match>),
    Any(Vec<Match>),
    Not(Box<Match>),
    Always,                                    // MATCH / catch-all

    // Leaf predicates
    Ip   { side: Side, test: IpTest },         // [nft] side = Dst | Src
    Port { side: Side, test: PortTest },       // [nft]
    Proto(NetworkType),                        // [nft] tcp / udp
    Asn  { side: Side, asn: u32 },             // [nft~]
    Geo  { side: Side, code: String },         // [L7] GEOIP / SRC-GEOIP
    Domain(DomainTest),                        // [L7]
    GeoSite(String),                           // [L7]
    Process(ProcessTest),                      // [L7] name/path/regex/uid
    Identity { field: IdField, eq: String },   // [L7] IN-USER / IN-NAME / auth_user / inbound type
    Meta(MetaTest),

    // Set membership: `ip daddr @cn`
    InSet { side: Side, field: SetField, set: String }, // [nft] includes RULE-SET
}

enum IpTest   { Cidr(IpNet), Suffix(IpNet), NoResolve(IpNet) } // no-resolve lives here
enum PortTest { Eq(u16), Range(RangeInclusive<u16>) }
enum DomainTest {
    Exact(String), Suffix(String), Keyword(String),
    Wildcard(Regex), Regex(Regex),
}
enum MetaTest {
    Dscp(u8),                              // [nft]
    CtState(CtState),                      // [nft] new/established/related — new capability
    InboundPort(u16),                      // [L7]
    TimeWindow { from: u32, to: u32 },     // [nft meta time]
    DayOfWeek(u8),                         // [nft meta day]
    ClashMode(String),                     // [L7 sing-box]
    NetworkType(String),                   // [L7 sing-box]
    WifiSsid(String), WifiBssid(String),   // [L7 sing-box]
    SniffedProtocol(String),               // [L7 sing-box protocol]
}
```

### 3.3. Statements, verdicts, and verdict maps

```rust
// Non-terminal: executed in order when a rule matches, then control flows to
// the verdict. [nft statements]
enum Statement {
    Counter,
    Log(String),
    Limit { rate: u32, per: Duration, burst: u32 }, // [nft] rate limit — new capability
    Mark(u32),
    Dnat(TargetAddr),  // [nft] == Hysteria hijack — finally honored
    Sniff,             // [L7] trigger protocol sniffing
}

// Terminal / chain-control. [nft verdicts]
enum Verdict {
    Forward(String),     // pick a named outbound (accept + route)
    Reject(RejectKind),  // reject / block / deny
    Drop,                // silent drop
    Return,              // pop to the calling chain
    Jump(String),        // call a chain, MAY return via Return — SUB-RULE lowers here
    Goto(String),        // tail-call a chain, never returns
    Map { key: MapKey, map: String }, // verdict map: `ip daddr vmap @m` — O(1) dispatch
}

struct VerdictMap {                       // [nft vmap] — Mihomo has no equivalent
    key_type: ElemType,
    entries: Vec<(SetKey, Verdict)>,      // interval / exact keys
    default: Option<Verdict>,
}

struct IrRule { matches: Match, stmts: Vec<Statement>, verdict: Verdict }
struct Chain  { name: String, policy: Verdict, rules: Vec<IrRule> }

struct Ruleset {
    sets:   HashMap<String, NamedSet>,
    maps:   HashMap<String, VerdictMap>,
    chains: HashMap<String, Chain>,
    entry:  String,                       // the base chain to start evaluation at
}
```

## 4. Evaluation Semantics

Evaluation MUST start at `entry` and scan that chain's rules top-to-bottom:

1. For each `IrRule`, evaluate `matches` against the connection's
   `MatchContext`.
2. On a match, execute `stmts` in order, then apply `verdict`.
3. `Forward` / `Reject` / `Drop` terminate evaluation.
4. `Jump(c)` pushes a return frame and continues at chain `c`; `Goto(c)`
   continues at `c` without a return frame; `Return` pops to the caller (or, in
   a base chain, falls through to the policy).
5. `Map { key, map }` looks `key` up in the named verdict map and applies the
   resulting verdict (or the map's `default`, or falls through if neither).
6. If a chain is exhausted without a terminal verdict, its `policy` applies.

Implementations MUST evaluate the rules of a single chain in order. The
ordering guarantee is the foundation on which §6 rests.

## 5. Degenerate Embedding of the Current Engine

The existing `do_route` (flat `Vec<Rule>`, first-match-wins, default outbound
fallback) is exactly the following `Ruleset`:

```rust
Ruleset {
    entry: "main",
    sets: {}, maps: {},
    chains: { "main": Chain {
        name: "main",
        policy: Forward(default_outbound),                 // no-rule-matched fallback
        rules: vec_rule.into_iter()
            .map(|r| IrRule { matches: r.into_match(), stmts: vec![],
                              verdict: r.into_verdict() }) // Forward / Reject
            .collect(),
    }},
}
```

This embedding is normative: any `acl-ir` implementation MUST produce
identical routing decisions to the current engine for inputs that use only the
constructs the current engine supports. `wind_core::RouteAction` need only gain
`Drop` and `Dnat` variants to host the new verdict/statement kinds; existing
`Forward` / `Reject` semantics are unchanged.

## 6. Lowering the Surface Dialects

The following table maps each external rule type to its `acl-ir` form.

| Surface rule | acl-ir lowering |
| --- | --- |
| Hysteria `out addr ports [hijack]` | `IrRule { matches: All([addr, port]), stmts: [hijack → Dnat], verdict: Forward/Reject }` |
| Hysteria `private` / `localhost` | `InSet { Dst, @builtin_private / @builtin_loopback }` (replaces the standalone `GuardConfig`) |
| `DOMAIN` / `-SUFFIX` / `-KEYWORD` / `-WILDCARD` / `-REGEX` | `Match::Domain(Exact/Suffix/Keyword/Wildcard/Regex)` |
| `GEOSITE` | `Match::GeoSite` |
| `IP-CIDR` / `IP-CIDR6` / `IP-SUFFIX` | `Match::Ip { Dst, Cidr/Suffix }`; `,no-resolve` → `IpTest::NoResolve` |
| `IP-ASN` / `GEOIP` | `Match::Asn { Dst }` / `Match::Geo { Dst }` |
| `SRC-IP-CIDR` / `SRC-GEOIP` / `SRC-IP-ASN` | same, `side: Src` |
| `DST-PORT` / `SRC-PORT` (incl. ranges) | `Match::Port { side, Eq/Range }` |
| `NETWORK` | `Match::Proto` |
| `IN-PORT` / `IN-TYPE` / `IN-USER` / `IN-NAME` | `Meta::InboundPort` / `Identity { field, .. }` |
| `PROCESS-NAME(-REGEX)` / `PROCESS-PATH(-REGEX)` / `UID` | `Match::Process(..)` |
| `DSCP` | `Meta::Dscp` |
| `AND` / `OR` / `NOT` | `Match::All` / `Any` / `Not` |
| `SUB-RULE` | a child `Chain` + `Verdict::Jump` |
| `RULE-SET` | `NamedSet` + `Match::InSet` (today a no-op placeholder) |
| `MATCH,target` | `Chain.policy`, or `IrRule { Always, Forward }` |
| target `reject` / `block` / `deny` | `Verdict::Reject` |
| sing-box `and` / `or` / `invert` | `All` / `Any` / `Not` |
| sing-box `rule_set` | `NamedSet` + `InSet` |
| sing-box `clash_mode` / `wifi_ssid` / `network_type` / `auth_user` / `protocol` | `Meta::*` / `Identity` |
| sing-box action `route` / `reject` / `hijack-dns`, `override_*` | `Verdict::Forward` / `Reject` / `Statement::Dnat` |
| nftables `expr → verdict` | 1:1 (this is the parent model) |

`RULE-SET` and `SUB-RULE` are the two cases where `acl-ir` upgrades, rather
than merely re-encodes, the current behavior: `RULE-SET` becomes a real
matchable set instead of the always-false placeholder in
`wind_core::rule::RuleType::RuleSet`, and `SUB-RULE` becomes a real chain call
instead of the AND approximation used today.

## 7. Order-Preserving Optimization

The ordered `Vec<IrRule>` per chain is the **ground truth**. Sets and verdict
maps are unordered lookup structures; collapsing ordered rules into them is an
optimization that MUST be applied only when provably order-invariant.

### 7.1. Soundness invariant

`may_overlap(a, b)` (§7.2) MUST be *sound*: returning `false` MUST imply the
two matches are provably disjoint. When in doubt it MUST return `true`. A
conservative `true` only causes the optimizer to fold less; it can never change
semantics.

### 7.2. Overlap predicate

```rust
// May two rules' matches be satisfied by the same connection?
// `false` MUST be provable; otherwise return `true`.
fn may_overlap(a: &Match, b: &Match) -> bool {
    match (leaf(a), leaf(b)) {
        // Same field & side & single-leaf → field-specific, decidable test.
        (Some(la), Some(lb)) if la.field == lb.field && la.side == lb.side =>
            values_may_overlap(la.field, &la.val, &lb.val),
        // Different fields can be matched together; compound/regex undecidable.
        _ => true,
    }
}

fn values_may_overlap(field: Field, x: &Val, y: &Val) -> bool {
    match field {
        Ip     => ipnet_intersects(x, y),  // CIDR intersection, exact
        Port   => range_intersects(x, y),  // interval intersection, exact
        Proto  => x == y,                  // tcp vs udp never overlap
        Asn    => x == y,
        Geo    => x == y,                  // country codes partition the space
        Domain => domain_may_overlap(x, y),
        _      => x == y,                  // scalar identity / meta
    }
}

fn domain_may_overlap(x: &DomainTest, y: &DomainTest) -> bool {
    use DomainTest::*;
    match (x, y) {
        (Exact(a),  Exact(b))  => a.eq_ignore_ascii_case(b),
        (Suffix(s), Suffix(t)) => is_dot_suffix(s, t) || is_dot_suffix(t, s),
        (Exact(e),  Suffix(s)) | (Suffix(s), Exact(e)) => ends_with_label(e, s),
        _ => true, // Keyword / Wildcard / Regex are not cheaply decidable
    }
}
```

### 7.3. Pass 1 — contiguous same-verdict runs (always safe)

**Theorem.** Merging a *contiguous* run of rules whose `(stmts, verdict)` are
identical into a single rule placed at the run's start position preserves
first-match-wins, with no overlap analysis required.

*Proof sketch.* All members yield the same verdict, so which one "wins"
internally is unobservable. Contiguity means no foreign rule is reordered past.
For a connection matched by the run, no earlier rule matched (those rules keep
their relative position before the merged rule), so the merged rule at the run's
start yields the same verdict. For a connection not matched by the run, the
merged rule does not match and control falls through exactly as before. ∎

Within the run, bucketable leaves are grouped by element type into named sets;
non-bucketable leaves (regex/wildcard/compound) are kept as alternatives of an
`Any`:

```rust
fn bucket_same_verdict(run: &[IrRule], sets: &mut SetTable) -> IrRule {
    let mut alts: Vec<Match> = vec![];
    let mut by_type: HashMap<(Field, Side), Vec<Val>> = map![];
    for r in run {
        match elementize(&r.matches) {            // single leaf usable as a set element?
            Some(leaf) => by_type.entry((leaf.field, leaf.side)).or_default().push(leaf.val),
            None       => alts.push(r.matches.clone()), // kept as-is (still same verdict)
        }
    }
    for ((field, side), vals) in by_type {
        let name = sets.intern(field, vals);       // dedup → NamedSet (prefix trie / suffix trie / ...)
        alts.push(Match::InSet { side, field: set_field(field), set: name });
    }
    IrRule { matches: Match::Any(alts), stmts: run[0].stmts.clone(), verdict: run[0].verdict.clone() }
}
```

### 7.4. Pass 2 — mutually-exclusive verdict maps

A contiguous run of single-leaf rules over the *same* field but with *differing*
verdicts MAY be compiled into a `VerdictMap` **iff the keys are pairwise
disjoint** (so at most one entry can match and order is unobservable):

```rust
fn try_vmap(run: &[IrRule], maps: &mut MapTable) -> Option<IrRule> {
    let (field, side) = single_field(run)?; // all same field & single-leaf, else None
    for (i, a) in run.iter().enumerate() {
        for b in &run[i+1..] {
            if values_may_overlap(field, val(a), val(b)) { return None; } // not exclusive → bail
        }
    }
    let entries = run.iter().map(|r| (key_of(r), r.verdict.clone())).collect();
    let name = maps.intern(field, entries);
    Some(IrRule { matches: Match::Always, stmts: vec![],
                  verdict: Verdict::Map { key: map_key(field, side), map: name } })
}
```

> **IP first-match vs longest-prefix.** Mihomo IP rules are first-declared-wins,
> not longest-prefix. `values_may_overlap(Ip, ..)` returns `true` for
> overlapping CIDRs, so `try_vmap` automatically bails and the rules stay
> ordered. This prevents `IP-CIDR,10.0.0.0/8,DIRECT` followed by
> `IP-CIDR,10.1.0.0/16,PROXY` from being miscompiled into an LPM table that
> would resolve `10.1.0.5` to `PROXY` instead of `DIRECT`.

### 7.5. The compiler

```rust
fn compile(rules: Vec<IrRule>, policy: Verdict) -> Ruleset {
    let (mut sets, mut maps) = (SetTable::new(), MapTable::new());
    let mut out: Vec<IrRule> = vec![];
    let mut i = 0;
    while i < rules.len() {
        // Pass 1: longest contiguous run of identical (stmts, verdict) — always safe.
        let j = run_end(&rules, i, |a, b| a.stmts == b.stmts && a.verdict == b.verdict);
        if j - i >= 2 { out.push(bucket_same_verdict(&rules[i..j], &mut sets)); i = j; continue; }

        // Pass 2: longest contiguous same-field single-leaf run; compile a vmap iff keys disjoint.
        let k = run_end(&rules, i, same_field_single_leaf);
        if k - i >= 2 {
            if let Some(rule) = try_vmap(&rules[i..k], &mut maps) { out.push(rule); i = k; continue; }
        }

        out.push(rules[i].clone()); i += 1; // ordered fallback — always correct
    }
    // Pass 3 (optional, §7.6) may run here.
    Ruleset {
        sets, maps,
        chains: hashmap!{ "main".into() => Chain { name: "main".into(), policy, rules: out } },
        entry: "main".into(),
    }
}
```

### 7.6. Pass 3 — non-adjacent hoisting (optional)

A later same-verdict rule `R_k` MAY be hoisted up to an earlier same-verdict
bucket at position `p` **iff** `R_k` is provably disjoint from every
*different-verdict* rule it would be moved past:

```rust
fn can_hoist(out: &[IrRule], p: usize, rk: &IrRule) -> bool {
    out[p..].iter().all(|r| r.verdict == rk.verdict || !may_overlap(&r.matches, &rk.matches))
}
```

Pass 1 already captures the overwhelmingly common "large block of same-verdict
geoip/port/domain rules" case, so Pass 3 is an optional refinement and MAY be
disabled.

### 7.7. Worked example

```text
Input (declaration order):                  Output Ruleset:
DOMAIN-SUFFIX,ads.ex.com,REJECT             rule0: Domain(Suffix ads.ex.com) → Reject   # kept (diff verdict, overlaps ex.com)
DOMAIN-SUFFIX,google.com,PROXY        ┐
DOMAIN-SUFFIX,github.com,PROXY        ├───►  rule1: InSet @s_proxy_suffix → Forward(proxy)   (Pass 1)
IP-CIDR,1.1.1.0/24,PROXY              ┘            @s_proxy_suffix = {google.com, github.com}
                                                   + IP bucket {1.1.1.0/24} (Any of two InSet)
DST-PORT,80,DIRECT                    ┐
DST-PORT,443,PROXY                    ├───►  rule2: dport vmap @m_port                        (Pass 2, disjoint keys)
DST-PORT,22,DIRECT                    ┘            @m_port = {80:DIRECT, 443:PROXY, 22:DIRECT}
MATCH,direct                                 policy: Forward(direct)
```

## 8. Capabilities Unlocked vs. Remaining Extensions

Net-new capabilities over today's `wind-acl`:

- `NamedSet` turns `RULE-SET` from the always-false placeholder
  (`RuleType::RuleSet(_) => false`) into a real matcher, with prefix-trie IP
  sets and suffix-trie domain sets; `SUB-RULE` becomes a real chain call rather
  than an AND approximation.
- `VerdictMap` gives O(1) dispatch for geoip/port routing instead of a linear
  scan.
- `Statement::Dnat` finally executes Hysteria's `hijack`, which the current
  builder only warns about and ignores.
- `Limit` / `CtState` / `Mark` are entirely new axes inherited from nftables.

What remains an L7 extension that nftables itself cannot provide — i.e. why this
is a hybrid and not nftables: `Domain*`, `GeoSite`, `Process*`, inbound
identity, `Sniff`, and the sing-box environment matchers. These require their
data to be carried in `MatchContext`. Note that `src_ip` and `inbound_user` are
currently always `None` in the route path; populating them is a prerequisite
for the corresponding `Match` kinds to be meaningful and is out of scope here.

## 9. Security Considerations

- **Fail-closed on overlap.** The optimizer's only correctness lever is
  `may_overlap` returning `false`. Because that is required to be sound and
  defaults to `true`, an optimizer bug can at worst leave rules un-folded; it
  cannot silently re-route or un-block traffic. Test suites SHOULD include
  differential checks comparing optimized and unoptimized evaluation over
  randomized contexts.
- **Loopback/private guards.** Lowering the guards to `@builtin_private` /
  `@builtin_loopback` membership rules (§6) MUST preserve the current
  fail-closed behavior, including the requirement that a resolver be present
  when those guards are active.
- **`Dnat`/`hijack`.** Honoring redirect targets changes where traffic is
  sent. It MUST remain opt-in and SHOULD be logged, matching the current
  warn-and-ignore posture until explicitly enabled.

## 10. References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119, March 1997.
- Mihomo (Clash.Meta) rule documentation — rule-type vocabulary mirrored by
  `wind_core::rule`.
- sing-box route rule documentation — source of the environment/identity
  matchers in `MetaTest`.
- nftables documentation — source of the engine model (sets, maps, chains,
  verdicts, statements).
