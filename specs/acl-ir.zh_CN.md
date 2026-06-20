RFC: wind ACL 中间表示规范 (acl-ir)
Category: Informational
Date: June 2026

# wind ACL 中间表示规范 (acl-ir)

## 摘要

`wind-acl` 目前把两种表层方言——Clash/Mihomo 规则行与 Hysteria 风格 ACL 行
——统一编译成一个扁平的 `Vec<wind_core::rule::Rule>`,按 first-match-wins
求值。本文档规范一种更强的中间表示(IR)`acl-ir`,它借鉴 nftables 的**引擎
形态**(类型化匹配表达式、命名集合、verdict map、带 jump/goto 的链,以及
「语句后裁决」的规则结构),同时保留 nftables 本身缺失的七层匹配词汇(域名、
geosite、进程、入站身份、嗅探协议)。

该 IR 的设计使得当前扁平引擎是它的**严格退化子集**:一个 base chain,其中每
条规则携带单一匹配 + `Forward`/`Reject` 裁决,以默认出站作为链 policy,即可
逐字复刻现有行为。任何把有序规则折叠进无序结构(集合、verdict map)的优化,
**仅在可证明保序时**才会施加,因此该 IR 在构造上保留了 Mihomo 的「声明顺序 =
匹配顺序」语义。

本文档为设计文档,不改动本仓库任何代码。

## 1. 引言

代理路由 ACL 回答一个问题:*给定目的地(以及我们对该连接已知的信息),哪个
出站——若有——为它服务?* 表达力的参照系是 Mihomo (Clash.Meta),其约 30 种
规则类型已被 `wind_core::rule` 镜像。Hysteria ACL 是该词汇的严格子集。
sing-box 则是近似对等:它新增了连接/环境类匹配器(`clash_mode`、`wifi_ssid`、
`network_type`、`auth_user`),这些是 Clash 模型所没有的,因此没有任何单一既
有方言是普适超集。

nftables 提供了比上述任何一者都更通用的**引擎**——类型化表达式匹配、带区间/
最长前缀查找的命名集合与映射、用于 O(1) 派发的 verdict map、带
`jump`/`goto`/`return` 的链,以及一套语句词汇(计数器、限速、打标记、
NAT/重定向)——但它工作在 L3/L4,没有域名、geosite、进程名或 L7 身份的概念。

`acl-ir` 即刻意的混合体:**nftables 的引擎模型,叠加 Mihomo 与 sing-box 的
L7 匹配词汇。** 它既作为 `wind-acl` 的内部求值形态,也作为一个公共编译目标,
让 Hysteria、Mihomo、sing-box 三种方言都能向其降级。

## 2. 约定与术语

本文档中的关键词 "MUST"、"MUST NOT"、"REQUIRED"、"SHALL"、"SHALL NOT"、
"SHOULD"、"SHOULD NOT"、"RECOMMENDED"、"MAY"、"OPTIONAL" 按 [RFC 2119] 解释。

- **Match(匹配)**:对连接 `MatchContext` 求值的布尔表达式。
- **Verdict(裁决)**:终结或链控制决策(forward、reject、drop、jump、goto、
  return,或 verdict-map 查表)。
- **Statement(语句)**:规则命中后、裁决之前按序执行的非终结动作(counter、
  log、limit、mark、dnat、sniff)。
- **Rule(规则)**:`匹配 → 语句* → 裁决`。
- **Chain(链)**:有序规则列表 + 一个默认 policy 裁决。
- **Set / Verdict map**:命名、类型化、无序的查找结构。
- **first-match-wins**:对连接 `c`,结果是声明序中第一条其匹配包含 `c` 的规则
  的裁决。
- **`[nft]` / `[L7]`**:标注每个构件是 nftables 原生概念,还是 nftables 不提供
  的七层扩展。

本文档中的记法为示意性的 Rust 风格伪代码,不是规范性 API;最终 `wind-acl-ir`
crate 中的字段名 MAY 不同。

## 3. 数据模型

### 3.1. 集合与元素类型

```rust
// 命名集合的元素类型 —— 类比 nft 的 `type ipv4_addr` / `inet_service`。
enum ElemType {
    Ip,                    // [nft] CIDR / 最长前缀
    Port,                  // [nft] 区间
    Asn,                   // [nft~]
    Domain,                // [L7] nft 无域名类型
    GeoTag,                // [L7] geoip / geosite 数据库标签
    Tuple(Vec<ElemType>),  // [nft] 拼接,如 `ip . port`
}

// 命名集合 —— RULE-SET / rule_set / domain-set 的统一落点。
struct NamedSet { name: String, data: SetData }

enum SetData {
    Ips(IpLpmSet),                   // [nft] 前缀树
    Ports(Vec<RangeInclusive<u16>>), // [nft]
    Asns(HashSet<u32>),
    Domains(DomainSet),              // [L7] 后缀 trie + exact + keyword 桶
    Geo(Vec<String>),               // [L7] 运行时查外部库
    Tuple(Vec<SetData>),             // [nft] 复合键
}
```

### 3.2. 匹配表达式

```rust
enum Match {
    // 逻辑组合
    // [nft 匿名拼接 / sing-box and|or|invert / Mihomo AND|OR|NOT]
    All(Vec<Match>),
    Any(Vec<Match>),
    Not(Box<Match>),
    Always,                                    // MATCH / 兜底

    // 叶子谓词
    Ip   { side: Side, test: IpTest },         // [nft] side = Dst | Src
    Port { side: Side, test: PortTest },       // [nft]
    Proto(NetworkType),                        // [nft] tcp / udp
    Asn  { side: Side, asn: u32 },             // [nft~]
    Geo  { side: Side, code: String },         // [L7] GEOIP / SRC-GEOIP
    Domain(DomainTest),                        // [L7]
    GeoSite(String),                           // [L7]
    Process(ProcessTest),                      // [L7] name/path/regex/uid
    Identity { field: IdField, eq: String },   // [L7] IN-USER / IN-NAME / auth_user / 入站类型
    Meta(MetaTest),

    // 集合成员:`ip daddr @cn`
    InSet { side: Side, field: SetField, set: String }, // [nft] 含 RULE-SET
}

enum IpTest   { Cidr(IpNet), Suffix(IpNet), NoResolve(IpNet) } // no-resolve 落这里
enum PortTest { Eq(u16), Range(RangeInclusive<u16>) }
enum DomainTest {
    Exact(String), Suffix(String), Keyword(String),
    Wildcard(Regex), Regex(Regex),
}
enum MetaTest {
    Dscp(u8),                              // [nft]
    CtState(CtState),                      // [nft] new/established/related —— 新能力
    InboundPort(u16),                      // [L7]
    TimeWindow { from: u32, to: u32 },     // [nft meta time]
    DayOfWeek(u8),                         // [nft meta day]
    ClashMode(String),                     // [L7 sing-box]
    NetworkType(String),                   // [L7 sing-box]
    WifiSsid(String), WifiBssid(String),   // [L7 sing-box]
    SniffedProtocol(String),               // [L7 sing-box protocol]
}
```

### 3.3. 语句、裁决与 verdict map

```rust
// 非终结:规则命中后按序执行,然后流向裁决。[nft statements]
enum Statement {
    Counter,
    Log(String),
    Limit { rate: u32, per: Duration, burst: u32 }, // [nft] 限速 —— 新能力
    Mark(u32),
    Dnat(TargetAddr),  // [nft] == Hysteria hijack —— 终于被执行
    Sniff,             // [L7] 触发协议嗅探
}

// 终结 / 链控制。[nft verdicts]
enum Verdict {
    Forward(String),     // 选定命名出站(accept + 路由)
    Reject(RejectKind),  // reject / block / deny
    Drop,                // 静默丢弃
    Return,              // 回到调用链
    Jump(String),        // 调子链,MAY 经 Return 返回 —— SUB-RULE 降级于此
    Goto(String),        // 尾调子链,不返回
    Map { key: MapKey, map: String }, // verdict map: `ip daddr vmap @m` —— O(1) 派发
}

struct VerdictMap {                       // [nft vmap] —— Mihomo 无对应
    key_type: ElemType,
    entries: Vec<(SetKey, Verdict)>,      // 区间 / 精确键
    default: Option<Verdict>,
}

struct IrRule { matches: Match, stmts: Vec<Statement>, verdict: Verdict }
struct Chain  { name: String, policy: Verdict, rules: Vec<IrRule> }

struct Ruleset {
    sets:   HashMap<String, NamedSet>,
    maps:   HashMap<String, VerdictMap>,
    chains: HashMap<String, Chain>,
    entry:  String,                       // 求值起始的 base chain
}
```

## 4. 求值语义

求值 MUST 从 `entry` 开始,自上而下扫描该链规则:

1. 对每条 `IrRule`,用连接的 `MatchContext` 求值 `matches`。
2. 命中则按序执行 `stmts`,然后应用 `verdict`。
3. `Forward` / `Reject` / `Drop` 终止求值。
4. `Jump(c)` 压入返回帧并跳到链 `c`;`Goto(c)` 跳到 `c` 但不压返回帧;
   `Return` 弹回调用方(在 base chain 中则落到 policy)。
5. `Map { key, map }` 在命名 verdict map 中查 `key` 并应用所得裁决(或 map 的
   `default`,两者皆无则继续往下)。
6. 链耗尽而无终结裁决时,应用其 `policy`。

实现 MUST 按序求值单链内的规则。该顺序保证是第 6 节的基石。

## 5. 现有引擎的退化嵌入

现有 `do_route`(扁平 `Vec<Rule>`、first-match-wins、默认出站兜底)恰好就是
如下 `Ruleset`:

```rust
Ruleset {
    entry: "main",
    sets: {}, maps: {},
    chains: { "main": Chain {
        name: "main",
        policy: Forward(default_outbound),                 // 无规则命中时的兜底
        rules: vec_rule.into_iter()
            .map(|r| IrRule { matches: r.into_match(), stmts: vec![],
                              verdict: r.into_verdict() }) // Forward / Reject
            .collect(),
    }},
}
```

该嵌入是规范性的:任何 `acl-ir` 实现 MUST 对「仅使用现有引擎所支持构件」的输入
产出与现有引擎完全一致的路由决策。`wind_core::RouteAction` 只需新增 `Drop` 与
`Dnat` 两个变体以承载新的裁决/语句种类;既有 `Forward` / `Reject` 语义不变。

## 6. 表层方言的降级

下表给出每种外部规则类型到 `acl-ir` 形态的映射。

| 表层规则 | acl-ir 降级 |
| --- | --- |
| Hysteria `out addr ports [hijack]` | `IrRule { matches: All([addr, port]), stmts: [hijack → Dnat], verdict: Forward/Reject }` |
| Hysteria `private` / `localhost` | `InSet { Dst, @builtin_private / @builtin_loopback }`(替代独立的 `GuardConfig`) |
| `DOMAIN` / `-SUFFIX` / `-KEYWORD` / `-WILDCARD` / `-REGEX` | `Match::Domain(Exact/Suffix/Keyword/Wildcard/Regex)` |
| `GEOSITE` | `Match::GeoSite` |
| `IP-CIDR` / `IP-CIDR6` / `IP-SUFFIX` | `Match::Ip { Dst, Cidr/Suffix }`;`,no-resolve` → `IpTest::NoResolve` |
| `IP-ASN` / `GEOIP` | `Match::Asn { Dst }` / `Match::Geo { Dst }` |
| `SRC-IP-CIDR` / `SRC-GEOIP` / `SRC-IP-ASN` | 同上,`side: Src` |
| `DST-PORT` / `SRC-PORT`(含区间) | `Match::Port { side, Eq/Range }` |
| `NETWORK` | `Match::Proto` |
| `IN-PORT` / `IN-TYPE` / `IN-USER` / `IN-NAME` | `Meta::InboundPort` / `Identity { field, .. }` |
| `PROCESS-NAME(-REGEX)` / `PROCESS-PATH(-REGEX)` / `UID` | `Match::Process(..)` |
| `DSCP` | `Meta::Dscp` |
| `AND` / `OR` / `NOT` | `Match::All` / `Any` / `Not` |
| `SUB-RULE` | 子 `Chain` + `Verdict::Jump` |
| `RULE-SET` | `NamedSet` + `Match::InSet`(当前为永假占位符) |
| `MATCH,target` | `Chain.policy`,或 `IrRule { Always, Forward }` |
| target `reject` / `block` / `deny` | `Verdict::Reject` |
| sing-box `and` / `or` / `invert` | `All` / `Any` / `Not` |
| sing-box `rule_set` | `NamedSet` + `InSet` |
| sing-box `clash_mode` / `wifi_ssid` / `network_type` / `auth_user` / `protocol` | `Meta::*` / `Identity` |
| sing-box 动作 `route` / `reject` / `hijack-dns`、`override_*` | `Verdict::Forward` / `Reject` / `Statement::Dnat` |
| nftables `expr → verdict` | 1:1(本就是母模型) |

`RULE-SET` 与 `SUB-RULE` 是 `acl-ir` 对当前行为「升级」而非仅「重编码」的两处:
`RULE-SET` 从 `wind_core::rule::RuleType::RuleSet` 的永假占位符变成可真正匹配的
集合;`SUB-RULE` 从当前的 AND 近似变成真正的链调用。

## 7. 保序优化

每条链的有序 `Vec<IrRule>` 是**地面真相**。集合与 verdict map 是无序查找结构;
把有序规则折叠进它们是一种优化,MUST 仅在可证明保序时施加。

### 7.1. 声音性不变式

`may_overlap(a, b)`(见 7.2)MUST 是*声音的*:返回 `false` MUST 蕴含两个匹配
可证明不相交。存疑时 MUST 返回 `true`。保守的 `true` 只会让优化器少折叠,绝不
改写语义。

### 7.2. 重叠判定

```rust
// 两条规则的匹配是否可能被同一连接满足?
// `false` MUST 是可证明的;否则返回 `true`。
fn may_overlap(a: &Match, b: &Match) -> bool {
    match (leaf(a), leaf(b)) {
        // 同 field 同 side 且单叶 → 字段专属的可判定测试。
        (Some(la), Some(lb)) if la.field == lb.field && la.side == lb.side =>
            values_may_overlap(la.field, &la.val, &lb.val),
        // 不同 field 可被同时命中;复合 / regex 不可判定。
        _ => true,
    }
}

fn values_may_overlap(field: Field, x: &Val, y: &Val) -> bool {
    match field {
        Ip     => ipnet_intersects(x, y),  // CIDR 交集,精确
        Port   => range_intersects(x, y),  // 区间交集,精确
        Proto  => x == y,                  // tcp vs udp 必不相交
        Asn    => x == y,
        Geo    => x == y,                  // 国家码划分整个空间
        Domain => domain_may_overlap(x, y),
        _      => x == y,                  // 标量身份 / meta
    }
}

fn domain_may_overlap(x: &DomainTest, y: &DomainTest) -> bool {
    use DomainTest::*;
    match (x, y) {
        (Exact(a),  Exact(b))  => a.eq_ignore_ascii_case(b),
        (Suffix(s), Suffix(t)) => is_dot_suffix(s, t) || is_dot_suffix(t, s),
        (Exact(e),  Suffix(s)) | (Suffix(s), Exact(e)) => ends_with_label(e, s),
        _ => true, // Keyword / Wildcard / Regex 不可廉价判定
    }
}
```

### 7.3. Pass 1 —— 连续同裁决段(永远安全)

**定理。** 把 `(stmts, verdict)` 完全相同的*连续*规则段合并成一条规则、放在该段
起始位置,严格保序,且无需任何重叠分析。

*证明概要。* 段内成员产出同一裁决,内部谁「赢」不可观测。连续性意味着没有外来
规则被跨越。对被该段命中的连接,不存在更早的命中规则(那些规则相对合并规则仍
在其前),故位于段首的合并规则产出同一裁决。对不被该段命中的连接,合并规则不
命中,控制流与之前完全一致地继续往下。∎

段内,可入集的叶子按元素类型归入命名集合;不可入集的叶子(regex/wildcard/复合)
作为 `Any` 的备选保留:

```rust
fn bucket_same_verdict(run: &[IrRule], sets: &mut SetTable) -> IrRule {
    let mut alts: Vec<Match> = vec![];
    let mut by_type: HashMap<(Field, Side), Vec<Val>> = map![];
    for r in run {
        match elementize(&r.matches) {            // 单叶且可作集合元素?
            Some(leaf) => by_type.entry((leaf.field, leaf.side)).or_default().push(leaf.val),
            None       => alts.push(r.matches.clone()), // 原样保留(仍同裁决)
        }
    }
    for ((field, side), vals) in by_type {
        let name = sets.intern(field, vals);       // 去重 → NamedSet(前缀树 / 后缀树 / ...)
        alts.push(Match::InSet { side, field: set_field(field), set: name });
    }
    IrRule { matches: Match::Any(alts), stmts: run[0].stmts.clone(), verdict: run[0].verdict.clone() }
}
```

### 7.4. Pass 2 —— 互斥 verdict map

同一 field、单叶、但裁决各异的连续段,MAY 编译成 `VerdictMap`,**当且仅当键
两两不相交**(从而至多一个条目命中,顺序不可观测):

```rust
fn try_vmap(run: &[IrRule], maps: &mut MapTable) -> Option<IrRule> {
    let (field, side) = single_field(run)?; // 全段同 field 且单叶,否则 None
    for (i, a) in run.iter().enumerate() {
        for b in &run[i+1..] {
            if values_may_overlap(field, val(a), val(b)) { return None; } // 非互斥 → 放弃
        }
    }
    let entries = run.iter().map(|r| (key_of(r), r.verdict.clone())).collect();
    let name = maps.intern(field, entries);
    Some(IrRule { matches: Match::Always, stmts: vec![],
                  verdict: Verdict::Map { key: map_key(field, side), map: name } })
}
```

> **IP 的 first-match vs 最长前缀。** Mihomo 的 IP 规则是先声明先赢,而非最长
> 前缀。`values_may_overlap(Ip, ..)` 对重叠 CIDR 返回 `true`,故 `try_vmap`
> 自动放弃、规则保持有序。这避免了把 `IP-CIDR,10.0.0.0/8,DIRECT` 后接
> `IP-CIDR,10.1.0.0/16,PROXY` 错编译成会把 `10.1.0.5` 解析为 `PROXY`(而非
> `DIRECT`)的 LPM 表。

### 7.5. 编译器

```rust
fn compile(rules: Vec<IrRule>, policy: Verdict) -> Ruleset {
    let (mut sets, mut maps) = (SetTable::new(), MapTable::new());
    let mut out: Vec<IrRule> = vec![];
    let mut i = 0;
    while i < rules.len() {
        // Pass 1:最长「同 (stmts, verdict)」连续段 —— 永远安全。
        let j = run_end(&rules, i, |a, b| a.stmts == b.stmts && a.verdict == b.verdict);
        if j - i >= 2 { out.push(bucket_same_verdict(&rules[i..j], &mut sets)); i = j; continue; }

        // Pass 2:最长「同 field 单叶」连续段;键互斥才编译 vmap。
        let k = run_end(&rules, i, same_field_single_leaf);
        if k - i >= 2 {
            if let Some(rule) = try_vmap(&rules[i..k], &mut maps) { out.push(rule); i = k; continue; }
        }

        out.push(rules[i].clone()); i += 1; // 有序退路 —— 永远正确
    }
    // Pass 3(可选,见 7.6)可在此运行。
    Ruleset {
        sets, maps,
        chains: hashmap!{ "main".into() => Chain { name: "main".into(), policy, rules: out } },
        entry: "main".into(),
    }
}
```

### 7.6. Pass 3 —— 非相邻上提(可选)

靠后的同裁决规则 `R_k` MAY 被上提到位置 `p` 处更早的同裁决桶,**当且仅当**
`R_k` 与它将被移过的每条*异裁决*规则都可证明不相交:

```rust
fn can_hoist(out: &[IrRule], p: usize, rk: &IrRule) -> bool {
    out[p..].iter().all(|r| r.verdict == rk.verdict || !may_overlap(&r.matches, &rk.matches))
}
```

Pass 1 已覆盖绝大多数「大块同裁决 geoip/端口/域名规则」的情形,故 Pass 3 是
可选的精修,MAY 关闭。

### 7.7. 端到端示例

```text
输入(声明序):                              输出 Ruleset:
DOMAIN-SUFFIX,ads.ex.com,REJECT             rule0: Domain(Suffix ads.ex.com) → Reject   # 保留(裁决不同,与 ex.com 重叠)
DOMAIN-SUFFIX,google.com,PROXY        ┐
DOMAIN-SUFFIX,github.com,PROXY        ├───►  rule1: InSet @s_proxy_suffix → Forward(proxy)   (Pass 1)
IP-CIDR,1.1.1.0/24,PROXY              ┘            @s_proxy_suffix = {google.com, github.com}
                                                   + IP 桶 {1.1.1.0/24}(两个 InSet 的 Any)
DST-PORT,80,DIRECT                    ┐
DST-PORT,443,PROXY                    ├───►  rule2: dport vmap @m_port                        (Pass 2,键互斥)
DST-PORT,22,DIRECT                    ┘            @m_port = {80:DIRECT, 443:PROXY, 22:DIRECT}
MATCH,direct                                 policy: Forward(direct)
```

## 8. 解锁的能力 vs 仍属扩展的部分

相对当前 `wind-acl` 的净增能力:

- `NamedSet` 让 `RULE-SET` 从永假占位符(`RuleType::RuleSet(_) => false`)变成
  真匹配,IP 走前缀树、域名走后缀树;`SUB-RULE` 从 AND 近似变成真正的链调用。
- `VerdictMap` 为 geoip/端口路由提供 O(1) 派发,替代线性扫描。
- `Statement::Dnat` 终于执行 Hysteria 的 `hijack`——当前构建器仅警告并忽略。
- `Limit` / `CtState` / `Mark` 是从 nftables 继承的全新维度。

仍属 nftables 自身无法提供的 L7 扩展——即本方案为何是混合体而非 nftables:
`Domain*`、`GeoSite`、`Process*`、入站身份、`Sniff`,以及 sing-box 环境匹配器。
它们要求其数据被携带进 `MatchContext`。注意 `src_ip` 与 `inbound_user` 当前在
路由路径中恒为 `None`;填充它们是对应 `Match` 种类有意义的前提,且不在本文档
范围内。

## 9. 安全考量

- **重叠上的失败即关闭(fail-closed)。** 优化器唯一的正确性杠杆是
  `may_overlap` 返回 `false`。由于它被要求声音且默认 `true`,优化器缺陷最坏只
  会让规则不被折叠,绝不会静默改路由或解除拦截。测试套件 SHOULD 包含差分检查,
  在随机化上下文上比对「优化后」与「未优化」的求值结果。
- **环回/私网守卫。** 把守卫降级为 `@builtin_private` / `@builtin_loopback`
  成员规则(见第 6 节)MUST 保留当前的 fail-closed 行为,包括这些守卫启用时
  必须存在 resolver 的要求。
- **`Dnat`/`hijack`。** 执行重定向目标会改变流量去向。它 MUST 保持显式开启,
  且 SHOULD 记录日志,在显式启用前与当前「警告并忽略」的姿态一致。

## 10. 参考

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119, 1997 年 3 月。
- Mihomo (Clash.Meta) 规则文档 —— `wind_core::rule` 所镜像的规则类型词汇。
- sing-box 路由规则文档 —— `MetaTest` 中环境/身份匹配器的来源。
- nftables 文档 —— 引擎模型(集合、映射、链、裁决、语句)的来源。
