import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test, { after } from 'node:test'

const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'clashboard-singbox-route-test-'))
const dbPath = path.join(tempDir, 'zashboard.sqlite')

process.env.ZASHBOARD_DB_PATH = dbPath

const serverModuleUrl = new URL(`./../index.mjs?test=${Date.now()}`, import.meta.url)
const {
  evaluateRoutePenetrationRulesForTesting,
  findStrictRuleSetMatchesForTesting,
  findStrictRuleSetMatchesFromSourceJson: findStrictRuleSetMatchesFromSourceJsonForTesting,
  normalizeLookupInputForTesting,
  seedRuleProviderCacheForTesting,
  shutdownServer,
} = await import(serverModuleUrl.href)

after(async () => {
  await shutdownServer().catch(() => {})
  await fs.rm(tempDir, { recursive: true, force: true })
})

const DOMAIN_LOOKUP = normalizeLookupInputForTesting('www.netflix.com')
const IP_LOOKUP = normalizeLookupInputForTesting('192.168.1.10')

const CONTROLLER_RULE = (type, payload, proxy, extra = {}) => ({
  type,
  payload,
  proxy,
  ...extra,
})

test('route penetration: first matching rule wins in order', () => {
  seedRuleProviderCacheForTesting([
    {
      name: 'ads',
      behavior: 'domain',
      format: 'text',
      url: 'https://example.test/ads.txt',
      body: 'ads.example.com\n',
    },
  ])

  const rules = [
    CONTROLLER_RULE('RuleSet', 'ads', 'REJECT'),
    CONTROLLER_RULE('DOMAIN-SUFFIX', 'netflix.com', 'PROXY'),
    CONTROLLER_RULE('MATCH', '', 'FINAL-OUT'),
  ]

  const result = evaluateRoutePenetrationRulesForTesting(DOMAIN_LOOKUP, rules)

  assert.ok(result.matched)
  assert.equal(result.matched.index, 1)
  assert.equal(result.matched.outbound, 'PROXY')
  assert.equal(result.matchError, '')
})

test('route penetration: falls back to final rule when nothing matches', () => {
  const rules = [
    CONTROLLER_RULE('DOMAIN-SUFFIX', 'google.com', 'PROXY'),
    CONTROLLER_RULE('Match', '', 'DIRECT'),
  ]

  const result = evaluateRoutePenetrationRulesForTesting(DOMAIN_LOOKUP, rules)

  assert.equal(result.matched, null)
  assert.equal(result.finalOutbound, 'DIRECT')
  assert.equal(result.matchError, '')
})

test('route penetration: missing rule provider cache yields matchError, not false negative', () => {
  const rules = [
    CONTROLLER_RULE('RuleSet', 'streaming', 'PROXY'),
    CONTROLLER_RULE('Match', '', 'DIRECT'),
  ]

  const result = evaluateRoutePenetrationRulesForTesting(DOMAIN_LOOKUP, rules)

  assert.equal(result.matched, null)
  assert.ok(result.matchError.includes('streaming'))
  assert.ok(result.matchError.includes('rule provider cache not found'))
})

test('route penetration: binary .srs cache yields matchError', () => {
  seedRuleProviderCacheForTesting([
    {
      name: 'geosite',
      behavior: 'srs',
      format: 'binary',
      url: 'https://example.test/geosite.srs',
      body: '\x00\x01binary',
    },
  ])

  const rules = [
    CONTROLLER_RULE('RuleSet', 'geosite', 'PROXY'),
    CONTROLLER_RULE('Match', '', 'DIRECT'),
  ]

  const result = evaluateRoutePenetrationRulesForTesting(DOMAIN_LOOKUP, rules)

  assert.equal(result.matched, null)
  assert.ok(result.matchError.includes('.srs'))
})

test('route penetration: matches inside cached rule provider body', () => {
  seedRuleProviderCacheForTesting([
    {
      name: 'streaming',
      behavior: 'domain',
      format: 'text',
      url: 'https://example.test/streaming.txt',
      body: `DOMAIN-SUFFIX,netflix.com
DOMAIN,api.openai.com
`,
    },
  ])

  const rules = [
    CONTROLLER_RULE('RuleSet', 'streaming', 'PROXY'),
    CONTROLLER_RULE('Match', '', 'DIRECT'),
  ]

  const result = evaluateRoutePenetrationRulesForTesting(DOMAIN_LOOKUP, rules)

  assert.ok(result.matched)
  assert.equal(result.matched.index, 0)
  assert.equal(result.matched.outbound, 'PROXY')
})

test('route penetration: sing-box route(...) outbound is unwrapped', () => {
  const rules = [
    CONTROLLER_RULE('RuleSet', 'streaming', 'route(outbound)'),
    CONTROLLER_RULE('Match', '', 'route(outbound)'),
  ]

  const result = evaluateRoutePenetrationRulesForTesting(DOMAIN_LOOKUP, rules)

  assert.ok(result.matched)
  assert.equal(result.matched.outbound, 'outbound')
})

test('route penetration: ip_is_private matches private ip lookups only', () => {
  const rules = [
    CONTROLLER_RULE('IpIsPrivate', true, 'DIRECT'),
    CONTROLLER_RULE('Match', '', 'PROXY'),
  ]

  const privateResult = evaluateRoutePenetrationRulesForTesting(IP_LOOKUP, rules)
  assert.ok(privateResult.matched)
  assert.equal(privateResult.matched.outbound, 'DIRECT')

  const publicResult = evaluateRoutePenetrationRulesForTesting(
    normalizeLookupInputForTesting('8.8.8.8'),
    rules,
  )
  assert.equal(publicResult.matched, null)
  assert.equal(publicResult.finalOutbound, 'PROXY')
})

test('route penetration: ip rules are skipped for domain lookups and vice versa', () => {
  const rules = [
    CONTROLLER_RULE('IP-CIDR', '8.8.8.8/32', 'PROXY'),
    CONTROLLER_RULE('Match', '', 'DIRECT'),
  ]

  const result = evaluateRoutePenetrationRulesForTesting(DOMAIN_LOOKUP, rules)

  // IP 规则对域名查询是"确定性不命中",不算 skippedTypes
  assert.equal(result.matched, null)
  assert.equal(result.finalOutbound, 'DIRECT')
  assert.equal(result.skippedTypes.length, 0)
})

test('route penetration: disabled rules are ignored', () => {
  const rules = [
    CONTROLLER_RULE('DOMAIN-SUFFIX', 'netflix.com', 'PROXY', { disabled: true }),
    CONTROLLER_RULE('Match', '', 'DIRECT'),
  ]

  const result = evaluateRoutePenetrationRulesForTesting(DOMAIN_LOOKUP, rules)

  assert.equal(result.matched, null)
  assert.equal(result.finalOutbound, 'DIRECT')
})

test('route penetration: domain-regex evaluates with regexp semantics', () => {
  const rules = [
    CONTROLLER_RULE('DOMAIN-REGEX', '.*\\.netflix\\.com$', 'PROXY'),
    CONTROLLER_RULE('Match', '', 'DIRECT'),
  ]

  const result = evaluateRoutePenetrationRulesForTesting(DOMAIN_LOOKUP, rules)

  assert.ok(result.matched)
  assert.equal(result.matched.outbound, 'PROXY')
})

test('route penetration: sing-box default payload domain_suffix list matches and unwraps route()', () => {
  const weixinLookup = normalizeLookupInputForTesting('weixin.qq.com')
  const rules = [
    CONTROLLER_RULE(
      'default',
      'domain_suffix=[work.weixin.qq.com weixin.qq.com qq.com...]',
      'route(直连)',
    ),
    CONTROLLER_RULE('Match', '', 'route(默认代理)'),
  ]

  const result = evaluateRoutePenetrationRulesForTesting(weixinLookup, rules)

  assert.ok(result.matched)
  assert.equal(result.matched.index, 0)
  assert.equal(result.matched.outbound, '直连')
  assert.equal(result.matchError, '')
})

test('route penetration: sing-box truncated suffix list without visible match stays unknown', () => {
  const rules = [
    CONTROLLER_RULE('default', 'domain_suffix=[google.com youtube.com...]', 'PROXY'),
    CONTROLLER_RULE('Match', '', 'DIRECT'),
  ]

  const result = evaluateRoutePenetrationRulesForTesting(DOMAIN_LOOKUP, rules)

  // "..." 表示列表被截断,可见值不命中也不能断言整条不命中
  assert.equal(result.matched, null)
  assert.equal(result.matchError, '')
  assert.ok(result.skippedTypes.includes('default'))
  assert.equal(result.finalOutbound, 'DIRECT')
})

test('route penetration: sing-box logical OR and inversion evaluate', () => {
  const rules = [
    CONTROLLER_RULE('logical', 'ip_is_private=true || domain_suffix=netflix.com', 'PROXY'),
    CONTROLLER_RULE('Match', '', 'DIRECT'),
  ]

  const result = evaluateRoutePenetrationRulesForTesting(DOMAIN_LOOKUP, rules)

  assert.ok(result.matched)
  assert.equal(result.matched.outbound, 'PROXY')

  const invertedRules = [
    CONTROLLER_RULE('logical', '!(domain_suffix=douyin.com || domain_suffix=amemv.com)', 'PROXY'),
    CONTROLLER_RULE('Match', '', 'DIRECT'),
  ]

  const invertedResult = evaluateRoutePenetrationRulesForTesting(DOMAIN_LOOKUP, invertedRules)

  // 两个 suffix 都确定不命中 → 取反后整条命中
  assert.ok(invertedResult.matched)
  assert.equal(invertedResult.matched.outbound, 'PROXY')
})

test('route penetration: sing-box default rule_set payload resolves cached provider', () => {
  seedRuleProviderCacheForTesting([
    {
      name: 'streaming',
      behavior: 'domain',
      format: 'text',
      url: 'https://example.test/streaming.txt',
      body: 'DOMAIN-SUFFIX,netflix.com\n',
    },
  ])

  const rules = [
    CONTROLLER_RULE('default', 'rule_set=streaming', 'route(PROXY)'),
    CONTROLLER_RULE('Match', '', 'DIRECT'),
  ]

  const result = evaluateRoutePenetrationRulesForTesting(DOMAIN_LOOKUP, rules)

  assert.ok(result.matched)
  assert.equal(result.matched.outbound, 'PROXY')
})

test('route penetration: sniff/hijack-dns/resolve outbounds do not terminate evaluation', () => {
  seedRuleProviderCacheForTesting([
    {
      name: 'streaming',
      behavior: 'domain',
      format: 'text',
      url: 'https://example.test/streaming.txt',
      body: 'DOMAIN-SUFFIX,netflix.com\n',
    },
  ])

  const rules = [
    CONTROLLER_RULE('default', 'rule_set=streaming', 'sniff(http,tls,500ms)'),
    CONTROLLER_RULE('Match', '', 'DIRECT'),
  ]

  const result = evaluateRoutePenetrationRulesForTesting(DOMAIN_LOOKUP, rules)

  // sniff 是处理型 action,命中后流量继续走后续规则
  assert.equal(result.matched, null)
  assert.equal(result.finalOutbound, 'DIRECT')
})

test('strict rule set match: suffix matches subdomain and apex but not unrelated domains', () => {
  const body = `DOMAIN-SUFFIX,netflix.com\n`
  const lookup = DOMAIN_LOOKUP

  assert.equal(findStrictRuleSetMatchesForTesting(lookup, body).length, 1)
  assert.equal(findStrictRuleSetMatchesForTesting({ ...lookup, value: 'flix.com' }, body).length, 0)
})

test('strict rule set match: bare domain lines and +. wildcard lines match', () => {
  const body = 'www.netflix.com\n+.openai.com\n'

  assert.equal(findStrictRuleSetMatchesForTesting(DOMAIN_LOOKUP, body).length, 1)
  assert.equal(
    findStrictRuleSetMatchesForTesting(normalizeLookupInputForTesting('api.openai.com'), body)
      .length,
    1,
  )
})

test('strict rule set match: ip lines never match domain lookups', () => {
  const body = 'IP-CIDR,8.8.8.8/32,no-resolve\n8.8.4.4/32\n'

  assert.equal(findStrictRuleSetMatchesForTesting(DOMAIN_LOOKUP, body).length, 0)
  assert.equal(
    findStrictRuleSetMatchesForTesting(normalizeLookupInputForTesting('8.8.8.8'), body).length,
    1,
  )
})

test('source json ruleset: decompiled body matches via json matcher', () => {
  const body = JSON.stringify({
    version: 2,
    rules: [
      { domain_suffix: ['ads.youtube.com', 'ggpht.com'] },
      { domain: 'www.youtube.com' },
      { ip_cidr: ['8.8.8.0/24'] },
    ],
  })

  const result = findStrictRuleSetMatchesFromSourceJsonForTesting(
    normalizeLookupInputForTesting('www.youtube.com'),
    body,
  )

  assert.equal(result.uncertain, false)
  assert.equal(result.matches.length, 1)
  assert.equal(result.matches[0].value, 'www.youtube.com')

  const suffixResult = findStrictRuleSetMatchesFromSourceJsonForTesting(
    normalizeLookupInputForTesting('www.ggpht.com'),
    body,
  )
  assert.equal(suffixResult.matches.length, 1)
  assert.equal(suffixResult.matches[0].value, 'ggpht.com')

  const ipResult = findStrictRuleSetMatchesFromSourceJsonForTesting(
    normalizeLookupInputForTesting('8.8.8.8'),
    body,
  )
  assert.equal(ipResult.matches.length, 1)

  const missResult = findStrictRuleSetMatchesFromSourceJsonForTesting(
    normalizeLookupInputForTesting('example.org'),
    body,
  )
  assert.equal(missResult.matches.length, 0)
  assert.equal(missResult.uncertain, false)
})

test('source json ruleset: logical rules keep result uncertain', () => {
  const body = JSON.stringify({
    version: 2,
    rules: [{ type: 'logical', conditions: [{ domain_suffix: ['youtube.com'] }], invert: false }],
  })

  const result = findStrictRuleSetMatchesFromSourceJsonForTesting(
    normalizeLookupInputForTesting('www.youtube.com'),
    body,
  )

  assert.equal(result.uncertain, true)
  assert.equal(result.matches.length, 0)
})

test('evaluate: srs provider with decompiled json body matches without binary map', () => {
  seedRuleProviderCacheForTesting([
    {
      name: 'geosite-youtube',
      behavior: 'srs',
      format: 'binary',
      url: 'https://example.test/youtube.srs',
      body: JSON.stringify({
        version: 2,
        rules: [{ domain_suffix: ['youtube.com'] }, { domain: 'youtu.be' }],
      }),
    },
  ])

  const rules = [
    CONTROLLER_RULE('default', 'rule_set=geosite-youtube', 'route(YouTube)'),
    CONTROLLER_RULE('Match', '', 'DIRECT'),
  ]

  const result = evaluateRoutePenetrationRulesForTesting(
    normalizeLookupInputForTesting('www.youtube.com'),
    rules,
  )

  assert.ok(result.matched)
  assert.equal(result.matched.outbound, 'YouTube')
  assert.equal(result.matchError, '')
})

// ===== DNS 路由推断(parseSingBoxDnsInfoFromConfig / resolveDnsRouteInfo) =====

const {
  parseSingBoxDnsInfoFromConfigForTesting,
  resolveDnsRouteInfoForTesting,
  collectDnsRuleSetNamesForTesting,
  buildDnsQueryPacketForTesting,
  parseDnsResponsePacketForTesting,
  isFakeIpValueForTesting,
  buildSrsMatchMapForTesting,
} = await import(serverModuleUrl.href)

const USER_DNS_CONFIG = {
  dns: {
    servers: [
      { tag: 'dns_dnsmasq', type: 'udp', server: '127.0.0.1', detour: '直连' },
      { tag: 'local', type: 'local' },
      { tag: 'ali', type: 'https', server: '223.5.5.5' },
      { tag: 'google', type: 'https', server: '8.8.8.8', detour: '默认代理' },
      {
        tag: 'fakeip',
        type: 'fakeip',
        inet4_range: '198.19.0.0/16',
        inet6_range: 'fc00::/18',
      },
    ],
    rules: [
      { query_type: ['HTTPS', 'SVCB'], action: 'reject' },
      {
        domain_suffix: ['lzxpm.top', 'lan', 'local', 'home.arpa', 'internal'],
        server: 'dns_dnsmasq',
      },
      { clash_mode: 'Direct', server: 'ali' },
      { clash_mode: 'Global', server: 'fakeip' },
      { domain_suffix: ['m-team.cc'], server: 'ali' },
      { rule_set: ['geosite-fakeipfilter-cn', 'geosite-cn'], server: 'ali' },
      { query_type: ['A', 'AAAA'], server: 'fakeip', rewrite_ttl: 1 },
    ],
    final: 'google',
    strategy: 'prefer_ipv4',
  },
  inbounds: [
    { type: 'tun', tag: 'tun-in' },
    { type: 'dns', tag: 'dns-in', listen: '0.0.0.0', listen_port: 1053 },
  ],
}

test('dns config parse: extracts dns section and dns inbound port', () => {
  const info = parseSingBoxDnsInfoFromConfigForTesting(USER_DNS_CONFIG)

  assert.ok(info)
  assert.equal(info.dns.final, 'google')
  assert.equal(info.dns.servers.length, 5)
  assert.equal(info.dns.rules.length, 7)
  assert.deepEqual(info.dnsInbound, { listen: '0.0.0.0', listen_port: 1053 })

  assert.equal(parseSingBoxDnsInfoFromConfigForTesting({ dns: { servers: [] } }), null)
  assert.equal(parseSingBoxDnsInfoFromConfigForTesting({}), null)
})

test('dns route: rule without explicit action defaults to route (domain_suffix)', () => {
  const info = parseSingBoxDnsInfoFromConfigForTesting(USER_DNS_CONFIG)
  const lookup = normalizeLookupInputForTesting('www.lzxpm.top')

  const result = resolveDnsRouteInfoForTesting(lookup, info, new Map())

  assert.ok(result)
  assert.equal(result.server, 'dns_dnsmasq')
  assert.equal(result.protocol, 'udp')
  assert.equal(result.address, '127.0.0.1')
  assert.equal(result.detour, '直连')
  assert.equal(result.matchedRule.index, 2)
  assert.equal(result.matchedRule.summary, 'domain_suffix×5')
})

test('dns route: single-entry rule_set summary and AND-semantics rule_set match', () => {
  const info = parseSingBoxDnsInfoFromConfigForTesting(USER_DNS_CONFIG)
  const lookup = normalizeLookupInputForTesting('www.m-team.cc')

  const result = resolveDnsRouteInfoForTesting(lookup, info, new Map())

  assert.equal(result.server, 'ali')
  assert.equal(result.matchedRule.index, 5)
  assert.equal(result.matchedRule.summary, 'domain_suffix: m-team.cc')

  const cnLookup = normalizeLookupInputForTesting('www.baidu.com')
  const srsMap = new Map([
    ['geosite-fakeipfilter-cn', { hit: false }],
    ['geosite-cn', { hit: true }],
  ])

  const cnResult = resolveDnsRouteInfoForTesting(cnLookup, info, srsMap)

  // rule_set 条件是 AND 语义:只命中 geosite-cn 不够,还需 geosite-fakeipfilter-cn
  assert.equal(cnResult.server, 'fakeip')
  assert.equal(cnResult.fakeip, true)
  assert.equal(cnResult.matchedRule.index, 7)
})

test('dns route: fakeip rule resolves real upstream by skipping fakeip servers', () => {
  const info = parseSingBoxDnsInfoFromConfigForTesting(USER_DNS_CONFIG)
  const lookup = normalizeLookupInputForTesting('www.example.org')

  const result = resolveDnsRouteInfoForTesting(lookup, info, new Map())

  assert.equal(result.protocol, 'fakeip')
  assert.equal(result.fakeip, true)
  assert.equal(result.matchedRule.index, 7)
  assert.ok(result.realServer)
  assert.equal(result.realServer.server, 'google')
  assert.equal(result.realServer.protocol, 'https')
  assert.equal(result.realServer.address, '8.8.8.8')
  assert.equal(result.realServer.detour, '默认代理')
  assert.equal(result.realServer.isFinal, true)
  assert.equal(result.realServer.matchedRule, null)
})

test('dns route: query_type reject skipped for A preview; clash_mode collected as notes', () => {
  const info = parseSingBoxDnsInfoFromConfigForTesting(USER_DNS_CONFIG)
  const lookup = normalizeLookupInputForTesting('www.tailscale.com')

  const result = resolveDnsRouteInfoForTesting(lookup, info, new Map())

  // query_type [HTTPS,SVCB] 的 reject 规则不应拦住 A 预览
  assert.notEqual(result.rejected, true)
  // clash_mode 规则不参与预判,但作为备注返回
  assert.deepEqual(
    result.clashModes.map((note) => note.mode + '->' + note.server),
    ['Direct->ali', 'Global->fakeip'],
  )
})

test('dns route: domain_regex condition and AND semantics', () => {
  const info = parseSingBoxDnsInfoFromConfigForTesting({
    dns: {
      servers: [
        { tag: 'a', type: 'udp', server: '1.1.1.1' },
        { tag: 'b', type: 'udp', server: '9.9.9.9' },
      ],
      rules: [
        {
          domain_regex: ['^foo-[a-z]+[.]example[.]com$'],
          domain_suffix: ['example.com'],
          server: 'b',
        },
      ],
      final: 'a',
    },
  })

  const hit = resolveDnsRouteInfoForTesting(
    normalizeLookupInputForTesting('foo-bar.example.com'),
    info,
    new Map(),
  )

  assert.equal(hit.server, 'b')
  assert.equal(
    hit.matchedRule.summary,
    'domain_suffix: example.com + domain_regex: ^foo-[a-z]+[.]example[.]com$',
  )

  const miss = resolveDnsRouteInfoForTesting(
    normalizeLookupInputForTesting('other.example.com'),
    info,
    new Map(),
  )

  assert.equal(miss.server, 'a')
  assert.equal(miss.isFinal, true)
})

test('dns route: reject action keeps matched rule info', () => {
  const info = parseSingBoxDnsInfoFromConfigForTesting({
    dns: {
      servers: [{ tag: 'a', type: 'udp', server: '1.1.1.1' }],
      rules: [{ domain_suffix: ['blocked.com'], action: 'reject' }],
      final: 'a',
    },
  })

  const result = resolveDnsRouteInfoForTesting(
    normalizeLookupInputForTesting('x.blocked.com'),
    info,
    new Map(),
  )

  assert.equal(result.rejected, true)
  assert.equal(result.matchedRule.index, 1)
})

test('dns rule-set names are collected from cached dns config', () => {
  const info = parseSingBoxDnsInfoFromConfigForTesting(USER_DNS_CONFIG)

  assert.deepEqual(collectDnsRuleSetNamesForTesting(info), [
    'geosite-fakeipfilter-cn',
    'geosite-cn',
  ])
  assert.deepEqual(collectDnsRuleSetNamesForTesting(null), [])
})

// ===== UDP DNS 报文构造与解析 =====

const encodeNameForTest = (labels) => {
  const chunks = []

  for (const label of labels) {
    chunks.push(Buffer.from([label.length]), Buffer.from(label, 'utf8'))
  }

  chunks.push(Buffer.from([0]))

  return Buffer.concat(chunks)
}

test('dns packet: build query and parse response with compressed names', () => {
  const query = buildDnsQueryPacketForTesting(0x1234, 'www.example.com', 1)

  // header(12) + qname(16) + root(1) + qtype/qclass(4)
  assert.equal(query.length, 12 + 16 + 1 + 4)
  assert.equal(query.readUInt16BE(0), 0x1234)

  // 构造带压缩指针的回答:answer.name 指向 question 里的 www(偏移 12)
  const response = Buffer.concat([
    (() => {
      const header = Buffer.alloc(12)
      header.writeUInt16BE(0x1234, 0)
      header.writeUInt16BE(0x8180, 2) // QR=1 RD=1 RA=1
      header.writeUInt16BE(1, 4) // qd
      header.writeUInt16BE(3, 6) // an
      return header
    })(),
    // question: www.example.com A IN
    encodeNameForTest(['www', 'example', 'com']),
    Buffer.from([0, 1, 0, 1]),
    // answer 1: 名字指针 -> www,CNAME 到 alias(指针指向 question 的 example 标签,rdata 共 8 字节)
    Buffer.from([0xc0, 0x0c]),
    Buffer.from([0, 5, 0, 1]),
    Buffer.from([0, 0, 0, 60]),
    Buffer.from([0, 8]),
    Buffer.from([5]),
    Buffer.from('alias', 'utf8'),
    Buffer.from([0xc0, 0x10]),
    // answer 2: A 1.2.3.4(TTL 256)
    Buffer.from([0xc0, 0x0c]),
    Buffer.from([0, 1, 0, 1]),
    Buffer.from([0, 0, 1, 0]),
    Buffer.from([0, 4]),
    Buffer.from([1, 2, 3, 4]),
    // answer 3: AAAA fd00::34(TTL 30)
    Buffer.from([0xc0, 0x0c]),
    Buffer.from([0, 28, 0, 1]),
    Buffer.from([0, 0, 0, 30]),
    Buffer.from([0, 16]),
    Buffer.concat([Buffer.from([0xfd, 0x00]), Buffer.alloc(13), Buffer.from([0x34])]),
  ])

  const parsed = parseDnsResponsePacketForTesting(response)

  assert.equal(parsed.id, 0x1234)
  assert.equal(parsed.rcode, 0)
  assert.equal(parsed.answers.length, 3)
  assert.equal(parsed.answers[0].type, 5)
  assert.equal(parsed.answers[0].value, '')
  assert.equal(parsed.answers[1].type, 1)
  assert.equal(parsed.answers[1].value, '1.2.3.4')
  assert.equal(parsed.answers[1].ttl, 256)
  assert.equal(parsed.answers[2].type, 28)
  assert.equal(parsed.answers[2].value, 'fd00::34')
})

test('dns packet: fakeip range detection', () => {
  assert.equal(isFakeIpValueForTesting('198.19.0.1'), true)
  assert.equal(isFakeIpValueForTesting('198.18.5.5'), true)
  assert.equal(isFakeIpValueForTesting('198.20.0.1'), false)
  assert.equal(isFakeIpValueForTesting('8.8.8.8'), false)
  assert.equal(isFakeIpValueForTesting('fc00::1234'), true)
  assert.equal(isFakeIpValueForTesting('fc3f::1'), true)
  assert.equal(isFakeIpValueForTesting('fc40::1'), false)
  assert.equal(isFakeIpValueForTesting('fe80::1'), false)
})

test('dns config parse: falls back to dns-tagged inbound without explicit dns type', () => {
  const info = parseSingBoxDnsInfoFromConfigForTesting({
    dns: { servers: [{ tag: 'ali', type: 'https', server: '223.5.5.5' }] },
    inbounds: [
      { type: 'direct', tag: 'dns-in', listen: '::', listen_port: 1053 },
      { type: 'http', tag: 'http-in', listen: '::', listen_port: 8080 },
    ],
  })

  assert.ok(info)
  assert.deepEqual(info.dnsInbound, { listen: '::', listen_port: 1053 })
})

test('dns srs match map: decompiled json provider registers hit for dns rule matching', async () => {
  seedRuleProviderCacheForTesting([
    {
      name: 'geosite-cn',
      behavior: 'srs',
      format: 'binary',
      url: 'https://example.test/geosite-cn.srs',
      body: JSON.stringify({
        version: 2,
        rules: [{ domain_suffix: ['baidu.com'] }, { domain: 'example.org' }],
      }),
    },
    {
      name: 'geoip-cn-text',
      behavior: 'json',
      format: 'source',
      url: 'https://example.test/geoip-cn.json',
      body: '10.0.0.0/8\n',
    },
  ])

  const controllerRules = [
    { type: 'default', payload: 'rule_set=geosite-cn', proxy: '直连' },
    { type: 'default', payload: 'rule_set=geoip-cn-text', proxy: '直连' },
  ]

  const { map } = await buildSrsMatchMapForTesting(controllerRules, 'www.baidu.com', ['geosite-cn'])

  // 反编译 JSON 规则集必须给出确定性命中,否则 DNS 推断会漏掉 domain 类规则集
  assert.equal(map.get('geosite-cn').hit, true)
  // 未命中域名给 false,而不是缺省 undefined
  assert.equal(map.get('geoip-cn-text').hit, false)
})

test('dns route: scalar rule_set condition matches (sing-box allows scalar form)', () => {
  const info = parseSingBoxDnsInfoFromConfigForTesting({
    dns: {
      servers: [{ tag: 'a', type: 'https', server: '223.5.5.5' }],
      rules: [
        { rule_set: 'geosite-cn', server: 'a' },
        { query_type: ['A', 'AAAA'], server: 'fakeip' },
      ],
      final: 'a',
    },
  })

  const srsMap = new Map([['geosite-cn', { hit: true }]])
  const hit = resolveDnsRouteInfoForTesting(
    normalizeLookupInputForTesting('www.baidu.com'),
    info,
    srsMap,
  )

  assert.equal(hit.server, 'a')
  assert.equal(hit.matchedRule.summary, 'rule_set: geosite-cn')

  const srsMapMiss = new Map([['geosite-cn', { hit: false }]])
  const miss = resolveDnsRouteInfoForTesting(
    normalizeLookupInputForTesting('www.baidu.com'),
    info,
    srsMapMiss,
  )

  assert.equal(miss.server, 'fakeip')

  const names = collectDnsRuleSetNamesForTesting({
    dns: { rules: [{ rule_set: 'geosite-cn' }, { rule_set: ['geosite-ai', 'geosite-youtube'] }] },
  })

  assert.deepEqual(names, ['geosite-cn', 'geosite-ai', 'geosite-youtube'])
})
