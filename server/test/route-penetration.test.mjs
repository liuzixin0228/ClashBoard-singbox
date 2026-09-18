import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test, { after } from 'node:test'

const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ange-clashboard-route-test-'))
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

  const rules = [CONTROLLER_RULE('RuleSet', 'geosite', 'PROXY'), CONTROLLER_RULE('Match', '', 'DIRECT')]

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
  const rules = [CONTROLLER_RULE('IpIsPrivate', true, 'DIRECT'), CONTROLLER_RULE('Match', '', 'PROXY')]

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

  const rules = [CONTROLLER_RULE('default', 'rule_set=streaming', 'route(PROXY)'), CONTROLLER_RULE('Match', '', 'DIRECT')]

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
  assert.equal(
    findStrictRuleSetMatchesForTesting({ ...lookup, value: 'flix.com' }, body).length,
    0,
  )
})

test('strict rule set match: bare domain lines and +. wildcard lines match', () => {
  const body = 'www.netflix.com\n+.openai.com\n'

  assert.equal(
    findStrictRuleSetMatchesForTesting(DOMAIN_LOOKUP, body).length,
    1,
  )
  assert.equal(
    findStrictRuleSetMatchesForTesting(
      normalizeLookupInputForTesting('api.openai.com'),
      body,
    ).length,
    1,
  )
})

test('strict rule set match: ip lines never match domain lookups', () => {
  const body = 'IP-CIDR,8.8.8.8/32,no-resolve\n8.8.4.4/32\n'

  assert.equal(findStrictRuleSetMatchesForTesting(DOMAIN_LOOKUP, body).length, 0)
  assert.equal(
    findStrictRuleSetMatchesForTesting(
      normalizeLookupInputForTesting('8.8.8.8'),
      body,
    ).length,
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

  const rules = [CONTROLLER_RULE('default', 'rule_set=geosite-youtube', 'route(YouTube)'), CONTROLLER_RULE('Match', '', 'DIRECT')]

  const result = evaluateRoutePenetrationRulesForTesting(
    normalizeLookupInputForTesting('www.youtube.com'),
    rules,
  )

  assert.ok(result.matched)
  assert.equal(result.matched.outbound, 'YouTube')
  assert.equal(result.matchError, '')
})
