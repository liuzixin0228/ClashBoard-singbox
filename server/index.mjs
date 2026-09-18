import express from 'express'
import { execFile, execFileSync } from 'node:child_process'
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import { isIP } from 'node:net'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { Client as SshClient } from 'ssh2'
import { WebSocket, WebSocketServer } from 'ws'
import { isSeq as isYamlSeq, parse as parseYaml, parseDocument as parseYamlDocument } from 'yaml'
import net from 'net'
import os from 'node:os'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const rootDir = path.resolve(__dirname, '..')
const distDir = path.join(rootDir, 'dist')
const dataDir = path.join(rootDir, 'data')
const dbPath = process.env.ZASHBOARD_DB_PATH || path.join(dataDir, 'zashboard.sqlite')
const host = process.env.HOST || '0.0.0.0'
const port = Number(process.env.PORT || 2048)
const backgroundImageStorageKey = '__background_image__'
const execFileAsync = promisify(execFile)
const defaultOpenClashUciConfigPath = '/etc/config/openclash'
const defaultOpenClashConfigDir = '/etc/openclash/config'
const defaultOpenClashPreCustomRulesPath =
  '/etc/openclash/custom/openclash_custom_rules.list'
const defaultOpenClashPostCustomRulesPath =
  '/etc/openclash/custom/openclash_custom_rules_2.list'
const defaultNikkiUciConfigPath = '/etc/config/nikki'
const openClashUciConfigPath =
  process.env.ZASHBOARD_OPENCLASH_UCI_PATH ||
  process.env.OPENCLASH_UCI_PATH ||
  defaultOpenClashUciConfigPath
const openClashConfigDir =
  process.env.ZASHBOARD_OPENCLASH_CONFIG_DIR ||
  process.env.OPENCLASH_CONFIG_DIR ||
  defaultOpenClashConfigDir
const mihomoBinaryPath =
  process.env.ZASHBOARD_MIHOMO_BIN ||
  (process.platform === 'win32'
    ? path.resolve('.tools/mihomo-bin/mihomo-windows-amd64-compatible.exe')
    : path.resolve('.tools/mihomo-bin/mihomo'))
const ruleSearchTempDir = path.join(dataDir, 'rule-search-temp')
const proxyGroupRulePenetrationCache = new Map()
const proxyGroupRulePenetrationCacheBySignature = new Map()
const PROXY_GROUP_RULE_PENETRATION_CACHE_TTL_MS = 10 * 60 * 1000
const PROXY_GROUP_RULE_PENETRATION_CACHE_LIMIT = 16
const DEFAULT_RULE_PROVIDER_AUTO_REFRESH_CHECK_MS = 60 * 1000
const ACCESS_PASSWORD_ENABLED_KEY = 'config/access-password-enabled'
const ACCESS_PASSWORD_KEY = 'config/access-password'
const SETUP_API_LIST_KEY = 'setup/api-list'
const SETUP_ACTIVE_UUID_KEY = 'setup/active-uuid'
const RULE_PROVIDER_SOURCE_METADATA_KEY = 'rule-provider-cache/source-metadata'
const ACCESS_SESSION_COOKIE_NAME = 'ange_clashboard_access_session'
const ACCESS_SESSION_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000
const ACCESS_PASSWORD_REQUIRED_CODE = 'ACCESS_PASSWORD_REQUIRED'
const ACCESS_PASSWORD_INVALID_CODE = 'ACCESS_PASSWORD_INVALID'
const RULE_SOURCE_SSH_REQUIRED_CODE = 'RULE_SOURCE_SSH_REQUIRED'
const accessSessionSecret = randomBytes(32).toString('hex')
const configuredRuleProviderAutoRefreshCheckMs = Number.parseInt(
  String(process.env.ZASHBOARD_RULE_PROVIDER_CACHE_AUTO_REFRESH_CHECK_MS || ''),
  10,
)
const RULE_PROVIDER_AUTO_REFRESH_CHECK_MS =
  Number.isFinite(configuredRuleProviderAutoRefreshCheckMs) &&
  configuredRuleProviderAutoRefreshCheckMs >= 5000
    ? configuredRuleProviderAutoRefreshCheckMs
    : DEFAULT_RULE_PROVIDER_AUTO_REFRESH_CHECK_MS
const serviceWorkerCleanupScript = `
self.addEventListener('install', () => {
  self.skipWaiting()
})

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const cacheKeys = await caches.keys()
    await Promise.all(cacheKeys.map((cacheKey) => caches.delete(cacheKey)))
    await self.registration.unregister()
    const clientsList = await self.clients.matchAll({
      type: 'window',
      includeUncontrolled: true,
    })
    await Promise.all(
      clientsList.map((client) => {
        if ('navigate' in client) {
          return client.navigate(client.url)
        }

        return Promise.resolve()
      }),
    )
  })())
})
`.trim()
const registerSWCleanupScript = `
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.getRegistrations()
    .then((registrations) =>
      Promise.allSettled(registrations.map((registration) => registration.unregister())),
    )
    .then(() => ('caches' in window ? caches.keys() : Promise.resolve([])))
    .then((cacheKeys) => Promise.allSettled(cacheKeys.map((cacheKey) => caches.delete(cacheKey))))
    .catch(() => {})
}
`.trim()

fs.mkdirSync(path.dirname(dbPath), { recursive: true })
fs.mkdirSync(ruleSearchTempDir, { recursive: true })

const db = new DatabaseSync(dbPath)

db.exec(`
  CREATE TABLE IF NOT EXISTS app_storage (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`)

db.exec(`
  CREATE TABLE IF NOT EXISTS rule_provider_cache (
    name TEXT PRIMARY KEY,
    behavior TEXT NOT NULL,
    format TEXT NOT NULL,
    kind TEXT NOT NULL,
    source_url TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL DEFAULT 0,
    body TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`)

const ruleProviderCacheColumns = db
  .prepare(`PRAGMA table_info(rule_provider_cache)`)
  .all()
  .map((row) => row.name)

if (
  !ruleProviderCacheColumns.includes('source_url') ||
  !ruleProviderCacheColumns.includes('interval_seconds') ||
  !ruleProviderCacheColumns.includes('kind') ||
  !ruleProviderCacheColumns.includes('body')
) {
  db.exec('DROP TABLE IF EXISTS rule_provider_cache')
  db.exec(`
    CREATE TABLE rule_provider_cache (
      name TEXT PRIMARY KEY,
      behavior TEXT NOT NULL,
      format TEXT NOT NULL,
      kind TEXT NOT NULL,
      source_url TEXT NOT NULL,
      interval_seconds INTEGER NOT NULL DEFAULT 0,
      body TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `)
}

const getSnapshotStatement = db.prepare(`
  SELECT key, value
  FROM app_storage
  ORDER BY key
`)

const insertSnapshotStatement = db.prepare(`
  INSERT INTO app_storage (key, value, updated_at)
  VALUES (?, ?, CURRENT_TIMESTAMP)
`)

const upsertStorageValueStatement = db.prepare(`
  INSERT INTO app_storage (key, value, updated_at)
  VALUES (?, ?, CURRENT_TIMESTAMP)
  ON CONFLICT(key) DO UPDATE SET
    value = excluded.value,
    updated_at = CURRENT_TIMESTAMP
`)

const getStorageValueStatement = db.prepare(`
  SELECT value
  FROM app_storage
  WHERE key = ?
`)

const deleteStorageValueStatement = db.prepare(`
  DELETE FROM app_storage
  WHERE key = ?
`)

const clearRuleProviderCacheStatement = db.prepare(`
  DELETE FROM rule_provider_cache
`)

const upsertRuleProviderCacheStatement = db.prepare(`
  INSERT INTO rule_provider_cache (
    name,
    behavior,
    format,
    kind,
    source_url,
    interval_seconds,
    body,
    updated_at
  )
  VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
  ON CONFLICT(name) DO UPDATE SET
    behavior = excluded.behavior,
    format = excluded.format,
    kind = excluded.kind,
    source_url = excluded.source_url,
    interval_seconds = excluded.interval_seconds,
    body = excluded.body,
    updated_at = CURRENT_TIMESTAMP
`)

const getCachedRuleProviderStatement = db.prepare(`
  SELECT name, behavior, format, kind, source_url, interval_seconds, body, updated_at
  FROM rule_provider_cache
  ORDER BY name
`)
const getCachedRuleProviderByNameStatement = db.prepare(`
  SELECT name, behavior, format, kind, source_url, interval_seconds, body, updated_at
  FROM rule_provider_cache
  WHERE name = ?
`)
const getRuleProviderCacheTotalCountStatement = db.prepare(`
  SELECT SUM(
    LENGTH(body) - LENGTH(REPLACE(body, CHAR(10), '')) +
    CASE
      WHEN LENGTH(TRIM(body)) = 0 THEN 0
      WHEN body LIKE '%' || CHAR(10) THEN 0
      ELSE 1
    END
  ) AS total
  FROM rule_provider_cache
`)
let activeRuleProviderUpdatePromise = null
let activeRuleProviderUpdateController = null
let ruleProviderAutoRefreshTimer = null
let activeRuleRefreshPromise = null
let activeRuleRefreshController = null
let ruleRefreshRunId = 0
let ruleProviderUpdateState = {
  isUpdating: false,
  totalProviders: 0,
  updatedProviders: 0,
  totalRules: 0,
  errors: 0,
  unsupportedCount: 0,
  cancelled: false,
  completed: false,
}

const createDefaultRuleRefreshState = () => ({
  runId: 0,
  isRefreshing: false,
  scope: 'all',
  providerName: '',
  phase: 'idle',
  totalProviders: 0,
  updatedProviders: 0,
  totalRules: 0,
  errors: 0,
  cancelled: false,
  completed: false,
  lastError: '',
  completedAt: 0,
  updatedAt: Date.now(),
})

let ruleRefreshState = createDefaultRuleRefreshState()

const parseStoredBoolean = (value) => {
  if (typeof value !== 'string') {
    return false
  }

  if (value === 'true' || value === '1') {
    return true
  }

  if (value === 'false' || value === '0' || value === '') {
    return false
  }

  if (value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1) === 'true'
  }

  return false
}

const parseStoredString = (value) => {
  if (typeof value !== 'string' || value === '') {
    return ''
  }

  if (value.startsWith('"') && value.endsWith('"')) {
    try {
      const parsed = JSON.parse(value)

      if (typeof parsed === 'string') {
        return parsed
      }
    } catch {
      // Fall back to the raw value below.
    }
  }

  return value
}

const parseStoredJson = (value, fallback) => {
  if (typeof value !== 'string' || value === '') {
    return fallback
  }

  try {
    return JSON.parse(value)
  } catch {
    return fallback
  }
}

const parseCookies = (cookieHeader) => {
  const cookies = new Map()

  if (typeof cookieHeader !== 'string' || cookieHeader.length === 0) {
    return cookies
  }

  cookieHeader.split(';').forEach((segment) => {
    const separatorIndex = segment.indexOf('=')

    if (separatorIndex === -1) {
      return
    }

    const key = segment.slice(0, separatorIndex).trim()
    const value = segment.slice(separatorIndex + 1).trim()

    if (!key) {
      return
    }

    cookies.set(key, decodeURIComponent(value))
  })

  return cookies
}

const readAccessAuthConfig = () => {
  const enabledRow = getStorageValueStatement.get(ACCESS_PASSWORD_ENABLED_KEY)
  const passwordRow = getStorageValueStatement.get(ACCESS_PASSWORD_KEY)

  return {
    enabled: parseStoredBoolean(enabledRow?.value),
    password: parseStoredString(passwordRow?.value),
  }
}

const readActiveBackendConfig = () => {
  const backendListRow = getStorageValueStatement.get(SETUP_API_LIST_KEY)
  const activeUuidRow = getStorageValueStatement.get(SETUP_ACTIVE_UUID_KEY)
  const backendList = parseStoredJson(backendListRow?.value, [])
  const activeUuid = parseStoredString(activeUuidRow?.value)

  if (!Array.isArray(backendList) || !activeUuid) {
    return null
  }

  return (
    backendList.find(
      (backend) =>
        backend &&
        typeof backend === 'object' &&
        backend.uuid === activeUuid &&
        typeof backend.protocol === 'string' &&
        typeof backend.host === 'string' &&
        typeof backend.port === 'string',
    ) || null
  )
}

const normalizeRuleSourcePlugin = (value) => {
  const normalizedValue = String(value || '').trim().toLowerCase()

  return ['openclash', 'nikki','singbox'].includes(normalizedValue) ? normalizedValue : 'auto'
}

const getErrorMessage = (error) => (error instanceof Error ? error.message : String(error))
const getErrorCode = (error) =>
  error && typeof error === 'object' && typeof error.code === 'string' ? error.code : ''
const getErrorDetail = (error) =>
  error && typeof error === 'object' && typeof error.detail === 'string' ? error.detail : ''

const supportedLocales = ['en-US', 'zh-CN', 'zh-TW', 'ru-RU']
const normalizeLocale = (value = '') => {
  const normalizedValue = String(value || '').trim().toLowerCase()

  if (normalizedValue.startsWith('zh-tw') || normalizedValue.startsWith('zh-hk')) {
    return 'zh-TW'
  }

  if (normalizedValue.startsWith('zh')) {
    return 'zh-CN'
  }

  if (normalizedValue.startsWith('ru')) {
    return 'ru-RU'
  }

  if (normalizedValue.startsWith('en')) {
    return 'en-US'
  }

  return 'zh-CN'
}

const getRequestLocale = (req) => {
  const explicitLocale = req.get('x-zashboard-locale') || ''
  const acceptLanguage = req.get('accept-language') || ''
  const candidate = explicitLocale || acceptLanguage.split(',')[0] || ''

  return normalizeLocale(candidate)
}

const ruleSourceSshRequiredMessages = {
  'en-US': {
    intro:
      'Rule source sync requires an SSH account and password first, and rule source detection must pass.',
    action:
      'Go to "Settings - Backend - Edit backend configuration" > "Rule Source SSH", enter the SSH account and SSH password, choose the correct OpenClash/Nikki/SingBox, then click "Detect rule source".',
    detailPrefix: 'Current error:',
  },
  'zh-CN': {
    intro: '规则源同步需要先配置 SSH 账号和密码，并确保规则源检测通过。',
    action:
      '请在“设置 - 后端 - 修改后端配置”的“规则源 SSH”中填写 SSH 账号、SSH 密码，选择正确的 OpenClash/Nikki/SingBox 后点击“检测规则源”。',
    detailPrefix: '当前错误：',
  },
  'zh-TW': {
    intro: '規則源同步需要先配置 SSH 帳號和密碼，並確保規則源檢測通過。',
    action:
      '請在「設定 - 後端 - 修改後端配置」的「規則源 SSH」中填寫 SSH 帳號、SSH 密碼，選擇正確的 OpenClash/Nikki/SingBox 後點擊「檢測規則源」。',
    detailPrefix: '目前錯誤：',
  },
  'ru-RU': {
    intro:
      'Для синхронизации источников правил сначала укажите SSH-аккаунт и пароль, а затем убедитесь, что проверка источника правил проходит успешно.',
    action:
      'Откройте «Настройки - Бэкенд - Редактировать конфигурацию бэкенда» > «SSH источников правил», введите SSH-аккаунт и SSH-пароль, выберите правильный OpenClash/Nikki/SingBox и нажмите «Проверить источник правил».',
    detailPrefix: 'Текущая ошибка:',
  },
}

const createRuleSourceSshRequiredMessage = (detail = '', locale = 'zh-CN') => {
  const messages =
    ruleSourceSshRequiredMessages[supportedLocales.includes(locale) ? locale : normalizeLocale(locale)] ||
    ruleSourceSshRequiredMessages['zh-CN']
  const message = [messages.intro, messages.action]

  if (detail) {
    message.push(`${messages.detailPrefix}${detail}`)
  }

  return message.join(' ')
}

const getLocalizedErrorMessage = (error, req) => {
  if (getErrorCode(error) === RULE_SOURCE_SSH_REQUIRED_CODE) {
    return createRuleSourceSshRequiredMessage(getErrorDetail(error), getRequestLocale(req))
  }

  return getErrorMessage(error)
}

const createRuleSourceSshRequiredError = (detail = '') => {
  const message = createRuleSourceSshRequiredMessage(detail)
  const error = new Error(message)
  error.code = RULE_SOURCE_SSH_REQUIRED_CODE
  error.detail = detail

  return error
}

const readOpenWrtRuleSourceSshConfig = () => {
  const backend = readActiveBackendConfig()
  const host = parseStoredString(process.env.ZASHBOARD_OPENWRT_SSH_HOST || backend?.host)
  const port =
    Number.parseInt(
      parseStoredString(
        process.env.ZASHBOARD_OPENWRT_SSH_PORT ||
          backend?.ruleSourceSshPort ||
          '22',
      ),
      10,
    ) || 22
  const username = parseStoredString(
    process.env.ZASHBOARD_OPENWRT_SSH_USER ||
      process.env.ZASHBOARD_OPENWRT_SSH_USERNAME ||
      backend?.ruleSourceSshUsername ||
      'root',
  )
  const password = parseStoredString(
    process.env.ZASHBOARD_OPENWRT_SSH_PASSWORD || backend?.ruleSourceSshPassword,
  )
  const plugin = normalizeRuleSourcePlugin(
    process.env.ZASHBOARD_RULE_SOURCE_PLUGIN || backend?.ruleSourcePlugin || 'auto',
  )

  // host 指向本机(127.0.0.1/localhost 等)时走本地文件读取,不需要 SSH 账号密码;
  // 远程模式仍然要求 host + username + password 三者齐备
  const isLocal = isLocalHost(host)

  return {
    host,
    port,
    username,
    password,
    plugin,
    isLocal,
    configured: isLocal ? Boolean(host) : Boolean(host && username && password),
  }
}

const sanitizeOpenWrtRuleSourceSshConfig = (config) => {
  const isLocal = isLocalHost(config.host)

  return {
    host: config.host || '',
    port: config.port || 22,
    username: config.username || 'root',
    password: config.password || '',
    plugin: normalizeRuleSourcePlugin(config.plugin || 'auto'),
    isLocal,
    configured: isLocal ? Boolean(config.host) : Boolean(config.host && config.username && config.password),
  }
}

/**
 * 判断 host 是否为本地 Loopback 或本机地址
 * @param {string} host
 * @returns {boolean}
 */
const isLocalHost = (host) => {
  const normalizedHost = String(host || '').trim().toLowerCase()

  if (
    !normalizedHost ||
    normalizedHost === 'localhost' ||
    normalizedHost === '127.0.0.1' ||
    normalizedHost === '::1' ||
    normalizedHost === '0.0.0.0'
  ) {
    return true
  }

  if (net.isIPv4(normalizedHost) && normalizedHost.startsWith('127.')) {
    return true
  }

  return false
}

/**
 * 标准化 OpenWrt 规则源配置输入（自动兼容本地模式与旧字段）
 * @param {Object} [input={}]
 * @returns {Object}
 */
export const normalizeOpenWrtRuleSourceSshConfigInput = (input = {}) => {
  const host = String(input.host || input.ruleSourceSshHost || '').trim()
  const port = Number.parseInt(String(input.port || input.ruleSourceSshPort || '22'), 10)

  // 判定是否为本地模式
  const isLocal = isLocalHost(host)

  return {
    isLocal,
    filePath: String(input.filePath || input.ruleSourceFilePath || '').trim(),
    host: isLocal ? '127.0.0.1' : host,
    port: Number.isFinite(port) && port > 0 ? port : 22,
    username: String(input.username || input.user || input.ruleSourceSshUsername || 'root').trim() || 'root',
    password: String(input.password || input.ruleSourceSshPassword || ''),
    plugin: normalizeRuleSourcePlugin(input.plugin || input.ruleSourcePlugin || 'auto'),
  }
}

const saveOpenWrtRuleSourceSshConfig = (config) => {
  const backendListRow = getStorageValueStatement.get(SETUP_API_LIST_KEY)
  const activeUuidRow = getStorageValueStatement.get(SETUP_ACTIVE_UUID_KEY)
  const backendList = parseStoredJson(backendListRow?.value, [])
  const activeUuid = parseStoredString(activeUuidRow?.value)

  if (!Array.isArray(backendList) || !activeUuid) {
    throw new Error('No active backend configured')
  }

  const backendIndex = backendList.findIndex((backend) => backend?.uuid === activeUuid)

  if (backendIndex === -1) {
    throw new Error('No active backend configured')
  }

  backendList[backendIndex] = {
    ...backendList[backendIndex],
    ruleSourcePlugin: normalizeRuleSourcePlugin(config.plugin || 'auto'),
    ruleSourceSshPort: String(config.port || 22),
    ruleSourceSshUsername: config.username || 'root',
    ruleSourceSshPassword: config.password || '',
  }

  upsertStorageValueStatement.run(SETUP_API_LIST_KEY, JSON.stringify(backendList))
}

const shellQuote = (value) => `'${String(value).replace(/'/g, "'\\''")}'`

const connectOpenWrtSsh = (config) => {
  return new Promise((resolve, reject) => {
    const client = new SshClient()
    let settled = false
    const settle = (callback, value) => {
      if (settled) return
      settled = true
      callback(value)
    }

    client
      .on('ready', () => settle(resolve, client))
      .on('keyboard-interactive', (_name, _instructions, _lang, prompts, finish) => {
        finish(prompts.map(() => config.password))
      })
      .on('close', () => {
        settle(reject, new Error('OpenWrt SSH connection closed before it was ready.'))
      })
      .on('error', (error) => settle(reject, error))
      .connect({
        host: config.host,
        port: config.port || 22,
        username: config.username || 'root',
        password: config.password,
        tryKeyboard: true,
        readyTimeout: 10000,
      })
  })
}

const sshExec = (client, command, options = {}) => {
  const maxBuffer = options.maxBuffer || 8 * 1024 * 1024

  return new Promise((resolve, reject) => {
    client.exec(command, (error, stream) => {
      if (error) {
        reject(error)
        return
      }

      let stdout = ''
      let stderr = ''
      let stdoutBytes = 0
      let stderrBytes = 0

      stream
        .on('error', reject)
        .on('close', (code) => {
          resolve({
            code,
            stdout,
            stderr,
          })
        })
        .on('data', (chunk) => {
          stdoutBytes += chunk.length
          if (stdoutBytes > maxBuffer) {
            stream.destroy(new Error('SSH command output is too large'))
            return
          }
          stdout += chunk.toString('utf8')
        })
        .stderr.on('data', (chunk) => {
          stderrBytes += chunk.length
          if (stderrBytes > maxBuffer) {
            stream.destroy(new Error('SSH command error output is too large'))
            return
          }
          stderr += chunk.toString('utf8')
        })
    })
  })
}

const withOpenWrtSshClient = async (config, callback) => {
  if (!config.host || !config.username || !config.password) {
    throw new Error('OpenWrt SSH is not configured. Set host, username and password first.')
  }

  const client = await connectOpenWrtSsh(config)

  try {
    return await callback(client)
  } finally {
    client.end()
  }
}

const remoteFileExists = async (client, filePath) => {
  const result = await sshExec(client, `[ -f ${shellQuote(filePath)} ] && printf 1 || printf 0`, {
    maxBuffer: 1024,
  })

  return result.stdout.trim() === '1'
}

const readRemoteFile = async (client, filePath) => {
  const result = await sshExec(client, `cat ${shellQuote(filePath)}`)

  if (result.code !== 0) {
    throw new Error(result.stderr.trim() || `Failed to read remote file: ${filePath}`)
  }

  return result.stdout
}

const writeRemoteFile = async (client, filePath, content) => {
  await new Promise((resolve, reject) => {
    client.sftp((error, sftp) => {
      if (error) {
        reject(error)
        return
      }

      sftp.writeFile(filePath, content, 'utf8', (writeError) => {
        sftp.end()

        if (writeError) {
          reject(writeError)
          return
        }

        resolve()
      })
    })
  })
}

const remotePathExists = async (client, filePath) => {
  const result = await sshExec(client, `[ -e ${shellQuote(filePath)} ] && printf 1 || printf 0`, {
    maxBuffer: 1024,
  })

  return result.stdout.trim() === '1'
}

const dedupeStrings = (values) => [...new Set(values.map((value) => String(value || '').trim()).filter(Boolean))]

const isRemoteYamlPath = (value) => /^\/\S+\.ya?ml$/i.test(String(value || '').trim())



function extractRemoteYamlConfigPathsFromUci(content) {
  const candidates = []

  String(content || '')
    .split(/\r?\n/)
    .forEach((line) => {
      const match = /^\s*(?:option|list)\s+\S+(?:\s+|=)(.+?)\s*$/.exec(line)

      if (!match) {
        return
      }

      const value = parseUciValue(match[1])

      if (isRemoteYamlPath(value)) {
        candidates.push(value)
      }
    })

  return dedupeStrings([
    ...candidates,
    ...extractRemoteYamlConfigPathsFromText(content),
  ])
}

const isOpenClashOwnedPath = (value) =>
  /(?:^|\/)openclash(?:\/|$)/i.test(String(value || '').trim())

const isNikkiProcessLine = (line) =>
  /\bnikki\b|\/nikki(?:\/|$)/i.test(String(line || ''))
function extractNikkiYamlConfigPathsFromProcessList(content) {
  return dedupeStrings(
    String(content || '')
      .split(/\r?\n/)
      .filter(isNikkiProcessLine)
      .flatMap((line) => extractRemoteYamlConfigPathsFromText(line))
      .filter((candidate) => !isOpenClashOwnedPath(candidate)),
  )
}


// eslint-disable-next-line @typescript-eslint/no-unused-vars
function isRemoteJsonPath(value) {
  return /^\/.+\.json$/i.test(String(value || '').trim())
}

const setRuleRefreshState = (partial) => {
  ruleRefreshState = {
    ...ruleRefreshState,
    ...partial,
    updatedAt: Date.now(),
  }
}

const createAccessSessionToken = (password) => {
  return createHmac('sha256', accessSessionSecret).update(password).digest('base64url')
}

const safeTokenEquals = (left, right) => {
  if (typeof left !== 'string' || typeof right !== 'string') {
    return false
  }

  const leftBuffer = Buffer.from(left)
  const rightBuffer = Buffer.from(right)

  if (leftBuffer.length !== rightBuffer.length) {
    return false
  }

  return timingSafeEqual(leftBuffer, rightBuffer)
}

const isAccessSessionAuthenticated = (cookieHeader, password) => {
  if (!password) {
    return false
  }

  const token = parseCookies(cookieHeader).get(ACCESS_SESSION_COOKIE_NAME)

  if (!token) {
    return false
  }

  return safeTokenEquals(token, createAccessSessionToken(password))
}

const getRequestAccessAuthStatus = (req) => {
  const config = readAccessAuthConfig()

  if (!config.enabled) {
    return {
      enabled: false,
      authenticated: true,
    }
  }

  return {
    enabled: true,
    authenticated: isAccessSessionAuthenticated(req.headers.cookie, config.password),
  }
}

const getUpgradeAccessAuthStatus = (request) => {
  const config = readAccessAuthConfig()

  if (!config.enabled) {
    return {
      enabled: false,
      authenticated: true,
    }
  }

  return {
    enabled: true,
    authenticated: isAccessSessionAuthenticated(request.headers.cookie, config.password),
  }
}

const setAccessSessionCookie = (res, password) => {
  res.cookie(ACCESS_SESSION_COOKIE_NAME, createAccessSessionToken(password), {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: ACCESS_SESSION_MAX_AGE_MS,
    path: '/',
  })
}

const clearAccessSessionCookie = (res) => {
  res.clearCookie(ACCESS_SESSION_COOKIE_NAME, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
  })
}

const sendAccessPasswordRequired = (res) => {
  res.setHeader('Cache-Control', 'no-store')
  clearAccessSessionCookie(res)
  res.status(401).json({
    code: ACCESS_PASSWORD_REQUIRED_CODE,
    message: 'Access password authentication required',
    enabled: true,
    authenticated: false,
  })
}

const readSnapshot = () => {
  const snapshot = {}

  for (const row of getSnapshotStatement.all()) {
    if (row.key === backgroundImageStorageKey) continue
    snapshot[row.key] = row.value
  }

  return snapshot
}

const replaceSnapshot = (entries) => {
  db.exec('BEGIN')

  try {
    db.prepare('DELETE FROM app_storage WHERE key != ?').run(backgroundImageStorageKey)

    for (const [key, value] of Object.entries(entries)) {
      insertSnapshotStatement.run(key, value)
    }

    db.exec('COMMIT')
  } catch (error) {
    db.exec('ROLLBACK')
    throw error
  }
}

const isValidEntries = (entries) => {
  return (
    entries &&
    typeof entries === 'object' &&
    !Array.isArray(entries) &&
    Object.entries(entries).every(
      ([key, value]) => typeof key === 'string' && typeof value === 'string',
    )
  )
}

function stripUciInlineComment(value) {
  let quote = ''
  let escaped = false

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]

    if (escaped) {
      escaped = false
      continue
    }

    if (quote) {
      if (quote === '"' && character === '\\') {
        escaped = true
        continue
      }

      if (character === quote) {
        quote = ''
      }

      continue
    }

    if (character === "'" || character === '"') {
      quote = character
      continue
    }

    if (character === '#') {
      return value.slice(0, index).trim()
    }
  }

  return value.trim()
}

function parseUciValue(value) {
  const normalizedValue = stripUciInlineComment(String(value || '')).trim()

  if (!normalizedValue) {
    return ''
  }

  const quote = normalizedValue[0]

  if (quote === "'" || quote === '"') {
    let parsedValue = ''
    let escaped = false

    for (let index = 1; index < normalizedValue.length; index += 1) {
      const character = normalizedValue[index]

      if (escaped) {
        parsedValue += character
        escaped = false
        continue
      }

      if (quote === '"' && character === '\\') {
        escaped = true
        continue
      }

      if (character === quote) {
        return parsedValue.trim()
      }

      parsedValue += character
    }

    return parsedValue.trim()
  }

  return normalizedValue.split(/\s+/)[0] || ''
}

function getUciSectionOptionValue(content, sectionType, optionName) {
  let isTargetSection = false
  let optionValue = ''

  String(content || '')
    .split(/\r?\n/)
    .forEach((line) => {
      const sectionMatch = /^\s*config\s+(\S+)/.exec(line)

      if (sectionMatch) {
        isTargetSection = sectionMatch[1] === sectionType
        return
      }

      if (!isTargetSection) {
        return
      }

      const optionMatch = new RegExp(`^\\s*option\\s+${optionName}(?:\\s+|=)(.+?)\\s*$`).exec(line)

      if (optionMatch) {
        optionValue = parseUciValue(optionMatch[1])
      }
    })

  return optionValue
}

const isUciEnabled = (value) => ['1', 'true', 'yes', 'on', 'enabled'].includes(String(value || '').trim().toLowerCase())

const isOpenWrtCustomRuleEnabled = (plugin, uciContent) => {
  if (plugin === 'openclash') {
    return isUciEnabled(getUciSectionOptionValue(uciContent, 'openclash', 'enable_custom_clash_rules'))
  }

  if (plugin === 'nikki') {
    return isUciEnabled(getUciSectionOptionValue(uciContent, 'mixin', 'rule'))
  }

  return false
}

function getOpenClashConfigPathFromUci(content) {
  const configPaths = []

  String(content || '')
    .split(/\r?\n/)
    .forEach((line) => {
      const match = /^\s*option\s+config_path(?:\s+|=)(.+?)\s*$/.exec(line)

      if (!match) {
        return
      }

      const configPath = parseUciValue(match[1])

      if (configPath) {
        configPaths.push(configPath)
      }
    })

  return configPaths.at(-1) || ''
}

function resolveOpenClashConfigPathValue(configPath, options = {}) {
  const normalizedConfigPath = String(configPath || '').trim()

  if (!normalizedConfigPath) {
    return ''
  }

  const pathApi = options.pathApi || path

  if (pathApi.isAbsolute(normalizedConfigPath)) {
    return pathApi.normalize(normalizedConfigPath)
  }

  const configDir = options.configDir || openClashConfigDir
  const uciConfigPath = options.uciConfigPath || openClashUciConfigPath
  const candidates = options.preferExisting === false
    ? [pathApi.resolve(configDir, normalizedConfigPath)]
    : [
        pathApi.resolve(configDir, normalizedConfigPath),
        pathApi.resolve(pathApi.dirname(uciConfigPath), normalizedConfigPath),
      ]
  const existingCandidate =
    options.preferExisting === false
      ? ''
      : candidates.find((candidate) => fs.existsSync(candidate))

  return existingCandidate || candidates[0]
}

function resolveOpenClashConfigPathFromUci(content, options = {}) {
  return resolveOpenClashConfigPathValue(getOpenClashConfigPathFromUci(content), options)
}

function extractRuleProviderEntriesFromContent(content) {
  const parsed = parseYaml(content)
  const providers = parsed?.['rule-providers']

  if (!providers || typeof providers !== 'object') {
    return []
  }

  return Object.entries(providers)
    .map(([name, provider]) => {
      if (!provider || typeof provider !== 'object') {
        return null
      }

      const url = normalizeRuleProviderUrl(provider.url)

      if (typeof url !== 'string' || !url) {
        return null
      }

      return {
        name,
        behavior: typeof provider.behavior === 'string' ? provider.behavior : '',
        format: typeof provider.format === 'string' ? provider.format : '',
        interval:
          typeof provider.interval === 'number'
            ? provider.interval
            : Number.parseInt(String(provider.interval || '0'), 10) || 0,
        url,
      }
    })
    .filter(Boolean)
}

const getNikkiRuleSourceConfigPathCandidates = async (client, config = {}) => {
  const isLocal = Boolean(config.isLocal)

  // 【本地模式】：直接返回 Mac 本地常见的 Nikki 配置路径（以及可能的 config.filePath）
  if (isLocal) {
    return dedupeStrings([
      ...(config.filePath ? [config.filePath] : []),
      '/usr/local/etc/nikki/config.yaml',
      '/usr/local/etc/nikki/config.yml',
      '/Users/liuzixin/.config/nikki/config.yaml',
      './config.yaml',
      './config.yml',
    ])
  }

  // 【远程模式】：保持你原本强大的 ps 进程与 UCI 自动推导逻辑
  const processResult = await sshExec(client, 'ps ww || ps w || ps', {
    maxBuffer: 256 * 1024,
  }).catch(() => null)
  const processCandidates = extractNikkiYamlConfigPathsFromProcessList(processResult?.stdout || '')
  const uciCandidates = []

  if (await remoteFileExists(client, '/etc/config/nikki')) {
    const uciContent = await readRemoteFile(client, '/etc/config/nikki')
    uciCandidates.push(
      ...extractRemoteYamlConfigPathsFromUci(uciContent).filter(
        (candidate) => !isOpenClashOwnedPath(candidate),
      ),
    )
  }

  return dedupeStrings([
    ...processCandidates,
    ...uciCandidates,
    '/etc/nikki/run/config.yaml',
    '/etc/nikki/run/config.yml',
    '/var/etc/nikki/config.yaml',
    '/var/run/nikki/config.yaml',
    '/tmp/etc/nikki/config.yaml',
  ])
}

const detectNikkiRuleSourceFromOpenWrtClient = async (client, config = {}) => {
  const isLocal = Boolean(config.isLocal)

  // 1. ⚠️ 关键修复：必须把 config 传给候选路径获取函数，防止它误走 SSH 执行 ps 命令
  const configPathCandidates = await getNikkiRuleSourceConfigPathCandidates(client, config)
  const checkedExistingPaths = []

  for (const configPath of configPathCandidates) {
    // 2. 文件存在性检查（自动兼容 本地/SSH）
    if (!(await fileExistsSafe(client, configPath, isLocal))) {
      continue
    }

    checkedExistingPaths.push(configPath)

    // 3. 读取文件内容（自动兼容 本地/SSH）
    const content = await readFileSafe(client, configPath, isLocal)
    const providers = extractRuleProviderEntriesFromContent(content)

    if (providers.length === 0) {
      continue
    }

    return {
      plugin: 'nikki',
      configPath,
      providers,
    }
  }

  // 4. ⚠️ 关键修复：本地模式 (isLocal) 直接跳过远程 OpenWrt 目录探测，严禁传入 null 的 client
  const hasNikkiDir = !isLocal && client && (
    (await remoteFileExists(client, '/etc/config/nikki')) ||
    (await remotePathExists(client, '/etc/nikki'))
  )

  if (checkedExistingPaths.length > 0 || hasNikkiDir) {
    throw new Error(
      `Nikki detected, but no readable YAML with rule-providers was found${
        checkedExistingPaths.length > 0 ? `: ${checkedExistingPaths.join(', ')}` : ''
      }.`,
    )
  }

  return null
}

// 提取规则集（route.rule_set）的解析函数
const extractSingBoxRuleSetEntriesFromContent = (content) => {
  try {
    if (content == null) return []

    let text = ''
    if (Buffer.isBuffer(content)) {
      text = content.toString('utf8')
    } else if (content instanceof Uint8Array) {
      text = Buffer.from(content).toString('utf8')
    } else if (typeof content === 'string') {
      text = content
    } else if (typeof content === 'object') {
      text = JSON.stringify(content)
    }

    if (!text.trim()) return []

    // 清理注释

    const config = JSON.parse(text)

    // 兼容 route.rule_set 或顶层 rule_set
    const ruleSets = config?.route?.rule_set || config?.rule_set
    if (!Array.isArray(ruleSets)) return []

    return ruleSets
      .filter((item) => {
        if (!item || typeof item !== 'object') return false
        const hasTag = Boolean(item.tag || item.name)
        const hasUrl = Boolean(item.url)
        return hasTag && hasUrl
      })
      .map((item) => {
        const tag = item.tag || item.name
        const url = item.url
        const isBinary = item.format === 'binary' || url.endsWith('.srs')
        const format = item.format || (isBinary ? 'binary' : 'source')

        return {
          name: tag,
          format,
          behavior: isBinary ? 'srs' : 'json',
          url,
        }
      })
  } catch (error) {
    console.error('[singbox-parser] JSON parse error:', error.message)
    return []
  }
}



// 1. 安全检查远程文件是否存在（不依赖严格的 exit code 异常抛出）
const fileExistsSafe = async (client, filePath, isLocal = false) => {
  if (isLocal) {
    try {
      return fs.existsSync(filePath)
    } catch {
      return false
    }
  }

  try {
    // 改用更直观的 shell 命令：如果文件存在且可读，直接打印 1，否则不打印
    const result = await sshExec(client, `[ -f "${filePath}" ] && echo "1" || echo "0"`, {
      maxBuffer: 64 * 1024,
    }).catch(() => null)

    const output = (result?.stdout || '').trim()
    return output === '1'
  } catch (e) {
    console.error(`[SSH File Check Error] ${filePath}:`, e.message)
    return false
  }
}

// 2. 安全读取远程文件内容
const readFileSafe = async (client, filePath, isLocal = false) => {
  if (isLocal) {
    try {
      return fs.readFileSync(filePath, 'utf-8')
    } catch {
      return ''
    }
  }

  try {
    const result = await sshExec(client, `cat "${filePath}"`, { maxBuffer: 1024 * 1024 })
    const rawOutput = result?.stdout || result || ''
    // 确保只取内容主体，去掉首尾多余的空白
    return typeof rawOutput === 'string' ? rawOutput.trim() : String(rawOutput)
  } catch (e) {
    console.error(`[SSH Read Error] ${filePath}:`, e.message)
    return ''
  }
}



// 候选配置文件路径表
const getSingBoxRuleSourceConfigPathCandidates = async (client, config = {}) => {
  const isLocal = Boolean(config.isLocal)

  // 【本地模式】：Mac 本地运行 GUI.for.SingBox
  if (isLocal) {
    const homeDir = os.homedir()
    const gsfmDir = path.join(homeDir, 'Library/Application Support/GUI.for.SingBox')

    return dedupeStrings([
      ...(config.filePath ? [config.filePath] : []),
      path.join(gsfmDir, 'sing-box/config.json'),
      path.join(gsfmDir, 'config.json'),
      path.join(homeDir, '.config/sing-box/config.json'),
      '/usr/local/etc/sing-box/config.json',
      './config.json',
    ])
  }

  // 【远程模式】：连接家里的 OpenWrt 路由器
  const processResult = await sshExec(client, 'ps ww || ps w || ps', {
    maxBuffer: 256 * 1024,
  }).catch(() => null)

  const stdout = processResult?.stdout || ''

  // 1. 从进程命令中动态捕获 -D 参数路径（例如你看到的 -D /etc/momo/run）
  const dataDirMatch = stdout.match(/-D\s+([^\s]+)/)
  const dynamicDirConfig = dataDirMatch ? `${dataDirMatch[1].replace(/\/+$/, '')}/config.json` : null

  // 2. 捕获显式指定的 -c 或 --config 路径
  const configMatch = stdout.match(/(?:-c|--config)\s+([^\s]+\.json)/i)
  const explicitConfig = configMatch?.[1] || null

  // 3. 返回完整的候选路径列表（将你确定的 /etc/momo/run/config.json 置顶）
  return dedupeStrings([
    '/etc/momo/run/config.json',
    ...(dynamicDirConfig ? [dynamicDirConfig] : []),
    ...(explicitConfig ? [explicitConfig] : []),
    '/var/etc/sing-box/config.json',
    '/etc/sing-box/config.json',
    '/etc/sing-box/main.json',
  ])
}

// sing-box 检测主入口
const detectSingBoxRuleSourceFromOpenWrtClient = async (client, config = {}) => {
  const isLocal = Boolean(config.isLocal)

  // ⚠️ 确保第 2 个参数透传了 config
  const configPathCandidates = await getSingBoxRuleSourceConfigPathCandidates(client, config)
  const checkedExistingPaths = []

  for (const configPath of configPathCandidates) {
    if (!(await fileExistsSafe(client, configPath, isLocal))) {
      continue
    }

    checkedExistingPaths.push(configPath)

    const content = await readFileSafe(client, configPath, isLocal)
    const providers = extractSingBoxRuleSetEntriesFromContent(content)

    if (providers.length === 0) {
      continue
    }

    return {
      plugin: 'singbox',
      configPath,
      providers,
    }
  }

  // 抛出检测异常提示（仅在远程 SSH 模式下判定 Momo 特有目录）
  const hasMomoDir = !isLocal && client && (
    (await remoteFileExists(client, '/etc/config/momo')) ||
    (await remotePathExists(client, '/etc/momo'))
  )

  if (checkedExistingPaths.length > 0 || hasMomoDir) {
    throw new Error(
      `sing-box/Momo detected, but no readable JSON with route.rule_set was found${
        checkedExistingPaths.length > 0 ? `: ${checkedExistingPaths.join(', ')}` : ''
      }.`,
    )
  }

  return null
}

const detectOpenClashRuleSourceFromOpenWrtClient = async (client, config = {}) => {
  const isLocal = Boolean(config.isLocal)

  // 1. 校验 OpenClash UCI 配置文件是否存在（兼容 本地/SSH）
  if (!(await fileExistsSafe(client, openClashUciConfigPath, isLocal))) {
    return null
  }

  // 2. 读取 UCI 配置文件（兼容 本地/SSH）
  const uciContent = await readFileSafe(client, openClashUciConfigPath, isLocal)

  // 3. 解析实际使用的 config_path 路径
  const configPath = resolveOpenClashConfigPathFromUci(uciContent, {
    configDir: openClashConfigDir,
    uciConfigPath: openClashUciConfigPath,
    pathApi: isLocal ? path : path.posix, // 本地模式下根据当前系统环境解析路径
    preferExisting: false,
  })

  if (!configPath) {
    throw new Error('OpenClash detected, but option config_path is missing.')
  }

  // 4. 校验规则配置文件是否存在（兼容 本地/SSH）
  if (!(await fileExistsSafe(client, configPath, isLocal))) {
    throw new Error(`OpenClash config_path file does not exist: ${configPath}`)
  }

  // 5. 读取规则配置文件内容（兼容 本地/SSH）
  const content = await readFileSafe(client, configPath, isLocal)

  return {
    plugin: 'openclash',
    configPath,
    providers: extractRuleProviderEntriesFromContent(content),
  }
}

const collectRuleSourceSnapshotsFromOpenWrtClient = async (
  client,
  requestedPlugin = 'auto',
  config = {},
) => {
  const plugin = normalizeRuleSourcePlugin(requestedPlugin)
  const snapshots = []
  const errors = []
  const detectors = [
    ['openclash', detectOpenClashRuleSourceFromOpenWrtClient],
    ['nikki', detectNikkiRuleSourceFromOpenWrtClient],
    ['singbox', detectSingBoxRuleSourceFromOpenWrtClient],
  ].filter(([name]) => plugin === 'auto' || plugin === name)

  for (const [name, detector] of detectors) {
    try {
      // 将 config 作为第二个参数透传给具体插件的检测函数
      const snapshot = await detector(client, config)

      if (snapshot) {
        snapshots.push(snapshot)
      }
    } catch (error) {
      errors.push({
        plugin: name,
        message: error instanceof Error ? error.message : String(error),
      })
    }
  }

  return {
    plugin,
    snapshots,
    errors,
  }
}

const detectRuleSourceFromOpenWrtClient = async (
  client,
  requestedPlugin = 'auto',
  config = {},
) => {
  // 把 config 往下传给 collectRuleSourceSnapshotsFromOpenWrtClient
  const { plugin, snapshots, errors } = await collectRuleSourceSnapshotsFromOpenWrtClient(
    client,
    requestedPlugin,
    config,
  )

  if (snapshots.length > 0) {
    return {
      ...snapshots[0],
      selectedPlugin: snapshots[0].plugin,
      availablePlugins: snapshots.map((snapshot) => snapshot.plugin),
      pluginErrors: errors,
    }
  }

  if (errors.length > 0) {
    throw new Error(errors.map((entry) => `${entry.plugin}: ${entry.message}`).join('; '))
  }

  // 动态匹配报错的主机文案（本地 vs 远程）
  const targetHost = config.isLocal ? 'local host' : 'OpenWrt host'

  throw new Error(
    plugin === 'auto'
      ? `OpenClash, Nikki or sing-box was not detected on the ${targetHost}.`
      : `${plugin} was not detected on the ${targetHost}.`,
  )
}


const getOpenWrtRuleSourceSnapshot = async (options = {}) => {
  const config = options.config || readOpenWrtRuleSourceSshConfig()

  if (!config.configured && !options.required) {
    return null
  }

  // 【关掉 SSH】：如果 host 是 127.0.0.1 / localhost，直接不建 SSH 链接，传入 config 跑本地检测
  if (config.isLocal) {
    return await detectRuleSourceFromOpenWrtClient(null, config.plugin, config)
  }

  // 远程 SSH 模式（保持不变）
  return await withOpenWrtSshClient(config, (client) =>
    detectRuleSourceFromOpenWrtClient(client, config.plugin, config),
  )
}

const getOpenWrtPluginCustomRuleStatus = async (client, plugin, isLocal = false) => {
  const uciPath = plugin === 'openclash' ? openClashUciConfigPath : defaultNikkiUciConfigPath

  if (!(await fileExistsSafe(client, uciPath, isLocal))) {
    return null
  }

  return {
    enabled: isOpenWrtCustomRuleEnabled(plugin, await readFileSafe(client, uciPath, isLocal)),
    plugin,
  }
}

const getOpenWrtCustomRuleStatus = async () => {
  const config = readOpenWrtRuleSourceSshConfig()

  if (!config.configured) {
    return { enabled: false, plugin: '' }
  }

  const readStatus = async (client) => {
    if (config.plugin !== 'auto') {
      return (await getOpenWrtPluginCustomRuleStatus(client, config.plugin, config.isLocal)) || {
        enabled: false,
        plugin: '',
      }
    }

    const snapshot = await detectRuleSourceFromOpenWrtClient(client, 'auto', config).catch(() => null)
    const plugins = snapshot ? [snapshot.plugin] : ['openclash', 'nikki']

    for (const plugin of plugins) {
      const status = await getOpenWrtPluginCustomRuleStatus(client, plugin, config.isLocal)

      if (status) {
        return status
      }
    }

    return { enabled: false, plugin: '' }
  }

  // 本地模式不建 SSH 连接,直接读本机文件
  if (config.isLocal) {
    return await readStatus(null)
  }

  return await withOpenWrtSshClient(config, readStatus)
}

const assertRuleSourceReadyForSync = async () => {
  const config = readOpenWrtRuleSourceSshConfig()

  if (!config.configured) {
    throw createRuleSourceSshRequiredError()
  }

  try {
    return await getOpenWrtRuleSourceSnapshot({
      config,
      required: true,
    })
  } catch (error) {
    throw createRuleSourceSshRequiredError(getErrorMessage(error))
  }
}

const getRuleProviderKind = (url, format, behavior) => {
  const normalizedUrl = url.toLowerCase()
  const normalizedFormat = format.toLowerCase()
  const normalizedBehavior = behavior.toLowerCase()

  if (
    normalizedUrl.endsWith('.mrs') ||
    normalizedFormat === 'mrs' ||
    normalizedFormat === 'mrsrule'
  ) {
    if (normalizedBehavior === 'ipcidr' || normalizedUrl.includes('/geoip/')) {
      return 'mrs-ip'
    }

    return 'mrs-domain'
  }

  return 'text'
}

const normalizeDomain = (domain) =>
  domain.trim().toLowerCase().replace(/^\.+/, '').replace(/\.+$/, '')
const normalizeKeyword = (value) => value.trim().toLowerCase()
function normalizeRuleProviderUrl(value) {
  return String(value || '')
    .trim()
    .replace(/^(https?:\/\/)(?:gh-)?https?:\/\//i, '$1')
}
const RULE_TYPE_ALIAS_MAP = new Map([
  ['DOMAIN', 'DOMAIN'],
  ['DOMAINSUFFIX', 'DOMAIN-SUFFIX'],
  ['DOMAINKEYWORD', 'DOMAIN-KEYWORD'],
  ['IPCIDR', 'IP-CIDR'],
  ['IPCIDR6', 'IP-CIDR6'],
  ['SRCIP', 'SRC-IP'],
  ['SRCIPCIDR', 'SRC-IP-CIDR'],
  ['SRCIPCIDR6', 'SRC-IP-CIDR6'],
  ['DSTPORT', 'DST-PORT'],
  ['SRCPORT', 'SRC-PORT'],
  ['INPORT', 'IN-PORT'],
  ['GEOIP', 'GEOIP'],
  ['RULESET', 'RULE-SET'],
  ['FINAL', 'FINAL'],
  ['MATCH', 'MATCH'],
])

const normalizeRuleTypeName = (value) => {
  const normalizedKey = String(value || '')
    .trim()
    .replace(/[^a-z0-9]/gi, '')
    .toUpperCase()

  return RULE_TYPE_ALIAS_MAP.get(normalizedKey) || String(value || '').trim().toUpperCase()
}

const getRuleEntryFamily = (type) => {
  if (['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'].includes(type)) {
    return 'domain'
  }

  if (
    ['IP-CIDR', 'IP-CIDR6', 'SRC-IP', 'SRC-IP-CIDR', 'SRC-IP-CIDR6', 'GEOIP'].includes(type)
  ) {
    return 'ip'
  }

  if (['DST-PORT', 'SRC-PORT', 'IN-PORT'].includes(type)) {
    return 'port'
  }

  return 'other'
}

const buildRuleEntry = (type, content, params = [], options = {}) => {
  const normalizedType = normalizeRuleTypeName(type)
  const normalizedContent = String(content || '').trim()
  const normalizedParams = params
    .map((param) => String(param || '').trim())
    .filter(Boolean)
  const raw =
    options.raw ||
    [normalizedType, normalizedContent, ...normalizedParams].filter(Boolean).join(',')

  return {
    type: normalizedType,
    family: getRuleEntryFamily(normalizedType),
    content: normalizedContent,
    params: normalizedParams.join(', '),
    raw,
    source: options.source || '',
    line: Number.isInteger(options.line) ? options.line : null,
  }
}

const parseRuleEntryFromTextLine = (rawLine, index = null, source = '') => {
  const line = String(rawLine || '').trim()

  if (!line || line.startsWith('#') || line.startsWith('//') || /^payload\s*:/i.test(line)) {
    return null
  }

  const normalizedLine = line.startsWith('- ') ? line.slice(2).trim() : line

  if (!normalizedLine) {
    return null
  }

  if (/^(domain|suffix|keyword|ip-cidr|ip-cidr6):/i.test(normalizedLine)) {
    const [, key, value] = normalizedLine.match(/^([^:]+):\s*(.+)$/) || []

    if (!key || !value) {
      return null
    }

    const canonicalType = normalizeRuleTypeName(key)

    return buildRuleEntry(canonicalType, value, [], {
      raw: `${canonicalType},${value.trim()}`,
      source,
      line: index,
    })
  }

  if (normalizedLine.startsWith('+.')) {
    const value = normalizedLine.slice(2).trim()

    return buildRuleEntry('DOMAIN-SUFFIX', value, [], {
      raw: `DOMAIN-SUFFIX,${value}`,
      source,
      line: index,
    })
  }

  if (!normalizedLine.includes(',')) {
    if (parseIpCidr(normalizedLine)) {
      return buildRuleEntry('IP-CIDR', normalizedLine, [], {
        raw: `IP-CIDR,${normalizedLine}`,
        source,
        line: index,
      })
    }

    return buildRuleEntry('DOMAIN', normalizedLine, [], {
      raw: `DOMAIN,${normalizedLine}`,
      source,
      line: index,
    })
  }

  const parts = normalizedLine.split(',').map((part) => part.trim())
  const canonicalType = normalizeRuleTypeName(parts[0])
  const content = parts[1] || ''
  const params = parts.slice(2)

  if (!canonicalType || !content) {
    return null
  }

  return buildRuleEntry(canonicalType, content, params, {
    raw: [canonicalType, content, ...params].filter(Boolean).join(','),
    source,
    line: index,
  })
}

const parseRuleEntriesFromBody = (body, source = '') => {
  const entries = []
  const lines = String(body || '').split(/\r?\n/)

  lines.forEach((line, index) => {
    const entry = parseRuleEntryFromTextLine(line, index + 1, source)

    if (entry) {
      entries.push(entry)
    }
  })

  return entries
}

const PROXY_DOMAIN_RULE_TYPES = new Set(['DOMAIN-SUFFIX', 'DOMAIN', 'DOMAIN-KEYWORD'])
const PROXY_IP_RULE_TYPES = new Set(['IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR', 'SRC-IP-CIDR6'])
const PROXY_DIRECT_RULE_TYPES = new Set([...PROXY_DOMAIN_RULE_TYPES, ...PROXY_IP_RULE_TYPES])
const PROXY_DOMAIN_RULE_INSERT_MODES = new Set(['append', 'before-types'])
const PROXY_CUSTOM_GROUP_MODES = new Set(['pre', 'post'])

const createBadRequestError = (message) => {
  const error = new Error(message)
  error.statusCode = 400
  return error
}

const getErrorStatusCode = (error, fallback = 500) => {
  const statusCode =
    error && typeof error === 'object' && Number.isInteger(error.statusCode)
      ? error.statusCode
      : fallback

  return statusCode >= 400 && statusCode < 600 ? statusCode : fallback
}

const normalizeProxyDomainRuleType = (value) => {
  const normalizedType = normalizeRuleTypeName(value || 'DOMAIN-SUFFIX')

  return PROXY_DIRECT_RULE_TYPES.has(normalizedType) ? normalizedType : 'DOMAIN-SUFFIX'
}

const normalizeProxyDomainRuleInsertMode = (value) => {
  const normalizedValue = String(value || '').trim().toLowerCase()

  return PROXY_DOMAIN_RULE_INSERT_MODES.has(normalizedValue) ? normalizedValue : 'append'
}

const normalizeProxyDomainRuleBeforeTypes = (value) => {
  const values = Array.isArray(value)
    ? value
    : String(value || '')
        .split(',')
        .map((item) => item.trim())

  return dedupeStrings(
    values
      .map((item) => normalizeRuleTypeName(item))
      .filter(Boolean),
  )
}

const getHostnameFromMaybeUrl = (value) => {
  const normalizedValue = String(value || '').trim()

  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(normalizedValue)) {
    return normalizedValue
  }

  try {
    return new URL(normalizedValue).hostname
  } catch {
    return normalizedValue
  }
}

const normalizeProxyDomainRuleValue = (value, type) => {
  const rawValue = getHostnameFromMaybeUrl(value)
  const withoutWildcard = rawValue.replace(/^\*\./, '')
  const normalizedValue =
    type === 'DOMAIN-KEYWORD'
      ? normalizeKeyword(withoutWildcard)
      : normalizeDomain(withoutWildcard)

  if (!normalizedValue) {
    throw createBadRequestError('domain is required')
  }

  if (/[\s,\r\n]/.test(normalizedValue)) {
    throw createBadRequestError('domain must not contain spaces or commas')
  }

  if (normalizedValue.length > 253) {
    throw createBadRequestError('domain is too long')
  }

  return normalizedValue
}

const normalizeProxyIpRuleValue = (value, type) => {
  const normalizedValue = String(value || '').trim()

  if (!normalizedValue) {
    throw createBadRequestError('ip is required')
  }

  if (/[\s,\r\n]/.test(normalizedValue)) {
    throw createBadRequestError('ip must not contain spaces or commas')
  }

  const parsedCidr = parseIpCidr(normalizedValue)

  if (!parsedCidr) {
    throw createBadRequestError('ip must be a valid IP or CIDR')
  }

  if (
    (type === 'IP-CIDR' || type === 'SRC-IP-CIDR') &&
    parsedCidr.version !== 4
  ) {
    throw createBadRequestError('ip must be IPv4 for this rule type')
  }

  if (
    (type === 'IP-CIDR6' || type === 'SRC-IP-CIDR6') &&
    parsedCidr.version !== 6
  ) {
    throw createBadRequestError('ip must be IPv6 for this rule type')
  }

  return normalizedValue
}

const normalizeProxyDirectRuleValue = (value, type) => {
  if (PROXY_IP_RULE_TYPES.has(type)) {
    return normalizeProxyIpRuleValue(value, type)
  }

  return normalizeProxyDomainRuleValue(value, type)
}

const normalizeProxyDomainRuleTargetName = (value) => {
  const targetName = String(value || '').trim()

  if (!targetName) {
    throw createBadRequestError('target is required')
  }

  if (/[\r\n,]/.test(targetName)) {
    throw createBadRequestError('target must not contain line breaks or commas')
  }

  return targetName
}

const normalizeProxyCustomGroupMode = (value) => {
  const normalizedValue = String(value || '').trim().toLowerCase()

  return PROXY_CUSTOM_GROUP_MODES.has(normalizedValue) ? normalizedValue : ''
}

const normalizeWritableProxyDomainRuleInput = (input = {}) => {
  const customGroupMode = normalizeProxyCustomGroupMode(input.customGroupMode)

  if (!customGroupMode) {
    throw createBadRequestError('Domain rules can only be added to custom rule sections.')
  }

  return {
    ...input,
    groupName: '',
    providerName: '',
    customGroupMode,
  }
}

const getWritableProxyDomainRulePath = (snapshot, customGroupMode) => {
  if (snapshot?.plugin !== 'openclash') {
    return snapshot?.configPath || ''
  }

  return customGroupMode === 'post'
    ? defaultOpenClashPostCustomRulesPath
    : defaultOpenClashPreCustomRulesPath
}

const normalizeProxyDomainRuleInput = (input = {}) => {
  const type = normalizeProxyDomainRuleType(input.type)
  const value = normalizeProxyDirectRuleValue(input.value || input.domain, type)
  const groupName = String(input.groupName || input.policy || '').trim()
  const customGroupMode = normalizeProxyCustomGroupMode(input.customGroupMode)
  const target = normalizeProxyDomainRuleTargetName(
    input.target || input.param || (customGroupMode ? '' : groupName),
  )
  const providerName = String(input.providerName || '').trim()
  const insertMode = normalizeProxyDomainRuleInsertMode(input.insertMode)
  const beforeTypes = normalizeProxyDomainRuleBeforeTypes(input.beforeTypes)
  const rule = `${type},${value},${target}`

  return {
    type,
    value,
    groupName,
    target,
    providerName,
    customGroupMode,
    insertMode,
    beforeTypes,
    rule,
  }
}

const getYamlRuleItemValue = (item) => {
  if (!item || typeof item !== 'object') {
    return ''
  }

  if (typeof item.value === 'string') {
    return item.value
  }

  return ''
}

const getYamlRuleItemType = (item) => {
  const value = getYamlRuleItemValue(item)

  if (!value) {
    return ''
  }

  return normalizeRuleTypeName(value.split(',')[0])
}

const getComparableProxyDomainRule = (value) => {
  const parts = String(value || '')
    .split(',')
    .map((part) => part.trim())

  const type = normalizeRuleTypeName(parts[0])

  if (!PROXY_DIRECT_RULE_TYPES.has(type) || !parts[1] || !parts[2]) {
    return ''
  }

  try {
    return [
      type,
      normalizeProxyDirectRuleValue(parts[1], type),
      normalizeProxyDomainRuleTargetName(parts[2]),
    ].join('\n')
  } catch {
    return ''
  }
}

const getYamlRuleItemParts = (item) =>
  getYamlRuleItemValue(item)
    .split(',')
    .map((part) => part.trim())

const getProxyDomainRuleInsertIndex = (rulesNode, options) => {
  if (options.customGroupMode === 'pre') {
    const firstRuleSetIndex = rulesNode.items.findIndex(
      (item) => getYamlRuleItemType(item) === 'RULE-SET',
    )

    return firstRuleSetIndex >= 0 ? firstRuleSetIndex : 0
  }

  if (options.customGroupMode === 'post') {
    const lastRuleSetIndex = rulesNode.items.reduce((matchedIndex, item, index) => {
      return getYamlRuleItemType(item) === 'RULE-SET' ? index : matchedIndex
    }, -1)

    return lastRuleSetIndex >= 0 ? lastRuleSetIndex + 1 : rulesNode.items.length
  }

  if (options.providerName && options.groupName) {
    const matchedProviderIndex = rulesNode.items.findIndex((item) => {
      const [type, providerName, targetName] = getYamlRuleItemParts(item)

      return (
        normalizeRuleTypeName(type) === 'RULE-SET' &&
        providerName === options.providerName &&
        targetName === options.groupName
      )
    })

    if (matchedProviderIndex >= 0) {
      return matchedProviderIndex
    }
  }

  if (options.groupName) {
    const matchedGroupIndex = rulesNode.items.findIndex((item) => {
      const [type, , targetName] = getYamlRuleItemParts(item)

      return normalizeRuleTypeName(type) === 'RULE-SET' && targetName === options.groupName
    })

    if (matchedGroupIndex >= 0) {
      return matchedGroupIndex
    }
  }

  if (options.insertMode !== 'before-types' || options.beforeTypes.length === 0) {
    return rulesNode.items.length
  }

  const beforeTypeSet = new Set(options.beforeTypes)
  const matchedIndex = rulesNode.items.findIndex((item) =>
    beforeTypeSet.has(getYamlRuleItemType(item)),
  )

  return matchedIndex >= 0 ? matchedIndex : rulesNode.items.length
}

const addProxyDomainRuleToYamlContent = (content, input = {}) => {
  const normalizedInput = normalizeProxyDomainRuleInput(input)
  const document = parseYamlDocument(String(content || ''))

  if (document.errors.length > 0) {
    throw new Error(document.errors.map((error) => error.message).join('; '))
  }

  let rulesNode = document.get('rules', true)

  if (!rulesNode || rulesNode.value === null) {
    document.set('rules', document.createNode([]))
    rulesNode = document.get('rules', true)
  }

  if (!isYamlSeq(rulesNode)) {
    throw new Error('YAML rules must be an array.')
  }

  const targetComparableRule = getComparableProxyDomainRule(normalizedInput.rule)
  const existingRule = rulesNode.items.some(
    (item) => getComparableProxyDomainRule(getYamlRuleItemValue(item)) === targetComparableRule,
  )

  if (existingRule) {
    return {
      changed: false,
      duplicated: true,
      content: String(content || ''),
      rule: normalizedInput.rule,
      insertMode: normalizedInput.insertMode,
      beforeTypes: normalizedInput.beforeTypes,
    }
  }

  const insertIndex = getProxyDomainRuleInsertIndex(rulesNode, normalizedInput)
  rulesNode.items.splice(insertIndex, 0, document.createNode(normalizedInput.rule))

  return {
    changed: true,
    duplicated: false,
    content: String(document),
    rule: normalizedInput.rule,
    insertMode: normalizedInput.insertMode,
    beforeTypes: normalizedInput.beforeTypes,
  }
}

const updateProxyDomainRuleInYamlContent = (content, originalRule, input = {}) => {
  const normalizedInput = normalizeProxyDomainRuleInput(input)
  const normalizedOriginalRule = normalizeOrderedProxyDomainRule(originalRule)

  if (!normalizedOriginalRule) {
    throw createBadRequestError('originalRule is required')
  }

  const document = parseYamlDocument(String(content || ''))

  if (document.errors.length > 0) {
    throw new Error(document.errors.map((error) => error.message).join('; '))
  }

  const rulesNode = document.get('rules', true)

  if (!isYamlSeq(rulesNode)) {
    throw new Error('YAML rules must be an array.')
  }

  const matchedItemIndex = rulesNode.items.findIndex(
    (item) => normalizeOrderedProxyDomainRule(getYamlRuleItemValue(item)) === normalizedOriginalRule,
  )

  if (matchedItemIndex < 0) {
    throw createBadRequestError('Original custom rule was not found')
  }

  const matchedItem = rulesNode.items[matchedItemIndex]

  if (!Array.isArray(matchedItem?.range)) {
    throw new Error('Original custom rule cannot be edited')
  }

  const updatedComparableRule = getComparableProxyDomainRule(normalizedInput.rule)
  const duplicated = rulesNode.items.some((item, index) => {
    return (
      index !== matchedItemIndex &&
      getComparableProxyDomainRule(getYamlRuleItemValue(item)) === updatedComparableRule
    )
  })

  if (duplicated) {
    throw createBadRequestError('Updated custom rule already exists')
  }

  if (normalizeOrderedProxyDomainRule(normalizedInput.rule) === normalizedOriginalRule) {
    return {
      changed: false,
      content: String(content || ''),
      originalRule: normalizedOriginalRule,
      rule: normalizedInput.rule,
    }
  }

  const updatedContent =
    String(content || '').slice(0, matchedItem.range[0]) +
    normalizedInput.rule +
    String(content || '').slice(matchedItem.range[1])
  const verifiedDocument = parseYamlDocument(updatedContent)

  if (verifiedDocument.errors.length > 0) {
    throw new Error(verifiedDocument.errors.map((error) => error.message).join('; '))
  }

  return {
    changed: true,
    content: updatedContent,
    originalRule: normalizedOriginalRule,
    rule: normalizedInput.rule,
  }
}

const deleteProxyDomainRuleInYamlContent = (content, rule) => {
  const sourceContent = String(content || '')
  const normalizedRule = normalizeOrderedProxyDomainRule(rule)

  if (!normalizedRule) {
    throw createBadRequestError('rule is required')
  }

  const document = parseYamlDocument(sourceContent)

  if (document.errors.length > 0) {
    throw new Error(document.errors.map((error) => error.message).join('; '))
  }

  const rulesNode = document.get('rules', true)

  if (!isYamlSeq(rulesNode)) {
    throw new Error('YAML rules must be an array.')
  }

  const matchedItem = rulesNode.items.find(
    (item) => normalizeOrderedProxyDomainRule(getYamlRuleItemValue(item)) === normalizedRule,
  )

  if (!Array.isArray(matchedItem?.range)) {
    throw createBadRequestError('Custom rule was not found')
  }

  const lineStart = sourceContent.lastIndexOf('\n', Math.max(0, matchedItem.range[0] - 1)) + 1
  const newlineIndex = sourceContent.indexOf('\n', matchedItem.range[1])
  const lineEnd = newlineIndex >= 0 ? newlineIndex + 1 : sourceContent.length
  const itemPrefix = sourceContent.slice(lineStart, matchedItem.range[0])

  if (!/^\s*-\s*$/.test(itemPrefix)) {
    throw new Error('Custom rule is not stored as an editable YAML list item')
  }

  const updatedContent = sourceContent.slice(0, lineStart) + sourceContent.slice(lineEnd)
  const verifiedDocument = parseYamlDocument(updatedContent)

  if (verifiedDocument.errors.length > 0) {
    throw new Error(verifiedDocument.errors.map((error) => error.message).join('; '))
  }

  return {
    changed: true,
    content: updatedContent,
    rule: normalizedRule,
  }
}

const normalizeOrderedProxyDomainRule = (value) =>
  String(value || '')
    .split(',')
    .map((part) => part.trim())
    .join(',')

const buildProxyDomainRuleCounts = (rules) => {
  const counts = new Map()

  rules.forEach((rule) => {
    const normalizedRule = normalizeOrderedProxyDomainRule(rule)
    counts.set(normalizedRule, (counts.get(normalizedRule) || 0) + 1)
  })

  return counts
}

const reorderProxyDomainRulesInYamlContent = (content, orderedRules = []) => {
  if (!Array.isArray(orderedRules) || orderedRules.some((rule) => typeof rule !== 'string')) {
    throw createBadRequestError('orderedRules must be an array of strings')
  }

  const document = parseYamlDocument(String(content || ''))

  if (document.errors.length > 0) {
    throw new Error(document.errors.map((error) => error.message).join('; '))
  }

  const rulesNode = document.get('rules', true)

  if (!isYamlSeq(rulesNode)) {
    throw new Error('YAML rules must be an array.')
  }

  const ruleItems = rulesNode.items.filter(
    (item) => typeof item?.value === 'string' && Array.isArray(item.range),
  )
  const currentRules = ruleItems.map((item) => String(item.value))

  if (orderedRules.length !== currentRules.length) {
    throw createBadRequestError('orderedRules must contain every enabled custom rule')
  }

  const currentCounts = buildProxyDomainRuleCounts(currentRules)
  const orderedCounts = buildProxyDomainRuleCounts(orderedRules)

  if (
    currentCounts.size !== orderedCounts.size ||
    [...currentCounts].some(([rule, count]) => orderedCounts.get(rule) !== count)
  ) {
    throw createBadRequestError('orderedRules must be a permutation of the current custom rules')
  }

  const changed = currentRules.some(
    (rule, index) =>
      normalizeOrderedProxyDomainRule(rule) !==
      normalizeOrderedProxyDomainRule(orderedRules[index]),
  )

  if (!changed) {
    return {
      changed: false,
      content: String(content || ''),
      count: currentRules.length,
    }
  }

  let updatedContent = String(content || '')
  const replacements = ruleItems.map((item, index) => ({
    start: item.range[0],
    end: item.range[1],
    value: normalizeOrderedProxyDomainRule(orderedRules[index]),
  }))

  replacements
    .sort((left, right) => right.start - left.start)
    .forEach((replacement) => {
      updatedContent =
        updatedContent.slice(0, replacement.start) +
        replacement.value +
        updatedContent.slice(replacement.end)
    })

  const verifiedDocument = parseYamlDocument(updatedContent)

  if (verifiedDocument.errors.length > 0) {
    throw new Error(verifiedDocument.errors.map((error) => error.message).join('; '))
  }

  return {
    changed: true,
    content: updatedContent,
    count: currentRules.length,
  }
}

const addProxyDomainRuleToRemoteConfig = async (input = {}) => {
  const normalizedInput = normalizeProxyDomainRuleInput(
    normalizeWritableProxyDomainRuleInput(input),
  )
  const config = readOpenWrtRuleSourceSshConfig()

  if (!config.configured) {
    throw createRuleSourceSshRequiredError()
  }

  try {
    return await withOpenWrtSshClient(config, async (client) => {
      const snapshot = await detectRuleSourceFromOpenWrtClient(client, config.plugin)
      const configPath = getWritableProxyDomainRulePath(
        snapshot,
        normalizedInput.customGroupMode,
      )
      const content = (await remoteFileExists(client, configPath))
        ? await readRemoteFile(client, configPath)
        : 'rules:\n'
      const result = addProxyDomainRuleToYamlContent(content, normalizedInput)

      if (result.changed) {
        await writeRemoteFile(client, configPath, result.content)
        proxyGroupRulePenetrationCache.clear()
        proxyGroupRulePenetrationCacheBySignature.clear()
      }

      return {
        ok: true,
        changed: result.changed,
        duplicated: result.duplicated,
        rule: result.rule,
        plugin: snapshot.plugin,
        configPath,
        sourceConfigPath: snapshot.configPath,
        insertMode: result.insertMode,
        beforeTypes: result.beforeTypes,
      }
    })
  } catch (error) {
    if (getErrorStatusCode(error, 0) === 400) {
      throw error
    }

    throw createRuleSourceSshRequiredError(getErrorMessage(error))
  }
}

const updateProxyDomainRuleOnOpenWrt = async (input = {}) => {
  const writableInput = normalizeWritableProxyDomainRuleInput(input)
  const normalizedInput = normalizeProxyDomainRuleInput(writableInput)
  const originalRule = String(input.originalRule || '').trim()

  if (!originalRule) {
    throw createBadRequestError('originalRule is required')
  }

  const config = readOpenWrtRuleSourceSshConfig()

  if (!config.configured) {
    throw createRuleSourceSshRequiredError()
  }

  try {
    return await withOpenWrtSshClient(config, async (client) => {
      const snapshot = await detectRuleSourceFromOpenWrtClient(client, config.plugin)
      const configPath = getWritableProxyDomainRulePath(
        snapshot,
        normalizedInput.customGroupMode,
      )
      const content = await readRemoteFile(client, configPath)
      const result = updateProxyDomainRuleInYamlContent(content, originalRule, normalizedInput)

      if (result.changed) {
        await writeRemoteFile(client, configPath, result.content)
        proxyGroupRulePenetrationCache.clear()
        proxyGroupRulePenetrationCacheBySignature.clear()
      }

      return {
        ok: true,
        changed: result.changed,
        originalRule: result.originalRule,
        rule: result.rule,
        plugin: snapshot.plugin,
        configPath,
      }
    })
  } catch (error) {
    if (getErrorStatusCode(error, 0) === 400) {
      throw error
    }

    throw createRuleSourceSshRequiredError(getErrorMessage(error))
  }
}

const deleteProxyDomainRuleOnOpenWrt = async (input = {}) => {
  const customGroupMode = normalizeProxyCustomGroupMode(input.customGroupMode)
  const rule = String(input.rule || '').trim()

  if (!customGroupMode) {
    throw createBadRequestError('Custom rule section is required')
  }

  if (!rule) {
    throw createBadRequestError('rule is required')
  }

  const config = readOpenWrtRuleSourceSshConfig()

  if (!config.configured) {
    throw createRuleSourceSshRequiredError()
  }

  try {
    return await withOpenWrtSshClient(config, async (client) => {
      const snapshot = await detectRuleSourceFromOpenWrtClient(client, config.plugin)
      const configPath = getWritableProxyDomainRulePath(snapshot, customGroupMode)
      const content = await readRemoteFile(client, configPath)
      const result = deleteProxyDomainRuleInYamlContent(content, rule)

      await writeRemoteFile(client, configPath, result.content)
      proxyGroupRulePenetrationCache.clear()
      proxyGroupRulePenetrationCacheBySignature.clear()

      return {
        ok: true,
        changed: true,
        rule: result.rule,
        plugin: snapshot.plugin,
        configPath,
      }
    })
  } catch (error) {
    if (getErrorStatusCode(error, 0) === 400) {
      throw error
    }

    throw createRuleSourceSshRequiredError(getErrorMessage(error))
  }
}

const reloadProxyDomainRulesOnOpenWrt = async () => {
  const config = readOpenWrtRuleSourceSshConfig()

  if (!config.configured) {
    throw createRuleSourceSshRequiredError()
  }

  try {
    return await withOpenWrtSshClient(config, async (client) => {
      const snapshot = await detectRuleSourceFromOpenWrtClient(client, config.plugin)
      const servicePath =
        snapshot.plugin === 'nikki' ? '/etc/init.d/nikki' : '/etc/init.d/openclash'

      if (!(await remotePathExists(client, servicePath))) {
        throw new Error(`Rule source service does not exist: ${servicePath}`)
      }

      const result = await sshExec(client, `${shellQuote(servicePath)} restart`, {
        maxBuffer: 2 * 1024 * 1024,
      })

      if (result.code !== 0) {
        throw new Error(result.stderr.trim() || `Failed to restart ${snapshot.plugin}`)
      }

      proxyGroupRulePenetrationCache.clear()
      proxyGroupRulePenetrationCacheBySignature.clear()

      return {
        ok: true,
        plugin: snapshot.plugin,
        configPath: snapshot.configPath,
      }
    })
  } catch (error) {
    if (getErrorStatusCode(error, 0) === 400) {
      throw error
    }

    throw createRuleSourceSshRequiredError(getErrorMessage(error))
  }
}

const reorderProxyDomainRulesOnOpenWrt = async (input = {}) => {
  const customGroupMode = normalizeProxyCustomGroupMode(input.customGroupMode)

  if (!customGroupMode) {
    throw createBadRequestError('Custom rule section is required')
  }

  const orderedRules = Array.isArray(input.orderedRules) ? input.orderedRules : null

  if (!orderedRules) {
    throw createBadRequestError('orderedRules is required')
  }

  const config = readOpenWrtRuleSourceSshConfig()

  if (!config.configured) {
    throw createRuleSourceSshRequiredError()
  }

  try {
    return await withOpenWrtSshClient(config, async (client) => {
      const snapshot = await detectRuleSourceFromOpenWrtClient(client, config.plugin)
      const configPath = getWritableProxyDomainRulePath(snapshot, customGroupMode)
      const content = await readRemoteFile(client, configPath)
      const result = reorderProxyDomainRulesInYamlContent(content, orderedRules)

      if (result.changed) {
        await writeRemoteFile(client, configPath, result.content)
        proxyGroupRulePenetrationCache.clear()
        proxyGroupRulePenetrationCacheBySignature.clear()
      }

      return {
        ok: true,
        changed: result.changed,
        count: result.count,
        plugin: snapshot.plugin,
        configPath,
      }
    })
  } catch (error) {
    if (getErrorStatusCode(error, 0) === 400) {
      throw error
    }

    throw createRuleSourceSshRequiredError(getErrorMessage(error))
  }
}

const isRuleEnabled = (rule) => {
  if (rule?.extra) {
    return !rule.extra.disabled
  }

  return !rule?.disabled
}

const parseDirectControllerRuleEntry = (rule) => {
  const normalizedType = normalizeRuleTypeName(rule?.type)

  if (!normalizedType || normalizedType === 'RULE-SET') {
    return null
  }

  const payloadParts = String(rule?.payload || '')
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean)
  const content = payloadParts[0] || ''
  const params = payloadParts.slice(1)
  const proxy = String(rule?.proxy || '').trim()
  const normalizedParams = proxy ? [...params, proxy] : params

  if (!content && normalizedType !== 'MATCH' && normalizedType !== 'FINAL') {
    return null
  }

  return buildRuleEntry(normalizedType, content, normalizedParams, {
    raw: [normalizedType, content, ...normalizedParams].filter(Boolean).join(','),
    source: 'controller',
    line: Number.isInteger(rule?.index) ? rule.index + 1 : null,
  })
}

const PROXY_GROUP_PRE_CUSTOM_KEY = '__custom_pre__'
const PROXY_GROUP_POST_CUSTOM_KEY = '__custom_post__'

const getProxyGroupCustomModeFromGroupName = (groupName) => {
  if (groupName === PROXY_GROUP_PRE_CUSTOM_KEY) {
    return 'pre'
  }

  if (groupName === PROXY_GROUP_POST_CUSTOM_KEY) {
    return 'post'
  }

  return null
}

const normalizeProxyGroupCustomMode = (value) => {
  return value === 'pre' || value === 'post' || value === 'all' ? value : null
}

const isProxyGroupCustomDirectRule = (normalizedType) => {
  return Boolean(
    normalizedType &&
      normalizedType !== 'RULE-SET' &&
      normalizedType !== 'MATCH' &&
      normalizedType !== 'FINAL',
  )
}

const parseProxyDomainCustomRulesFromYamlContent = (
  content,
  customGroupMode = 'pre',
  options = {},
) => {
  const sourceContent = String(content || '')
  const document = parseYamlDocument(sourceContent)

  if (document.errors.length > 0) {
    throw new Error(document.errors.map((error) => error.message).join('; '))
  }

  const rulesNode = document.get('rules', true)

  if (!isYamlSeq(rulesNode)) {
    if (options.standalone) {
      return []
    }

    throw new Error('YAML rules must be an array.')
  }

  const entries = []
  let hasSeenRuleSet = false

  rulesNode.items.forEach((item) => {
    const value = getYamlRuleItemValue(item)
    const normalizedType = getYamlRuleItemType(item)

    if (normalizedType === 'RULE-SET') {
      hasSeenRuleSet = true
      return
    }

    if (!value || !isProxyGroupCustomDirectRule(normalizedType)) {
      return
    }

    if (!options.standalone) {
      const itemMode = hasSeenRuleSet ? 'post' : 'pre'

      if (itemMode !== customGroupMode) {
        return
      }
    }

    const line = Array.isArray(item?.range)
      ? sourceContent.slice(0, item.range[0]).split(/\r?\n/).length
      : null
    const entry = parseRuleEntryFromTextLine(value, line, options.source || 'custom')

    if (entry) {
      entries.push(entry)
    }
  })

  return entries
}

const readProxyDomainCustomRulesOnOpenWrt = async (customGroupMode) => {
  const normalizedCustomGroupMode = normalizeProxyCustomGroupMode(customGroupMode)

  if (!normalizedCustomGroupMode) {
    throw createBadRequestError('Custom rule section is required')
  }

  const config = readOpenWrtRuleSourceSshConfig()

  if (!config.configured) {
    throw createRuleSourceSshRequiredError()
  }

  try {
    return await withOpenWrtSshClient(config, async (client) => {
      const snapshot = await detectRuleSourceFromOpenWrtClient(client, config.plugin)
      const configPath = getWritableProxyDomainRulePath(snapshot, normalizedCustomGroupMode)
      const content = (await remoteFileExists(client, configPath))
        ? await readRemoteFile(client, configPath)
        : 'rules:\n'
      const items = parseProxyDomainCustomRulesFromYamlContent(
        content,
        normalizedCustomGroupMode,
        {
          source: configPath,
          standalone: snapshot.plugin === 'openclash',
        },
      )

      return {
        plugin: snapshot.plugin,
        configPath,
        items,
      }
    })
  } catch (error) {
    if (getErrorStatusCode(error, 0) === 400) {
      throw error
    }

    throw createRuleSourceSshRequiredError(getErrorMessage(error))
  }
}

const expandProxyGroupRuleEntries = (groupName, rules, options = {}) => {
  const customGroupMode =
    normalizeProxyGroupCustomMode(options.customGroupMode) ||
    (options.customGroup === true ? 'all' : null) ||
    getProxyGroupCustomModeFromGroupName(groupName)
  const customGroup = customGroupMode !== null
  const relevantRules = []
  const sortedRules = [...rules]
    .filter((rule) => isRuleEnabled(rule))
    .sort((prev, next) => (prev?.index || 0) - (next?.index || 0))
  let hasSeenRuleSet = false

  sortedRules.forEach((rule) => {
    const normalizedType = normalizeRuleTypeName(rule?.type)

    if (customGroup) {
      if (normalizedType === 'RULE-SET') {
        hasSeenRuleSet = true
        return
      }

      if (!isProxyGroupCustomDirectRule(normalizedType)) {
        return
      }

      if (customGroupMode === 'all') {
        relevantRules.push(rule)
        return
      }

      const ruleMode = hasSeenRuleSet ? 'post' : 'pre'

      if (ruleMode === customGroupMode) {
        relevantRules.push(rule)
      }

      return
    }

    if (rule?.proxy === groupName) {
      relevantRules.push(rule)
    }
  })
  const entries = []
  const seenEntries = new Set()
  const missingProviders = new Set()

  const pushEntry = (entry) => {
    if (!entry) {
      return
    }

    const key = [entry.type, entry.content, entry.params, entry.raw].join('::')

    if (seenEntries.has(key)) {
      return
    }

    seenEntries.add(key)
    entries.push(entry)
  }

  for (const rule of relevantRules) {
    const normalizedType = normalizeRuleTypeName(rule?.type)

    if (normalizedType === 'RULE-SET') {
      const providerName = String(rule?.payload || '').trim()
      const cachedProvider = getCachedRuleProviderByNameStatement.get(providerName)

      if (!cachedProvider) {
        missingProviders.add(providerName)
        continue
      }

      parseRuleEntriesFromBody(cachedProvider.body, providerName).forEach(pushEntry)
      continue
    }

    pushEntry(parseDirectControllerRuleEntry(rule))
  }

  return {
    groupName,
    customGroup,
    customGroupMode,
    totalRules: relevantRules.length,
    items: entries,
    missingProviders: Array.from(missingProviders),
  }
}

const PROXY_GROUP_RULE_PENETRATION_TAB_SET = new Set(['all', 'domain', 'ip', 'port'])
const PROXY_GROUP_RULE_PENETRATION_SORT_KEY_SET = new Set(['type', 'content', 'params', 'raw'])
const PROXY_GROUP_RULE_PENETRATION_CACHE_VERSION = 3
const RULE_TYPE_DISPLAY_NAME_MAP = new Map([
  ['DOMAIN', '域名'],
  ['DOMAIN-SUFFIX', '域名后缀'],
  ['DOMAIN-KEYWORD', '关键字'],
  ['IP-CIDR', '目标IP'],
  ['IP-CIDR6', '目标IP'],
  ['SRC-IP', '源IP'],
  ['SRC-IP-CIDR', '源IP'],
  ['SRC-IP-CIDR6', '源IP'],
  ['DST-PORT', '目标端口'],
  ['SRC-PORT', '源端口'],
  ['IN-PORT', '入站端口'],
  ['GEOIP', '目标IP'],
  ['MATCH', '匹配'],
  ['FINAL', '最终'],
])

const pruneProxyGroupRulePenetrationCache = () => {
  const now = Date.now()

  for (const [cacheKey, entry] of proxyGroupRulePenetrationCache.entries()) {
    if (now - entry.lastAccessAt <= PROXY_GROUP_RULE_PENETRATION_CACHE_TTL_MS) {
      continue
    }

    proxyGroupRulePenetrationCache.delete(cacheKey)
    proxyGroupRulePenetrationCacheBySignature.delete(entry.signature)
  }

  if (proxyGroupRulePenetrationCache.size <= PROXY_GROUP_RULE_PENETRATION_CACHE_LIMIT) {
    return
  }

  const staleEntries = [...proxyGroupRulePenetrationCache.entries()].sort(
    (left, right) => left[1].lastAccessAt - right[1].lastAccessAt,
  )

  while (staleEntries.length > 0 && proxyGroupRulePenetrationCache.size > PROXY_GROUP_RULE_PENETRATION_CACHE_LIMIT) {
    const [cacheKey, entry] = staleEntries.shift()
    proxyGroupRulePenetrationCache.delete(cacheKey)
    proxyGroupRulePenetrationCacheBySignature.delete(entry.signature)
  }
}

const buildProxyGroupRulePenetrationSignature = (groupName, rules, options = {}) => {
  const customGroupMode =
    normalizeProxyGroupCustomMode(options.customGroupMode) || (options.customGroup === true ? 'all' : null)

  return createHash('sha1')
    .update(
      JSON.stringify({
        version: PROXY_GROUP_RULE_PENETRATION_CACHE_VERSION,
        groupName,
        customGroup: options.customGroup === true,
        customGroupMode,
        rules,
      }),
    )
    .digest('hex')
}

const getProxyGroupRulePenetrationDisplayType = (type) => {
  return RULE_TYPE_DISPLAY_NAME_MAP.get(type) || type
}

const buildRulePenetrationCounts = (items) => {
  const counts = {
    all: items.length,
    domain: 0,
    ip: 0,
    port: 0,
  }

  items.forEach((entry) => {
    if (entry.family === 'domain') {
      counts.domain += 1
    } else if (entry.family === 'ip') {
      counts.ip += 1
    } else if (entry.family === 'port') {
      counts.port += 1
    }
  })

  return counts
}

const normalizeProxyGroupRulePenetrationTab = (value) => {
  return PROXY_GROUP_RULE_PENETRATION_TAB_SET.has(value) ? value : 'all'
}

const normalizeProxyGroupRulePenetrationSortKey = (value) => {
  return PROXY_GROUP_RULE_PENETRATION_SORT_KEY_SET.has(value) ? value : null
}

const normalizeProxyGroupRulePenetrationSortDirection = (value) => {
  return value === 'desc' ? 'desc' : 'asc'
}

const normalizePositiveInteger = (value, defaultValue, maxValue) => {
  const parsed = Number.parseInt(String(value || ''), 10)

  if (!Number.isFinite(parsed) || parsed <= 0) {
    return defaultValue
  }

  return Math.min(parsed, maxValue)
}

const getProxyGroupRulePenetrationCacheEntry = ({
  groupName,
  cacheKey,
  rules,
  customGroup = false,
  customGroupMode = null,
}) => {
  pruneProxyGroupRulePenetrationCache()
  const normalizedCustomGroupMode =
    normalizeProxyGroupCustomMode(customGroupMode) || (customGroup === true ? 'all' : null)

  if (cacheKey) {
    const cachedEntry = proxyGroupRulePenetrationCache.get(cacheKey)

    if (
      !cachedEntry ||
      cachedEntry.groupName !== groupName ||
      cachedEntry.customGroup !== customGroup ||
      cachedEntry.customGroupMode !== normalizedCustomGroupMode
    ) {
      const error = new Error('cache expired')
      error.code = 'CACHE_EXPIRED'
      throw error
    }

    cachedEntry.lastAccessAt = Date.now()
    return cachedEntry
  }

  const signature = buildProxyGroupRulePenetrationSignature(groupName, rules, {
    customGroup,
    customGroupMode: normalizedCustomGroupMode,
  })
  const reusedCacheKey = proxyGroupRulePenetrationCacheBySignature.get(signature)

  if (reusedCacheKey) {
    const reusedEntry = proxyGroupRulePenetrationCache.get(reusedCacheKey)

    if (reusedEntry) {
      reusedEntry.lastAccessAt = Date.now()
      return reusedEntry
    }

    proxyGroupRulePenetrationCacheBySignature.delete(signature)
  }

  const expanded = expandProxyGroupRuleEntries(groupName, rules, {
    customGroup,
    customGroupMode: normalizedCustomGroupMode,
  })
  const nextCacheKey = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
  const createdEntry = {
    cacheKey: nextCacheKey,
    signature,
    groupName,
    customGroup,
    customGroupMode: expanded.customGroupMode,
    totalRules: expanded.totalRules,
    items: expanded.items,
    missingProviders: expanded.missingProviders,
    createdAt: Date.now(),
    lastAccessAt: Date.now(),
  }

  proxyGroupRulePenetrationCache.set(nextCacheKey, createdEntry)
  proxyGroupRulePenetrationCacheBySignature.set(signature, nextCacheKey)
  pruneProxyGroupRulePenetrationCache()

  return createdEntry
}

const matchesProxyGroupRulePenetrationSearch = (entry, search) => {
  if (!search) {
    return true
  }

  const normalizedSearch = search.toLowerCase()

  return [
    entry.type,
    getProxyGroupRulePenetrationDisplayType(entry.type),
    entry.content,
    entry.params,
    entry.raw,
  ].some((value) => String(value || '').toLowerCase().includes(normalizedSearch))
}

const sortProxyGroupRulePenetrationEntries = (items, sortKey, sortDirection) => {
  if (!sortKey) {
    return items
  }

  const direction = sortDirection === 'desc' ? -1 : 1

  return [...items].sort((left, right) => {
    const leftValue = sortKey === 'type' ? getProxyGroupRulePenetrationDisplayType(left.type) : left[sortKey]
    const rightValue = sortKey === 'type' ? getProxyGroupRulePenetrationDisplayType(right.type) : right[sortKey]

    return (
      String(leftValue || '').localeCompare(String(rightValue || ''), 'zh-Hans-CN', {
        numeric: true,
        sensitivity: 'base',
      }) * direction
    )
  })
}

const normalizeLookupInput = (value) => {
  const input = value.trim()

  if (!input) {
    return null
  }

  let candidate = input

  try {
    candidate = new URL(input.includes('://') ? input : `https://${input}`).hostname || input
  } catch {
    candidate = input.split('/')[0]
  }

  const trimmedCandidate = candidate.trim()
  const ipVersion = isIP(trimmedCandidate)

  if (ipVersion) {
    const parsedIp = parseIpAddress(trimmedCandidate)

    if (!parsedIp) {
      return null
    }

    return {
      raw: input,
      type: 'ip',
      value: trimmedCandidate.toLowerCase(),
      parsedIp,
    }
  }

  const normalizedDomainValue = normalizeDomain(trimmedCandidate)

  if (/^[a-z0-9.-]+$/i.test(normalizedDomainValue) && normalizedDomainValue.includes('.')) {
    return {
      raw: input,
      type: 'domain',
      value: normalizedDomainValue,
    }
  }

  const keyword = normalizeKeyword(input)

  if (!keyword) {
    return null
  }

  return {
    raw: input,
    type: 'keyword',
    value: keyword,
  }
}

const mergeLookupMatches = (matchesList) => {
  const seen = new Set()
  const merged = []

  matchesList.flat().forEach((match) => {
    const key = `${match.line}:${match.mode}:${match.value}:${match.raw}`

    if (seen.has(key)) {
      return
    }

    seen.add(key)
    merged.push(match)
  })

  return merged.sort((left, right) => {
    if (left.line !== right.line) {
      return left.line - right.line
    }

    return left.raw.localeCompare(right.raw, 'zh-Hans-CN', {
      numeric: true,
      sensitivity: 'base',
    })
  })
}

const findMatchesInTextRulesByLookups = async (lookups, body) => {
  return mergeLookupMatches(lookups.map((lookup) => findMatchesInTextRules(lookup, body)))
}
const countRulesInBody = (body) => {
  if (!body || !body.trim()) {
    return 0
  }

  return body
    .split(/\r?\n/)
    .filter((line) => {
      const trimmedLine = line.trim()

      return (
        trimmedLine &&
        !trimmedLine.startsWith('#') &&
        !trimmedLine.startsWith('//') &&
        !/^payload\s*:/i.test(trimmedLine)
      )
    })
    .length
}

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'host',
  'content-length',
])

const getProxyTarget = (req) => {
  const rawBase = req.header('x-zashboard-target-base')

  if (!rawBase) {
    throw new Error('Missing x-zashboard-target-base header')
  }

  const target = new URL(rawBase)

  if (!['http:', 'https:'].includes(target.protocol)) {
    throw new Error('Only http and https controller targets are supported')
  }

  return {
    base: target,
    secret: req.header('x-zashboard-target-secret') || '',
  }
}

const buildUpstreamUrl = (req, targetBase) => {
  const suffix = req.originalUrl.slice('/api/controller'.length) || '/'
  const normalizedBase = targetBase.toString().replace(/\/$/, '')

  return new URL(`${normalizedBase}${suffix.startsWith('/') ? suffix : `/${suffix}`}`)
}

const buildProxyPath = (basePath, suffix) => {
  const normalizedBasePath = (basePath || '').replace(/\/+$/, '')
  const normalizedSuffix = (suffix || '').replace(/^\/+/, '')

  if (!normalizedBasePath && !normalizedSuffix) {
    return '/'
  }

  if (!normalizedBasePath) {
    return `/${normalizedSuffix}`
  }

  if (!normalizedSuffix) {
    return normalizedBasePath || '/'
  }

  return `${normalizedBasePath}/${normalizedSuffix}`
}

const getControllerBaseUrl = (backend) => {
  const baseUrl = new URL(`${backend.protocol}://${backend.host}:${backend.port}`)

  if (backend.secondaryPath) {
    baseUrl.pathname = buildProxyPath(baseUrl.pathname, backend.secondaryPath)
  }

  return baseUrl
}

const createControllerRequestUrl = (backend, suffix) => {
  const baseUrl = getControllerBaseUrl(backend)
  const normalizedBase = baseUrl.toString().replace(/\/$/, '')

  return new URL(`${normalizedBase}${suffix.startsWith('/') ? suffix : `/${suffix}`}`)
}

const controllerFetch = async (backend, suffix, options = {}) => {
  const headers = new Headers(options.headers || {})

  if (backend.password) {
    headers.set('Authorization', `Bearer ${backend.password}`)
  } else {
    headers.delete('Authorization')
  }

  const response = await fetch(createControllerRequestUrl(backend, suffix), {
    ...options,
    headers,
    signal: options.signal ?? activeRuleRefreshController?.signal,
  })

  if (!response.ok) {
    const message = await response.text().catch(() => '')
    throw new Error(message || `Controller request failed: ${response.status}`)
  }

  return response
}

const fetchControllerRuleProviders = async (backend) => {
  const response = await controllerFetch(backend, '/providers/rules', {
    headers: {
      Accept: 'application/json',
    },
  })

  const data = await response.json()
  return Object.values(data?.providers || {})
}

const fetchControllerRules = async (backend) => {
  const response = await controllerFetch(backend, '/rules', {
    headers: {
      Accept: 'application/json',
    },
  })

  const data = await response.json()
  return Array.isArray(data?.rules) ? data.rules : []
}

const getReferencedProviderNamesFromControllerRules = (rules) => {
  const seen = new Set()
  const names = []

  rules.forEach((rule) => {
    if (!isRuleEnabled(rule) || normalizeRuleTypeName(rule?.type) !== 'RULE-SET') {
      return
    }

    const providerName = String(rule?.payload || '').trim()

    if (!providerName || seen.has(providerName)) {
      return
    }

    seen.add(providerName)
    names.push(providerName)
  })

  return names
}

const proxyControllerRequest = async (req, res) => {
  try {
    const { base, secret } = getProxyTarget(req)
    const upstreamUrl = buildUpstreamUrl(req, base)
    const headers = new Headers()

    Object.entries(req.headers).forEach(([key, value]) => {
      const normalizedKey = key.toLowerCase()

      if (
        HOP_BY_HOP_HEADERS.has(normalizedKey) ||
        normalizedKey.startsWith('x-zashboard-target-')
      ) {
        return
      }

      if (Array.isArray(value)) {
        headers.set(key, value.join(', '))
        return
      }

      if (typeof value === 'string') {
        headers.set(key, value)
      }
    })

    if (secret) {
      headers.set('Authorization', `Bearer ${secret}`)
    } else {
      headers.delete('Authorization')
    }

    const response = await fetch(upstreamUrl, {
      method: req.method,
      headers,
      body:
        req.method === 'GET' || req.method === 'HEAD'
          ? undefined
          : Buffer.isBuffer(req.body) && req.body.length
            ? req.body
            : undefined,
    })

    res.status(response.status)

    response.headers.forEach((value, key) => {
      if (!HOP_BY_HOP_HEADERS.has(key.toLowerCase())) {
        res.setHeader(key, value)
      }
    })

    const body = Buffer.from(await response.arrayBuffer())
    res.send(body)
  } catch (error) {
    res.status(502).json({
      message: error instanceof Error ? error.message : String(error),
    })
  }
}

const getWebSocketProxyTarget = (requestUrl) => {
  const targetBaseRaw = requestUrl.searchParams.get('targetBase')

  if (!targetBaseRaw) {
    throw new Error('Missing targetBase query parameter')
  }

  const targetBase = new URL(targetBaseRaw)

  if (!['http:', 'https:'].includes(targetBase.protocol)) {
    throw new Error('Only http and https controller targets are supported')
  }

  return {
    base: targetBase,
    secret: requestUrl.searchParams.get('secret') || '',
  }
}

const buildUpstreamWebSocketUrl = (requestUrl, targetBase, secret) => {
  const suffix = requestUrl.pathname.slice('/api/controller-ws'.length) || '/'
  const upstreamUrl = new URL(targetBase.toString())

  upstreamUrl.protocol = targetBase.protocol === 'https:' ? 'wss:' : 'ws:'
  upstreamUrl.pathname = buildProxyPath(upstreamUrl.pathname, suffix)
  upstreamUrl.search = ''

  requestUrl.searchParams.forEach((value, key) => {
    if (key !== 'targetBase' && key !== 'secret') {
      upstreamUrl.searchParams.append(key, value)
    }
  })

  if (secret) {
    upstreamUrl.searchParams.set('token', secret)
  }

  return upstreamUrl
}

const normalizeCloseCode = (code, fallback = 1000) => {
  if (!Number.isInteger(code)) {
    return fallback
  }

  if (code >= 3000 && code <= 4999) {
    return code
  }

  if (code >= 1000 && code <= 1014 && ![1004, 1005, 1006].includes(code)) {
    return code
  }

  return fallback
}

const closeSocket = (socket, code = 1000, reason = '') => {
  if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
    socket.close(normalizeCloseCode(code), reason)
  }
}

const closeSocketPair = (left, right, code = 1011, reason = '') => {
  closeSocket(left, code, reason)
  closeSocket(right, code, reason)
}

const relayControllerWebSocket = (clientSocket, request) => {
  let upstreamSocket

  try {
    const requestUrl = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`)
    const { base, secret } = getWebSocketProxyTarget(requestUrl)
    const upstreamUrl = buildUpstreamWebSocketUrl(requestUrl, base, secret)

    upstreamSocket = new WebSocket(upstreamUrl)

    const closeBoth = (code, reason) => {
      closeSocketPair(clientSocket, upstreamSocket, code, reason)
    }

    clientSocket.on('message', (data, isBinary) => {
      if (upstreamSocket.readyState === WebSocket.OPEN) {
        upstreamSocket.send(data, { binary: isBinary })
      }
    })

    clientSocket.on('close', (code, reason) => {
      closeSocket(upstreamSocket, code, reason?.toString())
    })

    clientSocket.on('error', () => {
      closeBoth(1011, 'Client websocket error')
    })

    upstreamSocket.on('message', (data, isBinary) => {
      if (clientSocket.readyState === WebSocket.OPEN) {
        clientSocket.send(data, { binary: isBinary })
      }
    })

    upstreamSocket.on('close', (code, reason) => {
      closeSocket(clientSocket, code, reason?.toString())
    })

    upstreamSocket.on('error', () => {
      closeBoth(1011, 'Upstream websocket error')
    })
  } catch (error) {
    closeSocket(clientSocket, 1011, error instanceof Error ? error.message : String(error))

    if (upstreamSocket) {
      closeSocket(upstreamSocket, 1011)
    }
  }
}

const isDomainMatch = (domain, ruleValue, mode) => {
  const normalizedDomain = normalizeDomain(domain)
  const normalizedRule = normalizeDomain(ruleValue)

  if (!normalizedDomain || !normalizedRule) {
    return false
  }

  if (mode === 'domain') {
    return normalizedDomain === normalizedRule
  }

  if (mode === 'suffix') {
    return normalizedDomain === normalizedRule || normalizedDomain.endsWith(`.${normalizedRule}`)
  }

  if (mode === 'keyword') {
    return normalizedDomain.includes(normalizedRule)
  }

  return false
}

const isDomainSearchMatch = (domain, ruleValue, mode) => {
  const normalizedDomain = normalizeDomain(domain)
  const normalizedRule = normalizeDomain(ruleValue)

  if (!normalizedDomain || !normalizedRule) {
    return false
  }

  if (isDomainMatch(normalizedDomain, normalizedRule, mode)) {
    return true
  }

  if (mode === 'domain' || mode === 'suffix') {
    return normalizedRule === normalizedDomain || normalizedRule.endsWith(`.${normalizedDomain}`)
  }

  return false
}

const isKeywordMatch = (keyword, ruleValue) => {
  const normalizedRule = normalizeDomain(ruleValue)

  return Boolean(keyword && normalizedRule && normalizedRule.includes(keyword))
}

const getKeywordMatchScore = (keyword, match) => {
  const normalizedRule = normalizeDomain(match.value)

  if (!keyword || !normalizedRule) {
    return Number.MIN_SAFE_INTEGER
  }

  const index = normalizedRule.indexOf(keyword)

  if (index === -1) {
    return Number.MIN_SAFE_INTEGER
  }

  const previousChar = normalizedRule[index - 1] || ''
  const nextChar = normalizedRule[index + keyword.length] || ''
  let score = 0

  if (normalizedRule === keyword) {
    score += 400
  }

  if (index === 0) {
    score += 120
  } else if (/[-_.]/.test(previousChar)) {
    score += 40
  }

  if (!nextChar) {
    score += 160
  } else if (nextChar === '.') {
    score += 140
  } else if (nextChar === '-') {
    score += 100
  } else if (nextChar === '_') {
    score += 80
  } else {
    score -= 10
  }

  if (match.mode === 'domain') {
    score += 30
  } else if (match.mode === 'suffix') {
    score += 20
  } else if (match.mode === 'keyword') {
    score += 10
  }

  score -= index * 8
  score -= normalizedRule.length

  return score
}

const sortRuleMatchesByLookup = (lookup, matches) => {
  if (lookup.type !== 'keyword') {
    return matches
  }

  return [...matches].sort((left, right) => {
    const scoreDelta = getKeywordMatchScore(lookup.value, right) - getKeywordMatchScore(lookup.value, left)

    if (scoreDelta !== 0) {
      return scoreDelta
    }

    return left.line - right.line
  })
}

const parseIPv4Address = (value) => {
  const parts = value.split('.')

  if (parts.length !== 4) {
    return null
  }

  let result = 0n

  for (const part of parts) {
    if (!/^\d+$/.test(part)) {
      return null
    }

    const octet = Number(part)

    if (octet < 0 || octet > 255) {
      return null
    }

    result = (result << 8n) + BigInt(octet)
  }

  return {
    version: 4,
    bits: 32,
    value: result,
  }
}

const parseIPv6Address = (value) => {
  let normalized = value.toLowerCase()

  if (normalized.includes('.')) {
    const lastColonIndex = normalized.lastIndexOf(':')

    if (lastColonIndex === -1) {
      return null
    }

    const ipv4Address = parseIPv4Address(normalized.slice(lastColonIndex + 1))

    if (!ipv4Address) {
      return null
    }

    normalized = `${normalized.slice(0, lastColonIndex)}:${Number(
      (ipv4Address.value >> 16n) & 0xffffn,
    ).toString(16)}:${Number(ipv4Address.value & 0xffffn).toString(16)}`
  }

  const doubleColonIndex = normalized.indexOf('::')

  if (doubleColonIndex !== normalized.lastIndexOf('::')) {
    return null
  }

  const headSegments =
    doubleColonIndex === -1
      ? normalized.split(':')
      : normalized.slice(0, doubleColonIndex).split(':').filter(Boolean)
  const tailSegments =
    doubleColonIndex === -1
      ? []
      : normalized
          .slice(doubleColonIndex + 2)
          .split(':')
          .filter(Boolean)

  if (doubleColonIndex === -1 && headSegments.length !== 8) {
    return null
  }

  if (headSegments.length + tailSegments.length > 8) {
    return null
  }

  const segments =
    doubleColonIndex === -1
      ? headSegments
      : [
          ...headSegments,
          ...Array.from({ length: 8 - headSegments.length - tailSegments.length }, () => '0'),
          ...tailSegments,
        ]

  if (segments.length !== 8) {
    return null
  }

  let result = 0n

  for (const segment of segments) {
    if (!/^[0-9a-f]{1,4}$/i.test(segment)) {
      return null
    }

    result = (result << 16n) + BigInt(`0x${segment}`)
  }

  return {
    version: 6,
    bits: 128,
    value: result,
  }
}

const parseIpAddress = (value) => {
  const ipVersion = isIP(value)

  if (ipVersion === 4) {
    return parseIPv4Address(value)
  }

  if (ipVersion === 6) {
    return parseIPv6Address(value)
  }

  return null
}

const parseIpCidr = (value) => {
  const trimmedValue = value.trim()

  if (!trimmedValue) {
    return null
  }

  const parts = trimmedValue.split('/')

  if (parts.length > 2) {
    return null
  }

  const parsedAddress = parseIpAddress(parts[0])

  if (!parsedAddress) {
    return null
  }

  const prefix = parts.length === 2 ? Number.parseInt(parts[1], 10) : parsedAddress.bits

  if (!Number.isInteger(prefix) || prefix < 0 || prefix > parsedAddress.bits) {
    return null
  }

  const suffixBits = BigInt(parsedAddress.bits - prefix)
  const network =
    suffixBits === 0n ? parsedAddress.value : (parsedAddress.value >> suffixBits) << suffixBits
  const size = 1n << suffixBits

  return {
    version: parsedAddress.version,
    prefix,
    start: network,
    end: network + size - 1n,
  }
}

const isIpInCidr = (parsedIp, ruleValue) => {
  const parsedRule = parseIpCidr(ruleValue)

  if (!parsedRule || parsedRule.version !== parsedIp.version) {
    return false
  }

  return parsedIp.value >= parsedRule.start && parsedIp.value <= parsedRule.end
}

const findMatchesInTextRules = (lookup, body) => {
  const matches = []
  const lines = body.split(/\r?\n/)

  lines.forEach((rawLine, index) => {
    const line = rawLine.trim()

    if (!line || line.startsWith('#') || line.startsWith('//') || /^payload\s*:/i.test(line)) {
      return
    }

    const normalizedLine = line.startsWith('- ') ? line.slice(2).trim() : line

    if (!normalizedLine) {
      return
    }

    if (/^(domain|suffix|keyword|ip-cidr|ip-cidr6):/i.test(normalizedLine)) {
      const [, key, value] = normalizedLine.match(/^([^:]+):\s*(.+)$/) || []

      if (!key || !value) {
        return
      }

      const normalizedKey = key.toLowerCase()

      if (lookup.type === 'ip') {
        const mode = normalizedKey.includes('6') ? 'ip-cidr6' : 'ip-cidr'

        if (normalizedKey.includes('ip') && isIpInCidr(lookup.parsedIp, value)) {
          matches.push({ line: index + 1, value, mode, raw: normalizedLine })
        }

        return
      }

      const mode = normalizedKey.includes('suffix')
        ? 'suffix'
        : normalizedKey.includes('keyword')
          ? 'keyword'
          : 'domain'

      const isMatched =
        lookup.type === 'domain'
          ? isDomainSearchMatch(lookup.value, value, mode)
          : isKeywordMatch(lookup.value, value)

      if (isMatched) {
        matches.push({ line: index + 1, value, mode, raw: normalizedLine })
      }

      return
    }

    if (lookup.type !== 'ip' && normalizedLine.startsWith('+.')) {
      const value = normalizedLine.slice(2)
      const isMatched =
        lookup.type === 'domain'
          ? isDomainSearchMatch(lookup.value, value, 'suffix')
          : isKeywordMatch(lookup.value, value)

      if (isMatched) {
        matches.push({ line: index + 1, value, mode: 'suffix', raw: normalizedLine })
      }

      return
    }

    const parts = normalizedLine.split(',').map((part) => part.trim())
    const ruleType = parts[0]?.toUpperCase()
    const value = parts[1] || parts[0]

    if (lookup.type === 'ip') {
      const supportsIpMatch =
        ['IP-CIDR', 'IP-CIDR6', 'SRC-IP', 'SRC-IP-CIDR', 'SRC-IP-CIDR6'].includes(ruleType) ||
        (!normalizedLine.includes(',') && Boolean(parseIpCidr(normalizedLine)))

      if (supportsIpMatch && isIpInCidr(lookup.parsedIp, value)) {
        matches.push({
          line: index + 1,
          value,
          mode:
            ruleType === 'IP-CIDR6' || ruleType === 'SRC-IP-CIDR6' ? 'ip-cidr6' : 'ip-cidr',
          raw: normalizedLine,
        })
      }

      return
    }

    const supportsDomainMatch =
      ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'].includes(ruleType) ||
      (!ruleType.includes('IP') && !ruleType.includes('PROCESS') && !normalizedLine.includes(','))

    if (!supportsDomainMatch) {
      return
    }

    const mode =
      ruleType === 'DOMAIN-SUFFIX' ? 'suffix' : ruleType === 'DOMAIN-KEYWORD' ? 'keyword' : 'domain'
    const isMatched =
      lookup.type === 'domain'
        ? isDomainSearchMatch(lookup.value, value, mode)
        : isKeywordMatch(lookup.value, value)

    if (isMatched) {
      matches.push({ line: index + 1, value, mode, raw: normalizedLine })
    }
  })

  return matches
}

const convertMrsToText = async (provider, buffer) => {
  if (!fs.existsSync(mihomoBinaryPath)) {
    throw new Error(`Mihomo binary not found: ${mihomoBinaryPath}`)
  }

  const tempName = `${Date.now()}-${Math.random().toString(36).slice(2)}`
  const sourcePath = path.join(ruleSearchTempDir, `${tempName}.mrs`)
  const targetPath = path.join(ruleSearchTempDir, `${tempName}.txt`)
  const behavior = provider.kind === 'mrs-ip' ? 'ipcidr' : 'domain'

  fs.writeFileSync(sourcePath, buffer)

  try {
    await execFileAsync(
      mihomoBinaryPath,
      ['convert-ruleset', behavior, 'mrs', sourcePath, targetPath],
      {
        windowsHide: true,
      },
    )

    return fs.readFileSync(targetPath, 'utf8')
  } finally {
    if (fs.existsSync(sourcePath)) fs.unlinkSync(sourcePath)
    if (fs.existsSync(targetPath)) fs.unlinkSync(targetPath)
  }
}

const fetchProviderBody = async (provider) => {
  const response = await fetch(provider.url, {
    signal: activeRuleProviderUpdateController?.signal,
  })

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`)
  }

  return provider.kind === 'mrs-domain' || provider.kind === 'mrs-ip'
    ? await convertMrsToText(provider, Buffer.from(await response.arrayBuffer()))
    : await response.text()
}

const saveProviderToCache = (provider, body) => {
  upsertRuleProviderCacheStatement.run(
    provider.name,
    provider.behavior,
    provider.format,
    provider.kind,
    provider.url,
    // sing-box 本地提取的 rule_set 没有 interval 字段,undefined 无法绑定 SQLite 参数
    Number.isFinite(provider.interval) ? provider.interval : 0,
    body,
  )
}

const getRuleProviderCacheRuleCount = () => {
  const row = getRuleProviderCacheTotalCountStatement.get()

  return Number(row?.total || 0)
}

const getRuleProviderCacheProviderCounts = () => {
  return Object.fromEntries(
    getCachedRuleProviderStatement.all().map((provider) => [
      provider.name,
      countRulesInBody(provider.body),
    ]),
  )
}

const buildRuleProviderSourceMetadata = (providers, extra = {}) => ({
  providerUrls: Object.fromEntries(
    providers
      .filter((provider) => provider.name && provider.url)
      .map((provider) => [provider.name, provider.url]),
  ),
  providerOrder: providers
    .map((provider) => String(provider.name || '').trim())
    .filter(Boolean),
  plugin: extra.plugin || '',
  configPath: extra.configPath || '',
  updatedAt: Date.now(),
})

const normalizeRuleProviderSourceMetadata = (metadata = {}) => {
  const providerUrls =
    metadata?.providerUrls &&
    typeof metadata.providerUrls === 'object' &&
    !Array.isArray(metadata.providerUrls)
      ? Object.fromEntries(
          Object.entries(metadata.providerUrls)
            .map(([name, url]) => [String(name || '').trim(), normalizeRuleProviderUrl(url)])
            .filter(([name, url]) => name && url),
        )
      : {}
  const providerOrder = Array.isArray(metadata?.providerOrder)
    ? [...new Set(metadata.providerOrder.map((name) => String(name || '').trim()).filter(Boolean))]
    : []

  return {
    providerUrls,
    providerOrder,
    plugin: typeof metadata?.plugin === 'string' ? metadata.plugin : '',
    configPath: typeof metadata?.configPath === 'string' ? metadata.configPath : '',
    updatedAt: Number(metadata?.updatedAt || 0) || 0,
  }
}

const hasRuleProviderSourceMetadata = (metadata) =>
  Object.keys(metadata.providerUrls || {}).length > 0 || (metadata.providerOrder || []).length > 0

const saveRuleProviderSourceMetadata = (providers, extra = {}) => {
  const metadata = buildRuleProviderSourceMetadata(providers, extra)

  upsertStorageValueStatement.run(
    RULE_PROVIDER_SOURCE_METADATA_KEY,
    JSON.stringify(metadata),
  )

  return normalizeRuleProviderSourceMetadata(metadata)
}

const getCachedRuleProviderSourceMetadata = () => {
  const row = getStorageValueStatement.get(RULE_PROVIDER_SOURCE_METADATA_KEY)
  const storedMetadata = normalizeRuleProviderSourceMetadata(parseStoredJson(row?.value, {}))

  if (hasRuleProviderSourceMetadata(storedMetadata)) {
    return storedMetadata
  }

  const cachedProviders = getCachedRuleProviderStatement.all()

  return normalizeRuleProviderSourceMetadata({
    providerUrls: Object.fromEntries(
      cachedProviders
        .filter((provider) => provider.name && provider.source_url)
        .map((provider) => [provider.name, provider.source_url]),
    ),
    providerOrder: cachedProviders.map((provider) => provider.name),
  })
}

const getRuleProviderSourceMetadata = async (options = {}) => {
  const cachedMetadata = getCachedRuleProviderSourceMetadata()

  if (hasRuleProviderSourceMetadata(cachedMetadata) || options.allowLive === false) {
    return cachedMetadata
  }

  try {
    const snapshot = await getOpenWrtRuleSourceSnapshot()

    if (!snapshot) {
      return cachedMetadata
    }

    return saveRuleProviderSourceMetadata(snapshot.providers, {
      plugin: snapshot.plugin,
      configPath: snapshot.configPath,
    })
  } catch {
    return cachedMetadata
  }
}

const replaceRuleProviderCache = (items, options = {}) => {
  const force = options.force ?? false

  db.exec('BEGIN')

  try {
    if (force) {
      clearRuleProviderCacheStatement.run()
    }

    for (const item of items) {
      saveProviderToCache(item.provider, item.body)
    }

    db.exec('COMMIT')
  } catch (error) {
    db.exec('ROLLBACK')
    throw error
  }
}

const seedRuleProviderCacheForTesting = (items) => {
  replaceRuleProviderCache(
    items.map((item) => ({
      provider: {
        name: item.name,
        behavior: item.behavior,
        format: item.format,
        kind: item.kind || getRuleProviderKind(item.url, item.format, item.behavior),
        url: item.url,
        interval: item.interval || 0,
      },
      body: item.body,
    })),
    {
      force: true,
    },
  )
}

const isCacheExpired = (updatedAt, intervalSeconds) => {
  if (!intervalSeconds || intervalSeconds <= 0) {
    return false
  }

  const updatedTime = new Date(updatedAt).getTime()

  if (Number.isNaN(updatedTime)) {
    return true
  }

  return Date.now() - updatedTime >= intervalSeconds * 1000
}

const waitForProgressFrame = async (durationMs) => {
  if (!durationMs || durationMs <= 0) {
    return
  }

  await new Promise((resolve) => {
    const timer = setTimeout(resolve, durationMs)

    if (typeof timer?.unref === 'function') {
      timer.unref()
    }
  })
}

const animateRuleCountProgress = async ({ startCount, endCount, signal, onProgress }) => {
  const safeStartCount = Number.isFinite(startCount) ? startCount : 0
  const safeEndCount = Number.isFinite(endCount) ? endCount : 0

  if (safeStartCount === safeEndCount) {
    onProgress(safeEndCount)
    return
  }

  const delta = safeEndCount - safeStartCount
  const steps = Math.min(20, Math.max(Math.abs(delta), 2))
  const totalDurationMs = Math.min(1600, Math.max(900, steps * 80))
  const frameDurationMs = Math.max(60, Math.round(totalDurationMs / steps))

  for (let step = 1; step <= steps; step++) {
    if (signal?.aborted) {
      return
    }

    onProgress(safeStartCount + Math.round((delta * step) / steps))

    if (step < steps) {
      await waitForProgressFrame(frameDurationMs)
    }
  }
}

const updateRuleProviderCache = async (options = {}) => {
  if (activeRuleProviderUpdatePromise) {
    return await activeRuleProviderUpdatePromise
  }

  activeRuleProviderUpdatePromise = (async () => {
    const force = options.force ?? true
    const providerNames =
      Array.isArray(options.providerNames) && options.providerNames.length > 0
        ? [...new Set(options.providerNames.map((name) => String(name || '').trim()).filter(Boolean))]
        : null
    const ruleSourceSnapshot = options.ruleSourceSnapshot || (await assertRuleSourceReadyForSync())
    const runtimeProviderEntries = ruleSourceSnapshot.providers
    const sourceMetadata = saveRuleProviderSourceMetadata(runtimeProviderEntries, {
      plugin: ruleSourceSnapshot.plugin,
      configPath: ruleSourceSnapshot.configPath,
    })

    const ruleSourceConfigSync = {
      changed: false,
      updatedProviders: runtimeProviderEntries.length,
      path: ruleSourceSnapshot.configPath,
      skipped: false,
      error: '',
      plugin: ruleSourceSnapshot.plugin,
    }

    const providers = runtimeProviderEntries
      .map((provider) => ({
        ...provider,
        kind: getRuleProviderKind(provider.url, provider.format, provider.behavior),
      }))
      .filter((provider) => !providerNames || providerNames.includes(provider.name))
    const configuredProviderNameSet = new Set(providers.map((provider) => provider.name))
    const unresolvedProviderNames =
      providerNames?.filter((providerName) => !configuredProviderNameSet.has(providerName)) || []
    const cachedProviderMap = new Map(
      getCachedRuleProviderStatement.all().map((provider) => [provider.name, provider]),
    )
    const errors = unresolvedProviderNames.map((providerName) => ({
      name: providerName,
      url: '',
      message:
        `Rule provider source URL is not configured for "${providerName}". Check the current OpenClash/Nikki YAML read through OpenWrt SSH.`,
    }))
    let updatedCount = 0
    let progressRules = 0
    const fetchedItems = []
    const unsupportedCount = 0

    activeRuleProviderUpdateController = new AbortController()
    ruleProviderUpdateState = {
      isUpdating: true,
      totalProviders: providers.length,
      updatedProviders: 0,
      totalRules: 0,
      errors: errors.length,
      unsupportedCount,
      cancelled: false,
      completed: false,
    }

    for (const provider of providers) {
      if (activeRuleProviderUpdateController.signal.aborted) {
        break
      }

      const cachedProvider = cachedProviderMap.get(provider.name)
      const shouldRefresh =
        force ||
        !cachedProvider ||
        cachedProvider.source_url !== provider.url ||
        cachedProvider.kind !== provider.kind ||
        cachedProvider.behavior !== provider.behavior ||
        cachedProvider.format !== provider.format ||
        cachedProvider.interval_seconds !== provider.interval ||
        isCacheExpired(cachedProvider.updated_at, provider.interval)

      if (!shouldRefresh) {
        continue
      }

      try {
        const body = await fetchProviderBody(provider)

        if (activeRuleProviderUpdateController.signal.aborted) {
          break
        }

        fetchedItems.push({ provider, body })
        updatedCount++
        const nextRuleCount = countRulesInBody(body)

        if (providerNames?.length === 1) {
          await animateRuleCountProgress({
            startCount: 0,
            endCount: nextRuleCount,
            signal: activeRuleProviderUpdateController?.signal,
            onProgress: (displayCount) => {
              ruleProviderUpdateState = {
                ...ruleProviderUpdateState,
                updatedProviders: updatedCount,
                totalRules: displayCount,
              }
            },
          })

          if (activeRuleProviderUpdateController.signal.aborted) {
            break
          }

          progressRules = nextRuleCount
        } else {
          progressRules += nextRuleCount
          ruleProviderUpdateState = {
            ...ruleProviderUpdateState,
            updatedProviders: updatedCount,
            totalRules: progressRules,
          }
        }
      } catch (error) {
        if (activeRuleProviderUpdateController.signal.aborted) {
          break
        }

        errors.push({
          name: provider.name,
          url: provider.url,
          message: error instanceof Error ? error.message : String(error),
        })
        ruleProviderUpdateState = {
          ...ruleProviderUpdateState,
          errors: errors.length,
        }
      }
    }

    const cancelled = activeRuleProviderUpdateController.signal.aborted

    if (!cancelled) {
      replaceRuleProviderCache(fetchedItems, { force: force && !providerNames })
    }

    ruleProviderUpdateState = {
      ...ruleProviderUpdateState,
      isUpdating: false,
      cancelled,
      completed: true,
    }

    return {
      ok: true,
      totalProviders: providers.length,
      updatedCount,
      unsupportedCount,
      mode: force ? 'force' : 'interval',
      providerNames,
      totalRules: getRuleProviderCacheRuleCount(),
      providerCounts: getRuleProviderCacheProviderCounts(),
      providerUrls: sourceMetadata.providerUrls,
      providerOrder: sourceMetadata.providerOrder,
      progressRules,
      cancelled,
      errors,
      ruleSourceConfigSync,
    }
  })()

  try {
    return await activeRuleProviderUpdatePromise
  } finally {
    activeRuleProviderUpdatePromise = null
    activeRuleProviderUpdateController = null
  }
}

const cancelRuleProviderUpdate = () => {
  if (activeRuleProviderUpdateController && !activeRuleProviderUpdateController.signal.aborted) {
    activeRuleProviderUpdateController.abort()
    ruleProviderUpdateState = {
      ...ruleProviderUpdateState,
      isUpdating: false,
      cancelled: true,
      completed: true,
    }
    return true
  }

  return false
}

const runRuleProviderAutoRefresh = async (reason = 'interval') => {
  try {
    const result = await updateRuleProviderCache({ force: false })

    if (result.updatedCount > 0 || result.errors.length > 0) {
      console.log(
        `[rule-provider-cache] auto refresh (${reason}) finished: ${result.updatedCount}/${result.totalProviders} providers updated, ${result.totalRules} rules cached`,
      )

      if (result.errors.length > 0) {
        console.warn(
          '[rule-provider-cache] auto refresh completed with errors:',
          result.errors.map((entry) => `${entry.name}: ${entry.message}`).join('; '),
        )
      }
    }
  } catch (error) {
    console.warn(`[rule-provider-cache] auto refresh (${reason}) failed`, error)
  }
}

const startRuleProviderAutoRefresh = () => {
  if (ruleProviderAutoRefreshTimer) {
    return
  }

  ruleProviderAutoRefreshTimer = setInterval(() => {
    void runRuleProviderAutoRefresh()
  }, RULE_PROVIDER_AUTO_REFRESH_CHECK_MS)

  if (typeof ruleProviderAutoRefreshTimer.unref === 'function') {
    ruleProviderAutoRefreshTimer.unref()
  }
}

const stopRuleProviderAutoRefresh = () => {
  if (!ruleProviderAutoRefreshTimer) {
    return
  }

  clearInterval(ruleProviderAutoRefreshTimer)
  ruleProviderAutoRefreshTimer = null
}

const getRuleRefreshResponsePayload = (options = {}) => {
  const providerName = options.providerName ? String(options.providerName).trim() : ''

  return {
    refresh: ruleRefreshState,
    progress: ruleProviderUpdateState,
    totalRules: getRuleProviderCacheRuleCount(),
    providerCounts: getRuleProviderCacheProviderCounts(),
    providerUrls: {},
    providerOrder: [],
    providerName,
  }
}

const startBackgroundRuleRefresh = async (options = {}) => {
  const targetProviderName = typeof options.providerName === 'string' ? options.providerName.trim() : ''
  const referencedOnly = options.referencedOnly === true
  const requestedProviderNames = targetProviderName
    ? [targetProviderName]
    : Array.isArray(options.providerNames)
      ? [...new Set(options.providerNames.map((name) => String(name || '').trim()).filter(Boolean))]
      : []

  if (activeRuleRefreshPromise) {
    return {
      ok: true,
      started: false,
      ...getRuleRefreshResponsePayload({
        providerName: targetProviderName,
      }),
    }
  }

  const backend = readActiveBackendConfig()

  if (!backend) {
    throw new Error('No active backend configured')
  }

  const ruleSourceSnapshot = await assertRuleSourceReadyForSync()

  activeRuleRefreshController = new AbortController()
  ruleRefreshRunId += 1
  ruleRefreshState = {
    ...createDefaultRuleRefreshState(),
    runId: ruleRefreshRunId,
    isRefreshing: true,
    scope: requestedProviderNames.length === 1 ? 'provider' : 'all',
    providerName: targetProviderName,
    phase: 'provider',
    totalRules: getRuleProviderCacheRuleCount(),
  }

  activeRuleRefreshPromise = (async () => {
    let processedProviders = 0
    let providerErrors = 0

    try {
      const targetProviderNames = targetProviderName
        ? [targetProviderName]
        : referencedOnly
          ? getReferencedProviderNamesFromControllerRules(await fetchControllerRules(backend))
          : Array.isArray(options.providerNames)
            ? [...new Set(options.providerNames.map((name) => String(name || '').trim()).filter(Boolean))]
            : []
      const providers = (await fetchControllerRuleProviders(backend))
        .filter(
          (provider) =>
            provider &&
            typeof provider === 'object' &&
            typeof provider.name === 'string' &&
            provider.name &&
            provider.vehicleType !== 'Inline',
        )
        .filter((provider) => targetProviderNames.length === 0 || targetProviderNames.includes(provider.name))

      if (targetProviderNames.length > 0 && providers.length === 0) {
        throw new Error(
          targetProviderName
            ? `Rule provider not found: ${targetProviderName}`
            : 'Rule providers not found',
        )
      }

      setRuleRefreshState({
        totalProviders: providers.length,
      })

      for (const provider of providers) {
        if (activeRuleRefreshController.signal.aborted) {
          break
        }

        try {
          await controllerFetch(backend, `/providers/rules/${encodeURIComponent(provider.name)}`, {
            method: 'PUT',
          })
        } catch {
          if (activeRuleRefreshController.signal.aborted) {
            break
          }

          providerErrors += 1
        } finally {
          if (!activeRuleRefreshController.signal.aborted) {
            processedProviders += 1
            setRuleRefreshState({
              updatedProviders: processedProviders,
              errors: providerErrors,
            })
          }
        }
      }

      if (activeRuleRefreshController.signal.aborted) {
        setRuleRefreshState({
          isRefreshing: false,
          cancelled: true,
          completed: true,
          completedAt: Date.now(),
          phase: 'idle',
        })

        return
      }

      setRuleRefreshState({
        phase: 'cache',
        updatedProviders: providers.length,
      })

      const cacheResult = await updateRuleProviderCache({
        force: true,
        providerNames: targetProviderNames.length > 0 ? targetProviderNames : null,
        ruleSourceSnapshot,
      })
      const targetTotalRules =
        targetProviderNames.length > 0
          ? targetProviderNames.reduce((total, providerName) => {
              return total + (cacheResult.providerCounts?.[providerName] ?? 0)
            }, 0)
          : cacheResult.totalRules

      setRuleRefreshState({
        isRefreshing: false,
        phase: 'idle',
        totalRules: targetTotalRules,
        errors: providerErrors + cacheResult.errors.length,
        cancelled: cacheResult.cancelled,
        completed: true,
        completedAt: Date.now(),
        lastError:
          cacheResult.errors[0]?.message || (providerErrors > 0 ? 'provider refresh failed' : ''),
      })
    } catch (error) {
      const isCancelled = activeRuleRefreshController?.signal.aborted === true
      const message = error instanceof Error ? error.message : String(error)

      setRuleRefreshState({
        isRefreshing: false,
        phase: 'idle',
        cancelled: isCancelled,
        completed: true,
        completedAt: Date.now(),
        errors: providerErrors + (isCancelled ? 0 : 1),
        lastError: isCancelled ? '' : message,
      })
    } finally {
      activeRuleRefreshPromise = null
      activeRuleRefreshController = null
    }
  })()

  return {
    ok: true,
    started: true,
    ...getRuleRefreshResponsePayload({
      providerName: targetProviderName,
    }),
  }
}

const cancelBackgroundRuleRefresh = () => {
  let cancelled = false

  if (activeRuleRefreshController && !activeRuleRefreshController.signal.aborted) {
    activeRuleRefreshController.abort()
    cancelled = true
  }

  if (cancelRuleProviderUpdate()) {
    cancelled = true
  }

  if (cancelled) {
    setRuleRefreshState({
      isRefreshing: false,
      phase: 'idle',
      cancelled: true,
      completed: true,
      completedAt: Date.now(),
    })
  }

  return {
    ok: cancelled,
    ...getRuleRefreshResponsePayload({
      providerName: ruleRefreshState.providerName,
    }),
  }
}

const searchRuleProviderCache = async (query, options = {}) => {
  const lookup = normalizeLookupInput(query)

  if (!lookup) {
    throw new Error('query is invalid')
  }

  const lookups = [lookup]
  const rules = Array.isArray(options.rules) ? options.rules : []
  const providerNames = new Set(
    Array.isArray(options.providerNames) && options.providerNames.length > 0
      ? options.providerNames.map((name) => String(name || '').trim()).filter(Boolean)
      : getReferencedProviderNamesFromControllerRules(rules),
  )
  const hasProviderFilter = providerNames.size > 0

  const cachedProviders = getCachedRuleProviderStatement
    .all()
    .filter((provider) => !hasProviderFilter || providerNames.has(provider.name))
  const cachedSourceMetadata = getCachedRuleProviderSourceMetadata()
  const needsLiveSourceMetadata =
    cachedProviders.length > 0 &&
    cachedProviders.some(
      (provider) => !provider.source_url && !cachedSourceMetadata.providerUrls[provider.name],
    )
  const sourceMetadata = needsLiveSourceMetadata
    ? await getRuleProviderSourceMetadata()
    : cachedSourceMetadata
  const matches = []
  const unsupported = []
  const directRuleIndexes = []

  for (const provider of cachedProviders) {
    const providerMatches = await findMatchesInTextRulesByLookups(lookups, provider.body)

    if (providerMatches.length > 0) {
      matches.push({
        name: provider.name,
        behavior: provider.behavior,
        format: provider.format,
        url: sourceMetadata.providerUrls[provider.name] || normalizeRuleProviderUrl(provider.source_url),
        totalRules: countRulesInBody(provider.body),
        status: 'cached',
        matches: sortRuleMatchesByLookup(lookup, providerMatches).slice(0, 20),
      })
    }
  }

  rules.forEach((rule) => {
    if (normalizeRuleTypeName(rule?.type) === 'RULE-SET') {
      return
    }

    const directRuleEntry = parseDirectControllerRuleEntry(rule)

    if (!directRuleEntry) {
      return
    }

    const directMatches = mergeLookupMatches(
      lookups.map((currentLookup) => findMatchesInTextRules(currentLookup, directRuleEntry.raw)),
    )

    if (directMatches.length > 0 && Number.isInteger(rule?.index)) {
      directRuleIndexes.push(rule.index)
      return
    }

    if (
      lookup.type === 'keyword' &&
      [rule.type, rule.payload, rule.proxy].some((value) =>
        String(value || '').toLowerCase().includes(lookup.value),
      ) &&
      Number.isInteger(rule?.index)
    ) {
      directRuleIndexes.push(rule.index)
    }
  })

  return {
    query: lookup.raw,
    queryType: lookup.type,
    mode: 'cached',
    matches,
    directRuleIndexes: [...new Set(directRuleIndexes)].sort((left, right) => left - right),
    unsupported,
    errors: [],
    totalProviders: sourceMetadata.providerOrder.length || cachedProviders.length,
    cachedProviders: cachedProviders.length,
  }
}

// ---------------------------------------------------------------------------
// 真实路由检测(route-penetration):移植自 Open-Box 的穿透查询。
// 输入域名/IP,按规则顺序预览首条命中规则,并由服务端实际发起请求,
// 通过 clash API /connections 捕获真实命中的规则、代理链路与 DNS 解析结果。
// ---------------------------------------------------------------------------

// 私有/回环/链路本地/CGNAT 网段(IPv4 + 常见 IPv6),用于 ip_is_private 判定
const PRIVATE_IP_CIDRS = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '100.64.0.0/10',
  '::1/128',
  'fc00::/7',
  'fe80::/10',
  '::ffff:0:0/96',
]

const isPrivateIpLookup = (lookup) => {
  if (!lookup || lookup.type !== 'ip') {
    return false
  }

  return PRIVATE_IP_CIDRS.some((cidr) => isIpInCidr(lookup.parsedIp, cidr))
}

// 与 findMatchesInTextRules 的"搜索"语义不同:路由判定必须是严格语义 ——
// suffix 即 domain === value || domain.endsWith('.' + value),keyword 即包含;
// 不做 isDomainSearchMatch 里"规则值反向属于域名"的宽松匹配。
const findStrictRuleSetMatches = (lookup, body) => {
  const matches = []
  const lines = String(body || '').split(/\r?\n/)

  lines.forEach((rawLine, index) => {
    const line = rawLine.trim()

    if (!line || line.startsWith('#') || line.startsWith('//') || /^payload\s*:/i.test(line)) {
      return
    }

    const normalizedLine = line.startsWith('- ') ? line.slice(2).trim() : line

    if (!normalizedLine) {
      return
    }

    let hit = null

    if (/^(domain|suffix|keyword|ip-cidr|ip-cidr6):/i.test(normalizedLine)) {
      const [, key, value] = normalizedLine.match(/^([^:]+):\s*(.+)$/) || []

      if (key && value) {
        const normalizedKey = key.toLowerCase()

        if (normalizedKey.includes('ip')) {
          hit =
            lookup.type === 'ip' && isIpInCidr(lookup.parsedIp, value) ? value : null
        } else {
          const mode = normalizedKey.includes('suffix')
            ? 'suffix'
            : normalizedKey.includes('keyword')
              ? 'keyword'
              : 'domain'

          hit =
            lookup.type === 'domain' && isDomainMatch(lookup.value, value, mode) ? value : null
        }
      }
    } else if (lookup.type !== 'ip' && normalizedLine.startsWith('+.')) {
      const value = normalizedLine.slice(2)

      hit = isDomainMatch(lookup.value, value, 'suffix') ? normalizedLine : null
    } else {
      const parts = normalizedLine.split(',').map((part) => part.trim())
      const ruleType = (parts[0] || '').toUpperCase()

      if (lookup.type === 'ip') {
        if (['IP-CIDR', 'IP-CIDR6', 'SRC-IP', 'SRC-IP-CIDR', 'SRC-IP-CIDR6'].includes(ruleType)) {
          hit = parts[1] && isIpInCidr(lookup.parsedIp, parts[1]) ? parts[1] : null
        } else if (!normalizedLine.includes(',') && parseIpCidr(normalizedLine)) {
          hit = isIpInCidr(lookup.parsedIp, normalizedLine) ? normalizedLine : null
        }
      } else if (ruleType === 'DOMAIN-REGEX' && parts[1]) {
        try {
          hit = new RegExp(parts[1], 'i').test(lookup.value) ? parts[1] : null
        } catch {
          hit = null
        }
      } else if (['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'].includes(ruleType) && parts[1]) {
        const mode =
          ruleType === 'DOMAIN-SUFFIX' ? 'suffix' : ruleType === 'DOMAIN-KEYWORD' ? 'keyword' : 'domain'

        hit = isDomainMatch(lookup.value, parts[1], mode) ? parts[1] : null
      } else if (
        // 裸域名行(domain behavior 的源格式,每行一个精确域名;无类型前缀、无逗号)
        !normalizedLine.includes(',') &&
        !ruleType.includes('IP') &&
        !ruleType.includes('PORT') &&
        !ruleType.includes('PROCESS')
      ) {
        hit = isDomainMatch(lookup.value, normalizedLine, 'domain') ? normalizedLine : null
      }
    }

    if (hit) {
      matches.push({ line: index + 1, value: hit })
    }
  })

  return matches
}

// sing-box clash API 的规则 payload 是条件表达式,不是单个值:
//   "domain_suffix=[work.weixin.qq.com weixin.qq.com qq.com...]"
//   "rule_set=geosite-ai" / "ip_is_private=true" / "port=[50228 50229]"
// 解析成 { key, values, truncated };无法解析返回 null。
const parseRoutePenetrationCondition = (term) => {
  const match = String(term || '').trim().match(/^([a-z0-9_]+)\s*=\s*(.+)$/i)

  if (!match) {
    return null
  }

  const key = match[1].toLowerCase()
  const raw = match[2].trim()
  const values = []
  let truncated = false

  if (raw.startsWith('[') && raw.endsWith(']')) {
    for (const token of raw.slice(1, -1).split(/\s+/)) {
      let value = token.trim()
      if (!value) continue
      // sing-box 截断长列表时直接把 "..." 接在最后一个值后面(无空格)
      if (value.endsWith('...')) {
        value = value.slice(0, -3)
        truncated = true
        if (!value) continue
      }
      if (value === '...') {
        truncated = true
        continue
      }
      values.push(value)
    }
  } else if (raw) {
    values.push(raw)
  }

  return { key, values, truncated }
}

// 单个条件求值:true=命中,false=确定不命中,null=无法判定。
// domain_suffix 多值列表被 "..." 截断时,可见值全不命中也无法断言不命中 → null。
const evaluateRouteConditionTerm = (lookup, cond) => {
  if (!cond || cond.values.length === 0) {
    return null
  }

  const someDomain = (mode) =>
    lookup.type === 'domain' && cond.values.some((v) => isDomainMatch(lookup.value, v, mode))

  switch (cond.key) {
    case 'domain':
      return someDomain('domain')
    case 'domain_suffix':
      if (someDomain('suffix')) return true
      return cond.truncated ? null : false
    case 'domain_keyword':
      if (someDomain('keyword')) return true
      return cond.truncated ? null : false
    case 'domain_regex': {
      if (lookup.type !== 'domain') return false
      try {
        return cond.values.some((v) => new RegExp(v, 'i').test(lookup.value))
      } catch {
        return null
      }
    }
    case 'ip_cidr':
      if (lookup.type !== 'ip') return false
      if (cond.values.some((v) => isIpInCidr(lookup.parsedIp, v))) return true
      return cond.truncated ? null : false
    case 'ip_is_private':
      return isPrivateIpLookup(lookup)
    default:
      // port/source_*/process_name/network/protocol/clash_mode 等与"目标域名/IP"
      // 这一输入无关,无法判定
      return null
  }
}

// 括号感知的顶层 " || " 切分(值列表 [a b c] 内含空格,不能直接 split)
const splitTopLevelOr = (payload) => {
  const parts = []
  let start = 0
  let depth = 0

  for (let i = 0; i < payload.length; i++) {
    const ch = payload[i]

    if (ch === '[' || ch === '(') depth++
    else if (ch === ']' || ch === ')') depth--
    else if (depth === 0 && payload.startsWith(' || ', i)) {
      parts.push(payload.slice(start, i))
      i += 4
      start = i
    }
  }

  parts.push(payload.slice(start))
  return parts.filter((p) => p.trim())
}

// mihomo/clash 传统规则(type 即条件类型,payload 是裸值)的兼容求值
const evaluateLegacyDirectType = (lookup, normalizedType, payload) => {
  if (!payload) return null
  switch (normalizedType) {
    case 'DOMAIN':
      return lookup.type === 'domain' && isDomainMatch(lookup.value, payload, 'domain')
    case 'DOMAIN-SUFFIX':
      return lookup.type === 'domain' && isDomainMatch(lookup.value, payload, 'suffix')
    case 'DOMAIN-KEYWORD':
      return lookup.type === 'domain' && isDomainMatch(lookup.value, payload, 'keyword')
    case 'DOMAIN-REGEX': {
      if (lookup.type !== 'domain') return false
      try {
        return new RegExp(payload, 'i').test(lookup.value)
      } catch {
        return null
      }
    }
    case 'IP-CIDR':
    case 'IP-CIDR6':
      return lookup.type === 'ip' && isIpInCidr(lookup.parsedIp, payload)
    case 'IP-ISPRIVATE':
    case 'IPISPRIVATE':
      return isPrivateIpLookup(lookup)
    default:
      return undefined
  }
}

// sing-box 的 proxy 字段形如 route(直连),链路解析/展示用去掉包裹后的名字
const unwrapRouteOutbound = (proxy) =>
  proxy.startsWith('route(') && proxy.endsWith(')') ? proxy.slice(6, -1) : proxy

// sniff/hijack-dns/resolve 是处理型 action,不决定流量去向,命中也不终止求值
const isNonTerminatingOutbound = (proxy) => {
  const inner = unwrapRouteOutbound(proxy)
  return /^(sniff|hijack-dns|resolve)(\s*\(|$)/.test(inner)
}

// 从 controller rules 里收集引用到的 rule_set 名称(RULE-SET 裸值 + payload 里的 rule_set=x 条件)
const collectReferencedRuleSetNames = (controllerRules) => {
  const names = new Set()

  for (const rule of controllerRules || []) {
    if (!isRuleEnabled(rule)) continue

    const normalizedType = normalizeRuleTypeName(rule?.type)
    const payload = String(rule?.payload || '').trim()

    if (normalizedType === 'RULE-SET') {
      if (payload) names.add(payload)
      continue
    }

    for (const match of payload.matchAll(/\brule_set\s*=\s*([A-Za-z0-9._!-]+)/g)) {
      if (match[1]) names.add(match[1])
    }
  }

  return [...names]
}

// 读取本机 sing-box 配置(GUI.for.SingBox / 标准路径),解析失败返回 null
const findLocalSingBoxConfig = () => {
  const homeDir = os.homedir()
  const candidates = [
    process.env.ZASHBOARD_SINGBOX_CONFIG,
    path.join(homeDir, 'Library/Application Support/GUI.for.SingBox/sing-box/config.json'),
    path.join(homeDir, '.config/sing-box/config.json'),
    '/usr/local/etc/sing-box/config.json',
    '/etc/sing-box/config.json',
  ].filter(Boolean)

  for (const configPath of candidates) {
    try {
      if (!fs.existsSync(configPath)) continue
      return JSON.parse(fs.readFileSync(configPath, 'utf8'))
    } catch {
      // 配置不可读就换下一个候选路径
    }
  }

  return null
}

// 判断域名会走哪个 DNS 服务器:按 dns.rules 顺序匹配,回落 dns.final。
// 支持 domain/domain_suffix/domain_keyword/query_type/rule_set 条件;
// clash_mode 依赖客户端状态,无法预判时跳过该条。
const resolveDnsRouteInfo = (lookup, config, srsMatchMap, orphanMatch = null) => {
  const dns = config?.dns

  if (!dns || !Array.isArray(dns.servers) || dns.servers.length === 0) {
    return null
  }

  const serverByTag = new Map(dns.servers.map((server) => [server.tag, server]))
  const describeServer = (tag) => {
    const server = serverByTag.get(tag)

    if (!server) {
      return { server: tag, protocol: '', address: '', detour: '' }
    }

    return {
      server: tag,
      protocol: String(server.type || ''),
      address: String(server.server || server.address || ''),
      detour: String(server.detour || ''),
    }
  }

  const rules = Array.isArray(dns.rules) ? dns.rules : []

  const resolveOnce = (skipFakeip) => {
    for (const rule of rules) {
      if (!rule || typeof rule !== 'object') continue

      if (rule.clash_mode) {
        // direct/global 模式依赖客户端状态,预览时无法判定,跳过
        continue
      }

      if (skipFakeip && rule.server && serverByTag.get(rule.server)?.type === 'fakeip') {
        continue
      }

      if (
        Array.isArray(rule.query_type) &&
        !rule.query_type.some((t) => String(t).toUpperCase() === 'A')
      ) {
        continue
      }

      if (Array.isArray(rule.domain)) {
        if (!rule.domain.includes(lookup.value)) continue
      } else if (Array.isArray(rule.domain_suffix)) {
        if (
          !rule.domain_suffix.some(
            (suffix) => lookup.value === suffix || lookup.value.endsWith(`.${suffix}`),
          )
        )
          continue
      } else if (Array.isArray(rule.domain_keyword)) {
        if (!rule.domain_keyword.some((keyword) => lookup.value.includes(keyword))) continue
      } else if (Array.isArray(rule.rule_set)) {
        const allMatched = rule.rule_set.every(
          (name) => srsMatchMap.get(name)?.hit === true || orphanMatch?.hit === true,
        )

        if (!allMatched) continue
      }

      if (rule.action === 'reject') {
        return { rejected: true, server: '', protocol: '', address: '', detour: '' }
      }

      if (rule.action === 'route' && rule.server) {
        return describeServer(rule.server)
      }
    }

    if (dns.final) {
      return describeServer(dns.final)
    }

    return null
  }

  const primary = resolveOnce(false)

  if (!primary || primary.rejected) {
    return primary
  }

  // fakeip 模式下客户端拿到的是假 IP,真实解析走上游:再按"跳过 fakeip"求值一次
  if (primary.protocol === 'fakeip') {
    const realServer = resolveOnce(true)

    return { ...primary, fakeip: true, realServer: realServer && !realServer.rejected ? realServer : null }
  }

  return primary
}

// .srs 二进制规则集预匹配:evaluateRoutePenetrationRules 是同步求值,
// 异步的二进制匹配在进入求值前先算好,以 name → {hit, error} 传入。
// 运行中内核的规则集可能与磁盘配置快照不一致(缓存里没有的名字):
// 从同前缀(geosite-/geoip-)的已缓存提供者的 URL 推导出下载地址再匹配。
const deriveMissingSrsUrl = (name, cachedProviders) => {
  const prefixMatch = String(name || '').match(/^(geosite|geoip)-/i)

  if (!prefixMatch) {
    return ''
  }

  const prefix = prefixMatch[0]
  const suffix = String(name).slice(prefix.length)

  if (!/^[a-z0-9-]+$/i.test(suffix)) {
    return ''
  }

  const donor = cachedProviders.find(
    (provider) =>
      provider &&
      provider.name &&
      provider.name.startsWith(prefix) &&
      provider.source_url &&
      provider.source_url.includes(provider.name.slice(prefix.length)),
  )

  if (!donor) {
    return ''
  }

  const donorSuffix = donor.name.slice(prefix.length)

  return normalizeRuleProviderUrl(donor.source_url.replace(donorSuffix, suffix))
}

const buildSrsMatchMap = async (controllerRules, target) => {
  const names = collectReferencedRuleSetNames(controllerRules)
  const map = new Map()
  const cachedProviders = getCachedRuleProviderStatement.all()

  await Promise.all(
    names.map(async (name) => {
      const cachedProvider = getCachedRuleProviderByNameStatement.get(name)

      if (!cachedProvider) {
        // 缓存缺失时按同前缀 URL 模板推导(仅对 .srs 二进制有意义)
        const derivedUrl = deriveMissingSrsUrl(name, cachedProviders)

        if (!derivedUrl) {
          return
        }

        try {
          map.set(name, await matchSrsRuleSetWithLocalBinary(name, derivedUrl, target))
        } catch (error) {
          map.set(name, { hit: false, error: getErrorMessage(error) })
        }
        return
      }

      if (String(cachedProvider.behavior || '').toLowerCase() !== 'srs') return

      const url = normalizeRuleProviderUrl(cachedProvider.source_url)

      if (!url) {
        map.set(name, { hit: false, error: 'srs source url unknown' })
        return
      }

      try {
        map.set(name, await matchSrsRuleSetWithLocalBinary(name, url, target))
      } catch (error) {
        map.set(name, { hit: false, error: getErrorMessage(error) })
      }
    }),
  )

  // 用户改过 rule_set tag 而内核没重启时,新 tag(缓存缺失)对应的规则集文件
  // 其实已在缓存里(挂在旧 tag 名下)。恰好只有一个"当前规则未引用的孤儿"时,
  // 用它补位匹配;多于一个则无法定位,保持三态。
  const orphanCandidates = names.length
    ? cachedProviders.filter(
        (provider) =>
          String(provider.behavior || '').toLowerCase() === 'srs' &&
          provider.source_url &&
          !names.includes(provider.name),
      )
    : []
  let orphanMatch = null

  if (orphanCandidates.length === 1) {
    const orphan = orphanCandidates[0]

    try {
      const result = await matchSrsRuleSetWithLocalBinary(
        orphan.name,
        normalizeRuleProviderUrl(orphan.source_url),
        target,
      )
      orphanMatch = { ...result, orphanName: orphan.name }
    } catch (error) {
      orphanMatch = { hit: false, error: getErrorMessage(error), orphanName: orphan.name }
    }
  }

  return { map, orphanMatch }
}

const evaluateRoutePenetrationRules = (
  lookup,
  controllerRules,
  srsMatchMap = new Map(),
  orphanMatch = null,
) => {
  let matchError = ''

  // RuleSet 条件的三态求值;无法确认时写入 matchError 并立即中断整个求值
  const resolveRuleSetTerm = (name) => {
    const cachedProvider = name ? getCachedRuleProviderByNameStatement.get(name) : null

    if (!cachedProvider) {
      // 缓存缺失时:先试推导 URL 的二进制匹配;推导失败(如改名后文件名猜不中)
      // 再退到唯一的孤儿规则集(旧 tag 名下的同内容文件)
      const derivedResult = srsMatchMap.get(name)

      if (derivedResult && !derivedResult.error) {
        return derivedResult.hit
      }

      if (orphanMatch) {
        if (orphanMatch.error) {
          matchError = orphanMatch.error
          return null
        }

        return orphanMatch.hit
      }

      matchError = derivedResult?.error || `rule provider cache not found: ${name}`
      return null
    }

    if (String(cachedProvider.behavior || '').toLowerCase() === 'srs') {
      // .srs 二进制规则集:用进入求值前算好的本机 sing-box 匹配结果
      const srsResult = srsMatchMap.get(name)

      if (!srsResult) {
        matchError = `binary .srs cache is not parseable: ${name}`
        return null
      }

      if (srsResult.error) {
        matchError = srsResult.error
        return null
      }

      return srsResult.hit
    }

    return findStrictRuleSetMatches(lookup, cachedProvider.body).length > 0
  }

  // 条件项求值(rule_set 交给缓存求值器)
  const evaluateTerm = (term) => {
    const trimmed = term.trim()

    if (trimmed.startsWith('!(') || trimmed.startsWith('(')) {
      return evaluateLogicalExpression(trimmed)
    }

    const cond = parseRoutePenetrationCondition(trimmed)

    if (!cond) {
      return null
    }

    if (cond.key === 'rule_set') {
      return resolveRuleSetTerm(cond.values[0])
    }

    return evaluateRouteConditionTerm(lookup, cond)
  }

  // 逻辑表达式:可选 !(...) 前缀 + 顶层 " || " 切分。
  // 任一项 true → true;全 false → false;夹着 null → null(无法确认)
  const evaluateLogicalExpression = (expr) => {
    const trimmed = expr.trim()
    let inverted = false
    let inner = trimmed

    if (inner.startsWith('!(') && inner.endsWith(')')) {
      inverted = true
      inner = inner.slice(2, -1)
    } else if (inner.startsWith('(') && inner.endsWith(')')) {
      inner = inner.slice(1, -1)
    }

    const terms = splitTopLevelOr(inner)
    let sawNull = false

    for (const term of terms) {
      const value = evaluateTerm(term)

      if (value === true) {
        return inverted ? false : true
      }
      if (value === null) {
        sawNull = true
      }
    }

    if (sawNull) return null
    return inverted ? true : false
  }

  const evaluateRulePayload = (payload) => {
    if (!payload) return null
    return evaluateLogicalExpression(payload)
  }

  let matched = null
  let finalOutbound = ''
  const skippedTypes = new Set()

  for (let i = 0; i < controllerRules.length; i++) {
    const rule = controllerRules[i]

    if (!isRuleEnabled(rule)) {
      continue
    }

    const normalizedType = normalizeRuleTypeName(rule?.type)
    const payload = String(rule?.payload || '').trim()
    const proxy = String(rule?.proxy || '').trim()

    if (normalizedType === 'MATCH' || normalizedType === 'FINAL') {
      finalOutbound = unwrapRouteOutbound(proxy)
      continue
    }

    let result = null

    if (normalizedType === 'RULE-SET') {
      result = resolveRuleSetTerm(payload)
    } else if (normalizedType === 'DEFAULT' || normalizedType === 'LOGICAL') {
      result = evaluateRulePayload(payload)
    } else {
      const legacy = evaluateLegacyDirectType(lookup, normalizedType, payload)
      result = legacy === undefined ? null : legacy
    }

    if (result === null && matchError) {
      // 三态里的"无法确认":带上规则位置,绝不能谎报"未命中"
      matchError = `rule #${i + 1} (${payload}): ${matchError}`
      matched = null
      break
    }

    if (result === null) {
      skippedTypes.add(String(rule?.type || ''))
    }

    if (result && !isNonTerminatingOutbound(proxy)) {
      matched = { index: i, type: String(rule?.type || ''), payload, outbound: unwrapRouteOutbound(proxy) }
      break
    }
  }

  return { matched, matchError, finalOutbound, skippedTypes: [...skippedTypes] }
}

// 沿 clash API /proxies/{tag} 的 now 字段逐层下钻直到叶子节点。
// 任何一步失败都降级为 chainError(保留已解析部分),不让整个请求失败。
const resolveRoutePenetrationChain = async (backend, tag) => {
  const chain = [tag]
  const seen = new Set([tag])
  let current = tag
  const MAX_DEPTH = 16

  for (let i = 0; i < MAX_DEPTH; i++) {
    let body
    try {
      const response = await controllerFetch(backend, `/proxies/${encodeURIComponent(current)}`, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(5000),
      })
      body = await response.json()
    } catch (error) {
      return { chain, chainError: `clash api unreachable: ${getErrorMessage(error)}` }
    }

    const now = body && typeof body.now === 'string' && body.now ? body.now : null

    if (!now || seen.has(now)) {
      break
    }

    seen.add(now)
    chain.push(now)
    current = now
  }

  return { chain }
}

const sleepForMs = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

// ---------------------------------------------------------------------------
// .srs 二进制规则集匹配:借用本机 sing-box 二进制跑 `rule-set match`
// (移植自 Open-Box penetration.mjs,命中与否退出码都是 0,必须看输出)。
// ---------------------------------------------------------------------------

const findLocalSingBoxBinary = () => {
  const homeDir = os.homedir()
  const gsfmDir = path.join(homeDir, 'Library/Application Support/GUI.for.SingBox/sing-box')
  const candidates = [
    process.env.ZASHBOARD_SINGBOX_BIN,
    path.join(gsfmDir, 'sing-box'),
    path.join(gsfmDir, 'sing-box.exe'),
    '/usr/bin/sing-box',
    '/usr/local/bin/sing-box',
    '/etc/momo/bin/sing-box',
  ].filter(Boolean)

  const found = candidates.find((candidate) => {
    try {
      return fs.existsSync(candidate) && fs.statSync(candidate).isFile()
    } catch {
      return false
    }
  })

  if (found) {
    return found
  }

  // 兜底:从 PATH 里找(sing-box 装在非标准位置但已在 PATH 中时)
  try {
    const which = execFileSync('which', ['sing-box'], { encoding: 'utf8', timeout: 3000 }).trim()

    return which || null
  } catch {
    return null
  }
}

const srsCacheDir = path.join(dataDir, 'rule-srs')

const ensureSrsFileOnDisk = async (providerName, url) => {
  fs.mkdirSync(srsCacheDir, { recursive: true })
  const safeName = providerName.replace(/[^a-zA-Z0-9._-]/g, '_')
  const filePath = path.join(srsCacheDir, `${safeName}.srs`)

  if (fs.existsSync(filePath)) {
    return filePath
  }

  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`download failed: ${response.status}`)
  }

  const buffer = Buffer.from(await response.arrayBuffer())
  await fs.promises.writeFile(filePath, buffer)
  return filePath
}

// 返回 { hit, error }:hit=true 命中;hit=false 且无 error 是确认未命中;
// error 非空表示"没能确认"(二进制缺失/下载失败/进程异常),绝不当作未命中。
const matchSrsRuleSetWithLocalBinary = async (providerName, url, target) => {
  const singboxBin = findLocalSingBoxBinary()

  if (!singboxBin) {
    return { hit: false, error: 'sing-box binary not found on this host' }
  }

  let srsPath
  try {
    srsPath = await ensureSrsFileOnDisk(providerName, url)
  } catch (error) {
    return { hit: false, error: `srs download failed: ${getErrorMessage(error)}` }
  }

  let stdout = ''
  let stderr = ''
  let code = 0
  try {
    const result = await execFileAsync(singboxBin, [
      'rule-set',
      'match',
      '-f',
      'binary',
      srsPath,
      target,
    ])
    stdout = result.stdout || ''
    stderr = result.stderr || ''
  } catch (error) {
    // 命中与否退出码都是 0;非 0 说明进程本身没跑成
    code = Number.isInteger(error?.code) ? error.code : 1
    stdout = error?.stdout || ''
    stderr = error?.stderr || ''
  }

  // "match rules." 可能出现在 stdout 或 stderr(不同版本行为不一致),后面跟命中条目序号
  const matchOutput = `${stdout}${stderr}`
  const matchLine = matchOutput.match(/^match rules\.\[(\d+)\]/m)

  if (matchLine) {
    return { hit: true, line: Number.parseInt(matchLine[1], 10) + 1 }
  }

  if (code !== 0 && !stdout && !stderr) {
    return { hit: false, error: `sing-box rule-set match exited ${code} with no output` }
  }

  return { hit: false }
}

// 读取本机 sing-box 配置(GUI.for.SingBox / sing-box 标准路径),找本地 mixed/http 入站端口。
// 真实路由检测经它发请求,流量才会进入内核;找不到则退回服务端直连发出。
const findLocalSingBoxProxyInbound = () => {
  const homeDir = os.homedir()
  const candidates = [
    path.join(homeDir, 'Library/Application Support/GUI.for.SingBox/sing-box/config.json'),
    path.join(homeDir, 'Library/Application Support/GUI.for.SingBox/config.json'),
    path.join(homeDir, '.config/sing-box/config.json'),
    '/usr/local/etc/sing-box/config.json',
    '/etc/sing-box/config.json',
  ]

  for (const configPath of candidates) {
    try {
      if (!fs.existsSync(configPath)) continue
      const config = JSON.parse(fs.readFileSync(configPath, 'utf8'))
      const inbounds = Array.isArray(config?.inbounds) ? config.inbounds : []
      const proxy = inbounds.find(
        (inbound) =>
          inbound &&
          (inbound.type === 'mixed' || inbound.type === 'http') &&
          Number.isInteger(inbound.listen_port),
      )

      if (proxy) {
        const listen = String(proxy.listen || '').trim()
        return {
          host: !listen || listen === '0.0.0.0' || listen === '::' ? '127.0.0.1' : listen,
          port: proxy.listen_port,
        }
      }
    } catch {
      // 配置不可读就换下一个候选路径
    }
  }

  return null
}

// 优先经本机 sing-box 代理端口发起(结果才反映内核真实路由);无本地入站则服务端直连发出。
// 返回 Promise<{ status, ms, location, error }> 供"真实路由"块展示请求耗时与 HTTP 状态。
const fireRoutePenetrationRequest = async (lookup, target) => {
  const inbound = findLocalSingBoxProxyInbound()
  const bracketedTarget = lookup.type === 'ip' && lookup.parsedIp.version === 6 ? `[${target}]` : target
  const requestUrl = `http://${bracketedTarget}/`
  const startedAt = Date.now()

  if (inbound) {
    return await new Promise((resolve) => {
      const request = http.request(
        {
          host: inbound.host,
          port: inbound.port,
          method: 'GET',
          path: requestUrl,
          headers: { Host: bracketedTarget },
          timeout: 8000,
        },
        (response) => {
          const result = {
            status: response.statusCode || 0,
            ms: Date.now() - startedAt,
            location: String(response.headers?.location || ''),
            error: '',
          }
          // 不消费响应体,保持连接打开直到 /connections 捕获后由 DELETE 清理
          resolve(result)
        },
      )

      request.on('error', (error) => {
        resolve({ status: 0, ms: Date.now() - startedAt, location: '', error: getErrorMessage(error) })
      })
      request.on('timeout', () => {
        request.destroy()
        resolve({ status: 0, ms: Date.now() - startedAt, location: '', error: 'request timeout' })
      })
      request.end()
    })
  }

  try {
    const response = await fetch(requestUrl, {
      redirect: 'manual',
      signal: AbortSignal.timeout(8000),
    })

    return {
      status: response.status,
      ms: Date.now() - startedAt,
      location: response.headers.get('location') || '',
      error: '',
    }
  } catch (error) {
    return { status: 0, ms: Date.now() - startedAt, location: '', error: getErrorMessage(error) }
  }
}

// 由服务端实际发起一次请求(结果可失败,只为触发核心建立连接),
// 随后轮询 /connections 捕获该目标的真实连接:命中规则、链路、DNS 解析结果。
const runRoutePenetrationLiveTest = async (backend, lookup, target) => {
  let requestPromise = fireRoutePenetrationRequest(lookup, target)

  const normalizedTarget = String(target || '').trim().toLowerCase()
  const MAX_POLLS = 36

  for (let i = 0; i < MAX_POLLS; i++) {
    // 部分源站(如秒回 301 的站点)整个连接只存活几十毫秒:
    // 前 ~500ms 用 30ms 密集轮询并多次补发,之后退化为 200ms 常规轮询
    if (i > 0) await sleepForMs(i <= 16 ? 30 : 200)

    if (i === 3 || i === 9 || i === 21) {
      requestPromise = fireRoutePenetrationRequest(lookup, target)
    }

    let connections = []
    try {
      const response = await controllerFetch(backend, '/connections', {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(5000),
      })
      const data = await response.json()
      connections = Array.isArray(data?.connections) ? data.connections : []
    } catch {
      continue
    }

    const connection = connections.find((item) => {
      const metadata = item?.metadata || {}
      const host = String(metadata.host || '').trim().toLowerCase()
      const sniffHost = String(metadata.sniffHost || '').trim().toLowerCase()
      const destinationIp = String(metadata.destinationIP || '').trim().toLowerCase()

      return (
        host === normalizedTarget ||
        sniffHost === normalizedTarget ||
        (lookup.type === 'ip' && destinationIp === normalizedTarget)
      )
    })

    if (connection) {
      const metadata = connection.metadata || {}

      try {
        await controllerFetch(backend, `/connections/${encodeURIComponent(connection.id)}`, {
          method: 'DELETE',
          signal: AbortSignal.timeout(3000),
        })
      } catch {
        // 清理失败不影响结果
      }

      // 找到连接后,等最新的真实请求结果(最多 1.5 秒)以拿到 HTTP 状态与耗时
      const requestResult = await Promise.race([
        requestPromise,
        sleepForMs(1500).then(() => null),
      ])

      return {
        found: true,
        id: connection.id,
        rule: String(connection.rule || ''),
        rulePayload: String(connection.rulePayload || ''),
        // clash API 返回的是 叶子→策略组 的倒序,反转成与预览链路一致的 策略组→出口
        chains: (Array.isArray(connection.chains) ? connection.chains : []).slice().reverse(),
        destinationIP: String(metadata.destinationIP || ''),
        destinationPort: String(metadata.destinationPort || ''),
        dnsMode: String(metadata.dnsMode || ''),
        sniffHost: String(metadata.sniffHost || ''),
        requestMs: requestResult?.ms || 0,
        httpStatus: requestResult?.status || 0,
        httpLocation: requestResult?.location || '',
        requestError: requestResult?.error || '',
      }
    }
  }

  return {
    found: false,
    liveError:
      'connection not observed: the server host traffic may not go through the core, or the request failed',
  }
}

const queryRoutePenetrationDns = async (backend, target) => {
  const startedAt = Date.now()

  try {
    const response = await controllerFetch(
      backend,
      `/dns/query?name=${encodeURIComponent(target)}`,
      {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(5000),
      },
    )

    return { answer: await response.json(), ms: Date.now() - startedAt }
  } catch {
    return { answer: null, ms: Date.now() - startedAt }
  }
}

const app = express()
const server = http.createServer(app)
const websocketServer = new WebSocketServer({ noServer: true })

app.use('/api/auth', express.json({ limit: '2kb' }))
app.use('/api/rule-refresh', express.json({ limit: '2kb' }))
app.use('/api/rule-provider-penetration', express.json({ limit: '2kb' }))
app.use('/api/route-penetration', express.json({ limit: '2kb' }))
app.use('/api/rule-provider-search', express.json({ limit: '128kb' }))
app.use('/api/storage', express.json({ limit: '25mb' }))
app.use('/api/openwrt-rule-source', express.json({ limit: '8kb' }))
app.use('/api/proxy-domain-rules', express.json({ limit: '8kb' }))
app.use('/api/background-image', express.json({ limit: '25mb' }))
app.use('/api/proxy-group-rule-penetration', express.json({ limit: '5mb' }))
app.use('/api/controller', express.raw({ type: '*/*', limit: '25mb' }))

app.get('/api/auth/status', (req, res) => {
  const authStatus = getRequestAccessAuthStatus(req)

  res.setHeader('Cache-Control', 'no-store')

  if (!authStatus.enabled) {
    clearAccessSessionCookie(res)
  }

  res.json(authStatus)
})

app.post('/api/auth/login', (req, res) => {
  const { enabled, password } = readAccessAuthConfig()

  res.setHeader('Cache-Control', 'no-store')

  if (!enabled) {
    clearAccessSessionCookie(res)
    res.json({
      enabled: false,
      authenticated: true,
    })
    return
  }

  const inputPassword = typeof req.body?.password === 'string' ? req.body.password : ''

  if (!safeTokenEquals(inputPassword, password)) {
    clearAccessSessionCookie(res)
    res.status(401).json({
      code: ACCESS_PASSWORD_INVALID_CODE,
      message: 'Invalid access password',
      enabled: true,
      authenticated: false,
    })
    return
  }

  setAccessSessionCookie(res, password)
  res.json({
    enabled: true,
    authenticated: true,
  })
})

app.post('/api/auth/logout', (_req, res) => {
  clearAccessSessionCookie(res)
  res.setHeader('Cache-Control', 'no-store')

  const { enabled } = readAccessAuthConfig()
  res.json({
    enabled,
    authenticated: !enabled,
  })
})

app.use((req, res, next) => {
  if (!req.path.startsWith('/api/')) {
    next()
    return
  }

  if (
    req.path === '/api/health' ||
    req.path === '/api/auth/status' ||
    req.path === '/api/auth/login' ||
    req.path === '/api/auth/logout'
  ) {
    next()
    return
  }

  const authStatus = getRequestAccessAuthStatus(req)

  if (!authStatus.enabled || authStatus.authenticated) {
    next()
    return
  }

  sendAccessPasswordRequired(res)
})

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    dbPath,
  })
})

app.get('/api/openwrt-rule-source/config', (_req, res) => {
  res.json({
    config: sanitizeOpenWrtRuleSourceSshConfig(readOpenWrtRuleSourceSshConfig()),
  })
})

app.get('/api/proxy-domain-custom-sections', async (_req, res) => {
  try {
    res.json(await getOpenWrtCustomRuleStatus())
  } catch {
    res.json({ enabled: false, plugin: '' })
  }
})

app.put('/api/openwrt-rule-source/config', (req, res) => {
  const config = normalizeOpenWrtRuleSourceSshConfigInput(req.body?.config || req.body)

  try {
    saveOpenWrtRuleSourceSshConfig(config)

    res.json({
      ok: true,
      config: sanitizeOpenWrtRuleSourceSshConfig(readOpenWrtRuleSourceSshConfig()),
    })
  } catch (error) {
    res.status(500).json({
      message: error instanceof Error ? error.message : String(error),
    })
  }
})

app.post('/api/openwrt-rule-source/detect', async (req, res) => {
  const config = req.body?.config
    ? {
      ...normalizeOpenWrtRuleSourceSshConfigInput(req.body.config),
      configured: true,
    }
    : readOpenWrtRuleSourceSshConfig()

  try {
    const snapshot = await getOpenWrtRuleSourceSnapshot({
      config,
      required: true,
    })

    if (!snapshot) {
      throw new Error('OpenWrt rule source is not configured.')
    }

    res.json({
      ok: true,
      plugin: snapshot.plugin,
      selectedPlugin: snapshot.selectedPlugin || snapshot.plugin,
      availablePlugins: snapshot.availablePlugins || [snapshot.plugin],
      pluginErrors: snapshot.pluginErrors || [],
      configPath: snapshot.configPath,
      providerCount: snapshot.providers.length,
      providers: snapshot.providers.slice(0, 20).map((provider) => ({
        name: provider.name,
        behavior: provider.behavior,
        format: provider.format,
        url: provider.url,
      })),
    })
  } catch (error) {
    res.status(500).json({
      message: error instanceof Error ? error.message : String(error),
    })
  }
})

app.all(/^\/api\/controller(?:\/.*)?$/, proxyControllerRequest)

app.get('/api/storage', (_req, res) => {
  res.json({
    entries: readSnapshot(),
  })
})

app.put('/api/storage', (req, res) => {
  const { entries } = req.body ?? {}

  if (!isValidEntries(entries)) {
    res.status(400).json({
      message: 'entries must be an object with string values',
    })
    return
  }

  replaceSnapshot(entries)

  res.json({
    ok: true,
    count: Object.keys(entries).length,
  })
})

app.get('/api/background-image', (_req, res) => {
  const row = getStorageValueStatement.get(backgroundImageStorageKey)

  res.json({
    image: row?.value || '',
  })
})

app.put('/api/background-image', (req, res) => {
  const { image } = req.body ?? {}

  if (typeof image !== 'string') {
    res.status(400).json({
      message: 'image must be a string',
    })
    return
  }

  upsertStorageValueStatement.run(backgroundImageStorageKey, image)

  res.json({
    ok: true,
    size: image.length,
  })
})

app.delete('/api/background-image', (_req, res) => {
  deleteStorageValueStatement.run(backgroundImageStorageKey)

  res.json({
    ok: true,
  })
})

app.post('/api/rule-provider-cache/update', async (_req, res) => {
  try {
    res.json(await updateRuleProviderCache())
  } catch (error) {
    res.status(500).json({
      code: getErrorCode(error),
      message: getLocalizedErrorMessage(error, _req),
    })
  }
})

app.post('/api/rule-provider-cache/cancel', (_req, res) => {
  res.json({
    ok: cancelRuleProviderUpdate(),
    progress: ruleProviderUpdateState,
  })
})

app.post('/api/rule-refresh/start', async (req, res) => {
  try {
    const providerName =
      typeof req.body?.providerName === 'string' ? req.body.providerName.trim() : ''
    const referencedOnly = req.body?.referencedOnly === true
    const providerNames = Array.isArray(req.body?.providerNames)
      ? req.body.providerNames
      : []

    res.json(
      await startBackgroundRuleRefresh({
        providerName,
        referencedOnly,
        providerNames,
      }),
    )
  } catch (error) {
    res.status(500).json({
      code: getErrorCode(error),
      message: getLocalizedErrorMessage(error, req),
    })
  }
})

app.post('/api/rule-refresh/cancel', (_req, res) => {
  res.json(cancelBackgroundRuleRefresh())
})

app.get('/api/rule-provider-cache/stats', async (_req, res) => {
  const sourceMetadata = await getRuleProviderSourceMetadata()

  res.json({
    totalRules: getRuleProviderCacheRuleCount(),
    providerCounts: getRuleProviderCacheProviderCounts(),
    providerUrls: sourceMetadata.providerUrls,
    providerOrder: sourceMetadata.providerOrder,
    progress: ruleProviderUpdateState,
    refresh: ruleRefreshState,
  })
})

app.get('/api/rule-provider-search', async (req, res) => {
  const query =
    typeof req.query.query === 'string'
      ? req.query.query
      : typeof req.query.domain === 'string'
        ? req.query.domain
        : ''

  if (!query.trim()) {
    res.status(400).json({
      message: 'query is required',
    })
    return
  }

  try {
    res.json(await searchRuleProviderCache(query))
  } catch (error) {
    res.status(500).json({
      message: error instanceof Error ? error.message : String(error),
    })
  }
})

app.post('/api/rule-provider-search', async (req, res) => {
  const query =
    typeof req.body?.query === 'string'
      ? req.body.query
      : typeof req.body?.domain === 'string'
        ? req.body.domain
        : ''
  const rules = Array.isArray(req.body?.rules) ? req.body.rules : []

  if (!query.trim()) {
    res.status(400).json({
      message: 'query is required',
    })
    return
  }

  try {
    res.json(
      await searchRuleProviderCache(query, {
        rules,
      }),
    )
  } catch (error) {
    res.status(500).json({
      message: error instanceof Error ? error.message : String(error),
    })
  }
})

app.post('/api/rule-provider-penetration', (req, res) => {
  const providerName = typeof req.body?.providerName === 'string' ? req.body.providerName.trim() : ''
  const page = normalizePositiveInteger(req.body?.page, 1, 10000)
  const pageSize = normalizePositiveInteger(req.body?.pageSize, 100, 500)
  const tab = normalizeProxyGroupRulePenetrationTab(req.body?.tab)
  const search = typeof req.body?.search === 'string' ? req.body.search.trim() : ''
  const sortKey = normalizeProxyGroupRulePenetrationSortKey(req.body?.sortKey)
  const sortDirection = normalizeProxyGroupRulePenetrationSortDirection(req.body?.sortDirection)

  if (!providerName) {
    res.status(400).json({
      message: 'providerName is required',
    })
    return
  }

  try {
    const cachedProvider = getCachedRuleProviderByNameStatement.get(providerName)

    if (!cachedProvider) {
      res.status(404).json({
        message: `Rule provider cache not found: ${providerName}`,
      })
      return
    }

    const allEntries = parseRuleEntriesFromBody(cachedProvider.body, providerName)
    const searchMatchedEntries = allEntries.filter((entry) =>
      matchesProxyGroupRulePenetrationSearch(entry, search),
    )
    const counts = buildRulePenetrationCounts(searchMatchedEntries)
    const tabMatchedEntries =
      tab === 'all' ? searchMatchedEntries : searchMatchedEntries.filter((entry) => entry.family === tab)
    const sortedEntries = sortProxyGroupRulePenetrationEntries(tabMatchedEntries, sortKey, sortDirection)
    const start = (page - 1) * pageSize
    const end = start + pageSize

    res.json({
      cacheKey: '',
      providerName,
      totalRules: allEntries.length,
      totalMatched: tabMatchedEntries.length,
      counts,
      items: sortedEntries.slice(start, end),
      missingProviders: [],
      page,
      pageSize,
      hasMore: end < sortedEntries.length,
    })
  } catch (error) {
    res.status(500).json({
      message: error instanceof Error ? error.message : String(error),
    })
  }
})

app.post('/api/route-penetration', async (req, res) => {
  const target = typeof req.body?.target === 'string' ? req.body.target.trim() : ''

  if (!target) {
    res.status(400).json({ message: 'target is required' })
    return
  }

  // target 只允许域名/IP 合法字符集,且不允许以 "-" 开头(防 CLI 参数注入形态)
  if (target.startsWith('-') || !/^[A-Za-z0-9._:-]+$/.test(target)) {
    res.status(400).json({ message: 'target must be a valid domain or IP address' })
    return
  }

  try {
    const backend = readActiveBackendConfig()

    if (!backend) {
      res.status(400).json({ message: 'No active backend configured' })
      return
    }

    const lookup = normalizeLookupInput(target)

    if (!lookup || (lookup.type !== 'domain' && lookup.type !== 'ip')) {
      res.status(400).json({ message: 'target must be a valid domain or IP address' })
      return
    }

    const controllerRules = await fetchControllerRules(backend)
    const { map: srsMatchMap, orphanMatch } = await buildSrsMatchMap(controllerRules, target)
    const { matched, matchError, finalOutbound, skippedTypes } = evaluateRoutePenetrationRules(
      lookup,
      controllerRules,
      srsMatchMap,
      orphanMatch,
    )

    // matchError 已设置时,finalOutbound/链路结论不再可信,不自信地报告
    const resolvedOutbound = matchError
      ? ''
      : matched
        ? matched.outbound
        : finalOutbound

    let chain = resolvedOutbound ? [resolvedOutbound] : []
    let chainError = ''

    if (resolvedOutbound) {
      const chainResult = await resolveRoutePenetrationChain(backend, resolvedOutbound)
      chain = chainResult.chain
      chainError = chainResult.chainError || ''
    }

    // 域名会由哪个 DNS 服务器解析(读本机 sing-box 配置推断);IP 输入不涉及
    const dnsInfo =
      lookup.type === 'domain'
        ? resolveDnsRouteInfo(lookup, findLocalSingBoxConfig(), srsMatchMap, orphanMatch)
        : null

    // 命中的规则若是规则集,附带集内命中的条目(文本缓存给行号+值,.srs 只能给行号)
    let matchedEntry = null

    if (matched) {
      const conditionMatch = matched.payload.match(/^rule_set=([A-Za-z0-9._!-]+)$/)
      const ruleSetName = conditionMatch?.[1] || (matched.type === 'RuleSet' ? matched.payload : '')

      if (ruleSetName) {
        const cachedProvider = getCachedRuleProviderByNameStatement.get(ruleSetName)
        const srsResult = srsMatchMap.get(ruleSetName)

        if (cachedProvider && String(cachedProvider.behavior || '').toLowerCase() !== 'srs') {
          const textMatch = findStrictRuleSetMatches(lookup, cachedProvider.body)[0]

          if (textMatch) {
            matchedEntry = { ruleset: ruleSetName, ...textMatch }
          }
        } else if (srsResult?.hit && Number.isInteger(srsResult.line)) {
          matchedEntry = { ruleset: ruleSetName, line: srsResult.line, value: '', mode: '' }
        }
      }
    }

    let live = null
    let liveError = ''

    if (req.body?.live !== false) {
      const liveResult = await runRoutePenetrationLiveTest(backend, lookup, target)
      live = liveResult.found ? liveResult : null
      liveError = liveResult.liveError || ''
    }

    let dnsAnswer = null

    if (req.body?.live !== false) {
      dnsAnswer = await queryRoutePenetrationDns(backend, target)
    }

    res.json({
      target,
      queryType: lookup.type,
      preview: {
        matched,
        matchError,
        finalOutbound,
        skippedTypes,
        resolvedOutbound,
        chain,
        chainError,
        dns: dnsInfo,
        matchedEntry,
      },
      live,
      liveError,
      dnsAnswer,
    })
  } catch (error) {
    res.status(500).json({
      message: error instanceof Error ? error.message : String(error),
    })
  }
})

app.post('/api/proxy-domain-rules', async (req, res) => {
  try {
    res.json(await addProxyDomainRuleToRemoteConfig(req.body || {}))
  } catch (error) {
    res.status(getErrorStatusCode(error)).json({
      code: getErrorCode(error),
      message: getLocalizedErrorMessage(error, req),
    })
  }
})

app.put('/api/proxy-domain-rules', async (req, res) => {
  try {
    res.json(await updateProxyDomainRuleOnOpenWrt(req.body || {}))
  } catch (error) {
    res.status(getErrorStatusCode(error)).json({
      code: getErrorCode(error),
      message: getLocalizedErrorMessage(error, req),
    })
  }
})

app.delete('/api/proxy-domain-rules', async (req, res) => {
  try {
    res.json(await deleteProxyDomainRuleOnOpenWrt(req.body || {}))
  } catch (error) {
    res.status(getErrorStatusCode(error)).json({
      code: getErrorCode(error),
      message: getLocalizedErrorMessage(error, req),
    })
  }
})

app.post('/api/proxy-domain-rules/reload', async (req, res) => {
  try {
    res.json(await reloadProxyDomainRulesOnOpenWrt())
  } catch (error) {
    res.status(getErrorStatusCode(error)).json({
      code: getErrorCode(error),
      message: getLocalizedErrorMessage(error, req),
    })
  }
})

app.put('/api/proxy-domain-rules/order', async (req, res) => {
  try {
    res.json(await reorderProxyDomainRulesOnOpenWrt(req.body || {}))
  } catch (error) {
    res.status(getErrorStatusCode(error)).json({
      code: getErrorCode(error),
      message: getLocalizedErrorMessage(error, req),
    })
  }
})

app.post('/api/proxy-group-rule-penetration', async (req, res) => {
  const groupName = typeof req.body?.groupName === 'string' ? req.body.groupName.trim() : ''
  const cacheKey = typeof req.body?.cacheKey === 'string' ? req.body.cacheKey.trim() : ''
  const rules = Array.isArray(req.body?.rules) ? req.body.rules : null
  const customGroupMode =
    normalizeProxyGroupCustomMode(req.body?.customGroupMode) || getProxyGroupCustomModeFromGroupName(groupName)
  const customGroup = customGroupMode !== null || req.body?.customGroup === true
  const providerName = typeof req.body?.providerName === 'string' ? req.body.providerName.trim() : ''
  const page = normalizePositiveInteger(req.body?.page, 1, 10000)
  const pageSize = normalizePositiveInteger(req.body?.pageSize, 100, 500)
  const tab = normalizeProxyGroupRulePenetrationTab(req.body?.tab)
  const search = typeof req.body?.search === 'string' ? req.body.search.trim() : ''
  const sortKey = normalizeProxyGroupRulePenetrationSortKey(req.body?.sortKey)
  const sortDirection = normalizeProxyGroupRulePenetrationSortDirection(req.body?.sortDirection)

  if (!groupName) {
    res.status(400).json({
      message: 'groupName is required',
    })
    return
  }

  if (!customGroup && !cacheKey && !Array.isArray(rules)) {
    res.status(400).json({
      message: 'rules must be an array when cacheKey is missing',
    })
    return
  }

  try {
    const remoteCustomRules =
      customGroupMode === 'pre' || customGroupMode === 'post'
        ? await readProxyDomainCustomRulesOnOpenWrt(customGroupMode)
        : null
    const cacheEntry = remoteCustomRules
      ? null
      : getProxyGroupRulePenetrationCacheEntry({
          groupName,
          cacheKey,
          rules: rules || [],
          customGroup,
          customGroupMode,
        })
    const sourceEntries = remoteCustomRules?.items || cacheEntry.items
    const scopedEntries = providerName
      ? sourceEntries.filter((entry) => {
          return providerName === 'controller' ? entry.source === 'controller' : entry.source === providerName
        })
      : sourceEntries
    const searchMatchedEntries = scopedEntries.filter((entry) =>
      matchesProxyGroupRulePenetrationSearch(entry, search),
    )
    const counts = buildRulePenetrationCounts(searchMatchedEntries)

    const tabMatchedEntries =
      tab === 'all' ? searchMatchedEntries : searchMatchedEntries.filter((entry) => entry.family === tab)
    const sortedEntries = sortProxyGroupRulePenetrationEntries(tabMatchedEntries, sortKey, sortDirection)
    const start = (page - 1) * pageSize
    const end = start + pageSize

    res.json({
      cacheKey: cacheEntry?.cacheKey || '',
      groupName,
      customGroup,
      customGroupMode,
      providerName,
      totalRules: remoteCustomRules?.items.length ?? cacheEntry.totalRules,
      totalMatched: tabMatchedEntries.length,
      counts,
      items: sortedEntries.slice(start, end),
      missingProviders: cacheEntry?.missingProviders || [],
      configPath: remoteCustomRules?.configPath || '',
      page,
      pageSize,
      hasMore: end < sortedEntries.length,
    })
  } catch (error) {
    if (error?.code === 'CACHE_EXPIRED') {
      res.status(410).json({
        message: 'cache expired',
      })
      return
    }

    res.status(getErrorStatusCode(error)).json({
      code: getErrorCode(error),
      message: getLocalizedErrorMessage(error, req),
    })
  }
})

app.get('/sw.js', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
  res.type('application/javascript')
  res.send(serviceWorkerCleanupScript)
})

app.get('/registerSW.js', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
  res.type('application/javascript')
  res.send(registerSWCleanupScript)
})

if (fs.existsSync(distDir)) {
  app.use(
    express.static(distDir, {
      setHeaders: (res, filePath) => {
        const fileName = path.basename(filePath)

        if (
          fileName === 'index.html' ||
          fileName === 'sw.js' ||
          fileName === 'registerSW.js' ||
          fileName === 'manifest.webmanifest'
        ) {
          res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
          return
        }

        if (/^index-[A-Za-z0-9_-]+\.(js|css)$/.test(fileName)) {
          res.setHeader('Cache-Control', 'public, max-age=31536000, immutable')
        }
      },
    }),
  )

  app.get(/^(?!\/api\/).*/, (_req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
    res.sendFile(path.join(distDir, 'index.html'))
  })
}

const writeUpgradeUnauthorized = (socket) => {
  socket.write(
    `HTTP/1.1 401 Unauthorized\r
Content-Type: application/json; charset=utf-8\r
Connection: close\r
\r
${JSON.stringify({
  code: ACCESS_PASSWORD_REQUIRED_CODE,
  message: 'Access password authentication required',
})}`,
  )
  socket.destroy()
}

server.on('upgrade', (request, socket, head) => {
  try {
    const requestUrl = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`)

    if (!requestUrl.pathname.startsWith('/api/controller-ws')) {
      socket.destroy()
      return
    }

    const authStatus = getUpgradeAccessAuthStatus(request)

    if (authStatus.enabled && !authStatus.authenticated) {
      writeUpgradeUnauthorized(socket)
      return
    }

    websocketServer.handleUpgrade(request, socket, head, (websocket) => {
      websocketServer.emit('connection', websocket, request)
    })
  } catch {
    socket.destroy()
  }
})

websocketServer.on('connection', relayControllerWebSocket)

const startServer = async () => {
  if (server.listening) {
    return server
  }

  await new Promise((resolve, reject) => {
    const handleError = (error) => {
      server.off('error', handleError)
      reject(error)
    }

    server.once('error', handleError)
    server.listen(port, host, () => {
      server.off('error', handleError)
      resolve()
    })
  })

  const address = server.address()
  const listenLabel =
    typeof address === 'object' && address
      ? `http://${address.address}:${address.port}`
      : `http://${host}:${port}`

  console.log(`zashboard server listening on ${listenLabel}`)
  console.log(`sqlite db: ${dbPath}`)
  startRuleProviderAutoRefresh()
  console.log(
    `rule-provider auto refresh check interval: ${Math.round(RULE_PROVIDER_AUTO_REFRESH_CHECK_MS / 1000)}s`,
  )

  return server
}

const shutdownServer = async () => {
  cancelRuleProviderUpdate()
  stopRuleProviderAutoRefresh()

  if (server.listening) {
    await new Promise((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error)
          return
        }

        resolve()
      })
    })
  }

  if (typeof db.close === 'function') {
    db.close()
  }
}

const isDirectExecution =
  Boolean(process.argv[1]) && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)

if (isDirectExecution) {
  startServer().catch((error) => {
    console.error(error instanceof Error ? error.message : error)
    process.exit(1)
  })
}

export {
  ACCESS_PASSWORD_INVALID_CODE,
  ACCESS_PASSWORD_REQUIRED_CODE,
  addProxyDomainRuleToYamlContent as addProxyDomainRuleToYamlContentForTesting,
  app,
  createAccessSessionToken as createAccessSessionTokenForTesting,
  deleteProxyDomainRuleInYamlContent as deleteProxyDomainRuleInYamlContentForTesting,
  extractNikkiYamlConfigPathsFromProcessList as extractNikkiYamlConfigPathsFromProcessListForTesting,
  db,

  extractRemoteYamlConfigPathsFromUci as extractRemoteYamlConfigPathsFromUciForTesting,
  getRequestAccessAuthStatus as getRequestAccessAuthStatusForTesting,
  getWritableProxyDomainRulePath as getWritableProxyDomainRulePathForTesting,
  isOpenWrtCustomRuleEnabled as isOpenWrtCustomRuleEnabledForTesting,
  normalizeWritableProxyDomainRuleInput as normalizeWritableProxyDomainRuleInputForTesting,
  parseProxyDomainCustomRulesFromYamlContent as parseProxyDomainCustomRulesFromYamlContentForTesting,
  reorderProxyDomainRulesInYamlContent as reorderProxyDomainRulesInYamlContentForTesting,
  updateProxyDomainRuleInYamlContent as updateProxyDomainRuleInYamlContentForTesting,
  resolveOpenClashConfigPathFromUci as resolveOpenClashConfigPathFromUciForTesting,
  readSnapshot,
  replaceSnapshot,
  searchRuleProviderCache,
  seedRuleProviderCacheForTesting,
  evaluateRoutePenetrationRules as evaluateRoutePenetrationRulesForTesting,
  findStrictRuleSetMatches as findStrictRuleSetMatchesForTesting,
  normalizeLookupInput as normalizeLookupInputForTesting,
  server,
  shutdownServer,
  startServer,
}
