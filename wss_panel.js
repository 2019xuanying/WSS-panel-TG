/**
 * WSS Panel Backend (Node.js + Express + SQLite)
 * V11.0.1 (Axiom Refactor V8.0 - BadVPN UDPGW Restore)
 *
 * [AXIOM V11.0.1 CHANGELOG]
 * - [REVERT] 恢复 udpgw 的端口配置和状态监控。
 * - [FEATURE] 在 CORE_SERVICES 中重新添加 'udpgw' 服务。
 * - [FEATURE] 在 getSystemStatusData 中查询 udpgw 的运行状态和端口状态。
 * - [BUGFIX] 修复 config 加载逻辑，确保 udpgw_port 存在。
 */

// --- 核心依赖 ---
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { execFile, spawn, exec } = require('child_process');
const { promisify } = require('util');
const path = require('path');
const fs = require('fs/promises');
const fsSync = require('fs');
const os = require('os');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const http = require('http');
const { WebSocketServer } = require('ws');
const tls = require('tls');
const dns = require('dns');

// [TG_BOT] 引入机器人逻辑模块
const { initTelegramBot } = require('./tg_bot_logic');

const app = express();
const asyncExecFile = promisify(execFile);

// --- [AXIOM V2.0] 配置加载 ---
let config = {};
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');
// [AXIOM V5.7] UDP Custom 专属配置路径
const UDP_CUSTOM_CONFIG_PATH = path.join(PANEL_DIR, 'udp-custom', 'config.json');

try {
    const configData = fsSync.readFileSync(CONFIG_PATH, 'utf8');
    config = JSON.parse(configData);
    // [AXIOM V11.0.1 FIX] 确保 udpgw_port 存在，如果旧配置没有，给默认值 7300
    if (!config.udpgw_port) config.udpgw_port = 7300;
    // [AXIOM V5.7] 确保 udp_custom_port 存在，如果旧配置没有，给默认值 7400
    if (!config.udp_custom_port) config.udp_custom_port = 7400;
    console.log(`[AXIOM V11.0.1] 成功从 ${CONFIG_PATH} 加载配置。UDPGW Port: ${config.udpgw_port}`);
} catch (e) {
    console.error(`[CRITICAL] 无法加载 ${CONFIG_PATH}: ${e.message}。将使用默认端口。`);
    // 默认配置
    config = {
        panel_port: 54321,
        wss_http_port: 80,
        wss_tls_port: 443,
        stunnel_port: 444,
        udpgw_port: 7300, // [RESTORED]
        udp_custom_port: 7400,
        internal_forward_port: 22,
        internal_api_port: 54322,
        internal_api_secret: "default-secret-change-me"
    };
    try {
        fsSync.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');
    } catch (writeErr) {
        console.error(`[CRITICAL] 无法写入默认配置: ${writeErr.message}`);
    }
}
// --- 结束配置加载 ---


// --- 核心常量 ---
const DB_PATH = path.join(PANEL_DIR, 'wss_panel.db');
const ROOT_HASH_FILE = path.join(PANEL_DIR, 'root_hash.txt');
const AUDIT_LOG_PATH = path.join(PANEL_DIR, 'audit.log');
const SECRET_KEY_PATH = path.join(PANEL_DIR, 'secret_key.txt');
const INTERNAL_SECRET_PATH = path.join(PANEL_DIR, 'internal_secret.txt');
const HOSTS_DB_PATH = path.join(PANEL_DIR, 'hosts.json');
const STUNNEL_CONF = '/etc/stunnel/ssh-tls.conf';
const ROOT_USERNAME = "root";
const GIGA_BYTE = 1024 * 1024 * 1024;
const BLOCK_CHAIN = "WSS_IP_BLOCK";
const BACKGROUND_SYNC_INTERVAL = 60000; 
const SYSTEM_HEALTH_CHECK_INTERVAL = 300000; // 5分钟检查一次系统健康
const STALE_CHECK_INTERVAL = 3000; // [V6.0 NEW] 3秒检查一次缓存状态
const STALE_TIMEOUT_MS = 3500; // [V6.0 NEW] 超过 3.5 秒未更新则认为是僵尸
const SHELL_DEFAULT = "/sbin/nologin";

// [AXIOM V11.0.1 UPDATE] 恢复 udpgw
const CORE_SERVICES = {
    'wss': 'WSS Proxy',
    'stunnel4': 'Stunnel4',
    'udpgw': 'BadVPN UDPGW (Binary)', // [RESTORED]
    'wss-udp-custom': 'UDP Custom', // [NEW] HTTP Custom UDP Tunnel
    'wss_panel': 'Web Panel'
};
let db;

// --- [AXIOM V7.0 NEW] 全局试用功能配置 (内存缓存) ---
// [V11.0 BUGFIX] 统一键名，避免 loadGlobalSettingsFromDb 的键名冲突
let globalTrialSettings = {
    enabled: false,
    auto_approve: false,
    max_attempts: 1,
    days: 1, // 统一为 days
    quota_gb: 1.0, // 统一为 quota_gb
    rate_kbps: 5120, 
    max_connections: 2,
    tg_alarm_threshold: 90 // CPU报警阈值 (Feature 3)
};
let globalFuseLimitKbps = 0;
let lastCpuUsage = 0; // 用于健康检查
let isCpuAlarmTriggered = false; // 报警状态

// [AXIOM V5.0] 实时推送状态管理 ---
let wssIpc = null;
let wssUiPool = new Set();
// [V6.0 UPDATE] Worker Cache 结构: 
let workerStatsCache = new Map(); 

// [AXIOM V5.0] 性能优化定时器
let liveUpdateInterval = null; 
let systemUpdateInterval = null; 
let staleCheckInterval = null; 
let systemHealthTimer = null; // [V11.0 NEW]
let isRealtimePushing = false; 

// [AXIOM V5.0] 智能推送：存储上一次推送的聚合数据，以便比较变化
let lastAggregatedStats = { users: {}, live_ips: {} };
let lastSystemStatus = {};

// [AXIOM V5.2] 新增：用于临时存储 Worker 元数据响应
let workerMetadataResponses = new Map();


const SUDO_COMMANDS = new Set([
    'useradd', 'usermod', 'userdel', 'gpasswd', 'chpasswd', 'pkill',
    'iptables', 'iptables-save', 'journalctl', 
    'systemctl', // 广义 systemctl，需要特殊处理
    'getent', 
    'sed', 
    'systemctl daemon-reload',
    'systemctl is-active',
    'systemctl restart',
    'systemctl stop',
    'systemctl enable',
    'systemctl disable'
]);

// =======================================================
// [AXIOM V5.5 FIX A7] 核心辅助函数：安全执行系统命令
// =======================================================

/**
 * [AXIOM V5.5 FIX A7] 增强对多参数命令的解析和执行，确保只执行白名单中的命令。
 */
async function safeRunCommand(command, inputData = null) {
    
    let fullCommand = [...command];
    let baseCommand = command[0];
    let isSudo = false;

    // 特殊处理带参数的 systemctl 命令，确保其在白名单内
    if (baseCommand === 'systemctl' && command.length > 1) {
        const fullSystemctlCmd = command.slice(0, 2).join(' ');
        if (SUDO_COMMANDS.has(fullSystemctlCmd)) {
            baseCommand = fullSystemctlCmd;
        } else if (command[1] === 'daemon-reload' && SUDO_COMMANDS.has('systemctl daemon-reload')) {
            baseCommand = 'systemctl daemon-reload';
        } else {
             // 如果不是已知的 systemctl 二级命令，回退到普通 systemctl 检查
             if (SUDO_COMMANDS.has(baseCommand)) {
                 // OK
             } else {
                 console.error(`[SUDO_CHECK] Command not whitelisted: ${command.join(' ')}`);
                 return { success: false, output: "Command not authorized." };
             }
        }
    } else if (!SUDO_COMMANDS.has(baseCommand)) {
        console.error(`[SUDO_CHECK] Command not whitelisted: ${command.join(' ')}`);
        return { success: false, output: "Command not authorized." };
    }
    
    if (SUDO_COMMANDS.has(baseCommand) || baseCommand.startsWith('systemctl')) {
        fullCommand.unshift('sudo');
        isSudo = true;
    }
    
    const commandToExec = fullCommand.join(' ');

    if (command[0] === 'chpasswd' || (isSudo && command[1] === 'chpasswd') && inputData) {
        return new Promise((resolve, reject) => {
            const child = spawn(fullCommand[0], fullCommand.slice(1), {
                stdio: ['pipe', 'pipe', 'pipe'],
                // [AXIOM V5.5 FIX] 确保 PATH 包含 Node.js 环境所需的路径
                env: { ...process.env, PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' }
            });
            let stdout = '';
            let stderr = '';
            child.stdout.on('data', (data) => { stdout += data.toString(); });
            child.stderr.on('data', (data) => { stderr += data.toString(); });
            child.on('close', (code) => {
                if (code === 0) {
                    resolve({ success: true, output: stdout.trim() });
                } else {
                    console.error(`safeRunCommand (spawn) Stderr (Command: ${commandToExec}): ${stderr.trim()}`);
                    resolve({ success: false, output: stderr.trim() || `Command ${commandToExec} failed with code ${code}` });
                }
            });
             child.on('error', (err) => {
                 console.error(`safeRunCommand (spawn) Error (Command: ${commandToExec}): ${err.message}`);
                resolve({ success: false, output: err.message });
            });
            try {
                child.stdin.write(inputData);
                child.stdin.end();
            } catch (e) {
                 resolve({ success: false, output: e.message });
            }
        });
    }

    try {
        const { stdout, stderr } = await asyncExecFile(fullCommand[0], fullCommand.slice(1), {
            timeout: 10000,
            input: inputData,
            // [AXIOM V5.5 FIX] 确保 PATH 包含 Node.js 环境所需的路径
            env: { ...process.env, PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' }
        });
        const output = (stdout + stderr).trim();
        
        if (stderr && 
            !stderr.includes('user not found') &&
            !stderr.includes('userdel: user') &&
            !stderr.includes('already exists')
           ) {
             console.warn(`safeRunCommand (asyncExecFile) Non-fatal Stderr (Command: ${commandToExec}): ${stderr.trim()}`);
        }
        return { success: true, output: stdout.trim() };
        
    } catch (e) {
        // systemctl is-active 失败（非活动状态）返回 code 3
        if (baseCommand === 'systemctl is-active' && e.code === 3) {
            return { success: false, output: 'inactive' };
        }
        
        if (e.code !== 'ETIMEDOUT') {
            console.error(`safeRunCommand (asyncExecFile) Fatal Error (Command: ${commandToExec}): Code=${e.code}, Stderr=${e.stderr || 'N/A'}, Msg=${e.message}`);
        }
        
        return { success: false, output: e.stderr || e.message || `Command ${fullCommand[0]} failed.` };
    }
}

async function loadRootHash() {
    try {
        const hash = await fs.readFile(ROOT_HASH_FILE, 'utf8');
        return hash.trim();
    } catch (e) {
        console.error(`Root hash file not found: ${e.message}`);
        return null;
    }
}

async function getUserByUsername(username) {
    return db.get('SELECT * FROM users WHERE username = ?', username);
}

function loadInternalSecret() {
    return config.internal_api_secret;
}

async function loadHosts() {
    try {
        if (!fsSync.existsSync(HOSTS_DB_PATH)) {
            await fs.writeFile(HOSTS_DB_PATH, '[]', 'utf8');
            return [];
        }
        const data = await fs.readFile(HOSTS_DB_PATH, 'utf8');
        const hosts = JSON.parse(data);
        if (Array.isArray(hosts)) {
            return hosts.map(h => String(h).toLowerCase()).filter(h => h);
        }
        return [];
    } catch (e) {
        console.error(`Error loading hosts file: ${e.message}`);
        return [];
    }
}

// --- 辅助函数 (safeRunCommand, logAction, getSystemLockStatus) ---

async function logAction(actionType, username, details = "") {
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const operatorIp = '127.0.0.1 (System)'; 
    const logEntry = `[${timestamp}] [USER:${username}] [IP:${operatorIp}] ACTION:${actionType} DETAILS: ${details}\n`;
    try {
        await fs.appendFile(AUDIT_LOG_PATH, logEntry);
    } catch (e) {
        console.error(`Error writing to audit log: ${e.message}`);
    }
}

async function getSystemLockStatus() {
    try {
        const { success, output } = await safeRunCommand(['getent', 'shadow']);
        if (!success) {
            console.error("[CRITICAL] getSystemLockStatus: Failed to run 'sudo getent shadow'. Falling back to empty map.");
            return new Set();
        }
        const lockedUsers = new Set();
        output.split('\n').forEach(line => {
            const parts = line.split(':');
            if (parts.length > 1) {
                const username = parts[0];
                const passwordHash = parts[1];
                if (passwordHash.startsWith('!') || passwordHash.startsWith('*')) {
                    lockedUsers.add(username);
                }
            }
        });
        return lockedUsers;
    } catch (e) {
        console.error(`[CRITICAL] getSystemLockStatus Error: ${e.message}`);
        return new Set();
    }
}


// --- 数据库 Setup and User Retrieval (initDb) ---

async function initDb() {
    db = await open({
        filename: DB_PATH,
        driver: sqlite3.Database
    });
    try {
        await db.exec('PRAGMA journal_mode = WAL;');
        console.log("[DB] WAL (Write-Ahead Logging) mode enabled.");
    } catch (e) {
        console.error(`[DB] Failed to enable WAL mode: ${e.message}`);
    }
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY, password_hash TEXT, created_at TEXT,
            status TEXT, expiration_date TEXT, quota_gb REAL,
            usage_gb REAL DEFAULT 0.0, rate_kbps INTEGER DEFAULT 0,
            max_connections INTEGER DEFAULT 0,
            require_auth_header INTEGER DEFAULT 1, realtime_speed_up REAL DEFAULT 0.0,
            realtime_speed_down REAL DEFAULT 0.0, active_connections INTEGER DEFAULT 0,
            status_text TEXT, allow_shell INTEGER DEFAULT 0, fuse_threshold_kbps INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS ip_bans ( ip TEXT PRIMARY KEY, reason TEXT, added_by TEXT, timestamp TEXT );
        CREATE TABLE IF NOT EXISTS traffic_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
            date TEXT NOT NULL, usage_gb REAL DEFAULT 0.0, UNIQUE(username, date)
        );
        CREATE TABLE IF NOT EXISTS global_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        -- [V9.9 NEW] 试用申请表: 记录来自 TG 的申请 (ID 用于唯一标识记录)
        CREATE TABLE IF NOT EXISTS trial_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            tg_id TEXT NOT NULL, 
            tg_username TEXT,
            status TEXT NOT NULL, -- pending, approved, rejected, completed
            request_time TEXT NOT NULL,
            username TEXT, -- 审核通过后关联的账号
            UNIQUE(tg_id, status) -- 确保每个用户只能有一条 pending 或 approved 记录
        );
        -- [V11.0 NEW] 账号绑定表: 记录 TG ID 和 WSS 账号的绑定关系 (Feature 4)
        CREATE TABLE IF NOT EXISTS tg_bindings (
            tg_id TEXT PRIMARY KEY, 
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL, -- 存储密码哈希以用于卡密兑换时的二次验证
            bind_time TEXT NOT NULL,
            UNIQUE(username) 
        );
        -- [V11.0 NEW] 卡密表: 记录生成的卡密 (Feature 1)
        CREATE TABLE IF NOT EXISTS vouchers (
            code TEXT PRIMARY KEY, 
            days INTEGER DEFAULT 0,
            quota_gb REAL DEFAULT 0.0,
            is_used INTEGER DEFAULT 0, -- 0: 未使用, 1: 已使用
            used_by TEXT, -- 使用的用户名
            used_at TEXT,
            created_at TEXT NOT NULL
        );
    `);
    await db.exec(`CREATE INDEX IF NOT EXISTS idx_traffic_history_user_date ON traffic_history (username, date);`);
    await db.exec(`CREATE INDEX IF NOT EXISTS idx_trial_requests_status ON trial_requests (status);`);
    await db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_trial_requests_tg_id_status ON trial_requests (tg_id, status) WHERE status IN ('pending', 'approved');`); // 确保唯一性

    // --- 表结构迁移 (保持现有逻辑) ---
    try { await db.exec('ALTER TABLE users ADD COLUMN password_hash TEXT'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN max_connections INTEGER DEFAULT 0'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN require_auth_header INTEGER DEFAULT 1'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN realtime_speed_up REAL DEFAULT 0.0'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN realtime_speed_down REAL DEFAULT 0.0'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN active_connections INTEGER DEFAULT 0'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN status_text TEXT'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN allow_shell INTEGER DEFAULT 0'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN fuse_threshold_kbps INTEGER DEFAULT 0'); } catch (e) { /* ignore */ }
    
    // --- [V11.0 UPDATE] 试用功能全局设置初始化 (统一键名) ---
    // 为了兼容旧的 DB 记录，我们仍然使用 'trial_' 前缀键写入，但在内存中统一键名
    await db.run("INSERT OR IGNORE INTO global_settings (key, value) VALUES (?, ?)", 'fuse_threshold_kbps', '0');
    await db.run("INSERT OR IGNORE INTO global_settings (key, value) VALUES (?, ?)", 'trial_enabled', '0');
    await db.run("INSERT OR IGNORE INTO global_settings (key, value) VALUES (?, ?)", 'trial_auto_approve', '0');
    await db.run("INSERT OR IGNORE INTO global_settings (key, value) VALUES (?, ?)", 'trial_max_attempts', '1');
    await db.run("INSERT OR IGNORE INTO global_settings (key, value) VALUES (?, ?)", 'trial_days', '1');
    await db.run("INSERT OR IGNORE INTO global_settings (key, value) VALUES (?, ?)", 'trial_quota_gb', '1.0');
    await db.run("INSERT OR IGNORE INTO global_settings (key, value) VALUES (?, ?)", 'trial_rate_kbps', '5120');
    await db.run("INSERT OR IGNORE INTO global_settings (key, value) VALUES (?, ?)", 'trial_max_connections', '2');
    await db.run("INSERT OR IGNORE INTO global_settings (key, value) VALUES (?, ?)", 'tg_alarm_threshold', '90'); // CPU 报警阈值 (Feature 3)

    // 加载所有全局设置到内存 (包括 fuse 和 trial)
    await loadGlobalSettingsFromDb();
    
    console.log(`SQLite database initialized at ${DB_PATH}`);
}

/**
 * [V7.0 NEW] 从 DB 加载所有全局设置到内存 (包括 fuse 和 trial)
 * [V11.0 FIX] 修复键名不一致的 BUG，确保内存中的 globalTrialSettings 键名是统一的。
 */
async function loadGlobalSettingsFromDb() {
    try {
        const settings = await db.all("SELECT key, value FROM global_settings");
        settings.forEach(setting => {
            // [V11.0 FIX] 统一处理键名
            let key = setting.key;
            let value = setting.value;

            if (key.startsWith('trial_')) {
                key = key.replace('trial_', ''); // 去掉前缀，例如 'trial_days' -> 'days'
            }

            if (key in globalTrialSettings) {
                // 试用功能相关
                if (['enabled', 'auto_approve'].includes(key)) {
                    globalTrialSettings[key] = (value === '1' || value === 'true');
                } else if (key === 'tg_alarm_threshold' || ['max_attempts', 'days', 'rate_kbps', 'max_connections'].includes(key)) {
                    globalTrialSettings[key] = parseInt(value) || 0;
                } else if (key === 'quota_gb') {
                    globalTrialSettings[key] = parseFloat(value) || 0.0;
                }
            } else if (key === 'fuse_threshold_kbps') {
                globalFuseLimitKbps = parseInt(value) || 0;
            }
        });
        console.log(`[DB] Global Trial Settings loaded: ${JSON.stringify(globalTrialSettings)}`);
    } catch(e) {
        console.error(`[DB] Failed to load global settings: ${e.message}`);
    }
}

/**
 * [V7.0 NEW] 更新 DB 中的单个全局设置
 * @param {string} key - 键名 (例如: 'days', 'trial_days', 'fuse_threshold_kbps')
 * @param {string|number} value - 值
 */
async function updateGlobalSetting(key, value) {
    // 如果传入的是统一键名 ('days', 'quota_gb')，则自动添加 'trial_' 前缀，以便写入 DB
    const dbKey = key.startsWith('trial_') || key === 'fuse_threshold_kbps' || key === 'tg_alarm_threshold' ? key : `trial_${key}`;
    
    // 确保键值存在于 globalTrialSettings 中 (处理简写)
    const normalizedKey = dbKey.startsWith('trial_') ? dbKey.replace('trial_', '') : dbKey;
    if (!(normalizedKey in globalTrialSettings) && dbKey !== 'fuse_threshold_kbps' && dbKey !== 'tg_alarm_threshold') {
         // 不存在则跳过，防止注入
         return false; 
    }
    
    try {
        await db.run(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES (?, ?)",
            dbKey,
            String(value)
        );
        await loadGlobalSettingsFromDb(); // 重新加载以更新内存缓存
        return true;
    } catch (e) {
        console.error(`[DB] Failed to update global setting ${dbKey}: ${e.message}`);
        return false;
    }
}

/**
 * [V9.9 NEW] 随机生成用户名和密码
 */
function generateTrialCredentials() {
    const username = 'trial' + crypto.randomBytes(4).toString('hex');
    const password = crypto.randomBytes(8).toString('base64').replace(/\W/g, '').substring(0, 8);
    return { username, password };
}


/**
 * [V7.0 NEW] 获取用户的试用状态 (检查是否已申请/已批准/达到次数限制)
 * @param {string} tg_id - Telegram ID
 * @returns {object} { enabled, auto_approve, max_attempts, attempts, current }
 */
async function getTrialStatus(tg_id) {
    const tgIdString = tg_id.toString();
    try {
        // 1. 检查当前处于 pending 或 approved 状态的请求
        const currentRequest = await db.get('SELECT * FROM trial_requests WHERE tg_id = ? AND status IN ("pending", "approved") ORDER BY request_time DESC LIMIT 1', tgIdString);
        
        // 2. 检查历史申请次数 (所有状态都算一次尝试，防止滥用)
        const historyCountResult = await db.get('SELECT COUNT(*) as count FROM trial_requests WHERE tg_id = ?', tgIdString);

        return {
            enabled: globalTrialSettings.enabled,
            auto_approve: globalTrialSettings.auto_approve,
            max_attempts: globalTrialSettings.max_attempts,
            attempts: historyCountResult.count,
            current: currentRequest // pending 或 approved 的记录
        };
    } catch (e) {
        console.error(`[DB] Failed to get trial status for ${tg_id}: ${e.message}`);
        return { enabled: false, auto_approve: false, max_attempts: 1, attempts: 99, current: null }; // Fail safe
    }
}

/**
 * [V7.0 NEW - 核心] 创建试用用户 (用于手动批准和自动批准)
 * @param {string} tg_id - Telegram ID
 * @param {string} tg_username - Telegram 用户名
 * @param {number} requestId - trial_requests 表中的记录 ID
 */
async function createTrialUser(tg_id, tg_username, requestId) {
    const creds = generateTrialCredentials();
    
    // 从内存中获取试用参数 (V11.0 FIX: 使用统一的键名)
    const days = globalTrialSettings.days;
    const quotaGb = globalTrialSettings.quota_gb;
    const rateKbps = globalTrialSettings.rate_kbps;
    const maxConnections = globalTrialSettings.max_connections;
    
    try {
        const existingUser = await getUserByUsername(creds.username);
        if (existingUser) { return createTrialUser(tg_id, tg_username, requestId); } // 冲突重试

        const shell = "/sbin/nologin";
        const { success: userAddSuccess, output: userAddOutput } = await safeRunCommand(['useradd', '-m', '-s', shell, creds.username]);
        if (!userAddSuccess && !userAddOutput.includes("already exists")) {
            throw new Error(`系统用户创建失败: ${userAddOutput}`);
        }

        const chpasswdInput = `${creds.username}:${creds.password}`;
        const { success: chpassSuccess } = await safeRunCommand(['chpasswd'], chpasswdInput);
        if (!chpassSuccess) throw new Error(`密码设置失败`);

        await safeRunCommand(['usermod', '-U', creds.username]);

        const passwordHash = await bcrypt.hash(creds.password, 12);
        const expiryDate = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
        
        const newUser = {
            username: creds.username, password_hash: passwordHash,
            created_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
            status: 'active',
            expiration_date: expiryDate, 
            quota_gb: quotaGb, usage_gb: 0.0, 
            rate_kbps: rateKbps, 
            max_connections: maxConnections,
            require_auth_header: 1, 
            realtime_speed_up: 0.0, realtime_speed_down: 0.0,
            active_connections: 0, 
            status_text: '试用 (Trial)',
            allow_shell: 0
        };
        
        await db.run(`INSERT INTO users (
                        username, password_hash, created_at, status, expiration_date, 
                        quota_gb, usage_gb, rate_kbps, max_connections, 
                        require_auth_header, realtime_speed_up, realtime_speed_down, active_connections, status_text,
                        allow_shell
                      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                      Object.values(newUser));
        
        // 更新请求状态 (使用 record ID)
        await updateTrialRequestStatus(requestId, 'approved', creds.username);
        
        await logAction("TRIAL_APPROVE", "TG_BOT", `Trial user ${creds.username} created and approved for TG ID ${tg_id}`);
        broadcastToFrontends({ type: 'users_changed' });
        
        return { ...creds, expiryDate, quotaGb, rateKbps, maxConnections };

    } catch (e) {
         // 失败时，尝试清理系统用户 (使用生成的用户名)
         await safeRunCommand(['userdel', '-r', creds.username]).catch(() => {});
         throw new Error(`创建失败: ${e.message}`);
    }
}

/**
 * [V9.9 NEW] 获取所有待处理试用申请
 * @returns {Array<object>} - 返回待批准的申请记录
 */
async function getPendingTrialRequests() {
    // [V7.0 FIX] 确保查询的是 'pending' 状态的记录，并按记录 ID 排序
    return db.all('SELECT * FROM trial_requests WHERE status = "pending" ORDER BY id ASC');
}

/**
 * [V9.9 NEW] 添加试用申请
 * @param {string} tg_id - Telegram ID
 * @param {string} tg_username - Telegram 用户名
 * @returns {number} - 返回新创建的记录 ID
 */
async function addTrialRequest(tg_id, tg_username) {
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    try {
         const result = await db.run(`INSERT INTO trial_requests (tg_id, tg_username, status, request_time) 
                     VALUES (?, ?, 'pending', ?)`, 
                     tg_id.toString(), tg_username, timestamp);
        // [V7.0 FIX] 返回新插入的记录 ID
        return result.lastID;
    } catch (e) {
        if (e.message.includes('UNIQUE constraint failed')) {
            // 如果是 tg_id+status 的唯一性约束失败，说明已经有 pending 或 approved 的记录
            throw new Error("您已有一条正在处理中的申请。");
        }
        throw e;
    }
}

/**
 * [V9.9 NEW] 更新试用申请状态
 * @param {number} requestId - trial_requests 表中的记录 ID
 * @param {string} status - 新状态
 * @param {string} [username=null] - 关联的用户名
 */
async function updateTrialRequestStatus(requestId, status, username = null) {
    // 确保更新的是 'id' 字段，而不是 tg_id
    if (username) {
        return db.run('UPDATE trial_requests SET status = ?, username = ? WHERE id = ?', status, username, requestId);
    }
    return db.run('UPDATE trial_requests SET status = ? WHERE id = ?', status, requestId);
}

// =======================================================
// [V11.0 NEW] Feature 1: 卡密兑换系统 (Voucher/CDK) 核心逻辑
// =======================================================

/**
 * [V11.0 NEW] 创建新的卡密
 * @param {number} days - 续期天数
 * @param {number} quotaGb - 增加的流量
 * @returns {string} - 生成的卡密代码
 */
async function createVoucher(days, quotaGb) {
    const code = crypto.randomBytes(6).toString('hex').toUpperCase(); // 12位十六进制
    const created_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
    
    try {
        await db.run(
            'INSERT INTO vouchers (code, days, quota_gb, is_used, created_at) VALUES (?, ?, ?, 0, ?)',
            code, days, quotaGb, created_at
        );
        await logAction("VOUCHER_CREATE", ROOT_USERNAME, `Created voucher ${code}: +${days} days, +${quotaGb} GB.`);
        return code;
    } catch (e) {
        if (e.message.includes('UNIQUE constraint failed')) {
            return createVoucher(days, quotaGb); // 递归重试 (极低概率)
        }
        throw new Error(`创建卡密失败: ${e.message}`);
    }
}

/**
 * [V11.0 NEW] 兑换卡密
 * @param {string} code - 卡密
 * @param {string} username - WSS 用户名
 * @param {string} tgId - Telegram ID
 */
async function redeemVoucher(code, username, tgId) {
    const voucher = await db.get('SELECT * FROM vouchers WHERE code = ?', code.toUpperCase());
    
    if (!voucher) {
        throw new Error("卡密不存在。");
    }
    if (voucher.is_used === 1) {
        throw new Error(`卡密已被使用 (使用者: ${voucher.used_by})。`);
    }

    const user = await getUserByUsername(username);
    if (!user) {
        throw new Error(`用户 ${username} 不存在。`);
    }

    const redeem_time = new Date().toISOString().slice(0, 19).replace('T', ' ');
    const daysToAdd = voucher.days || 0;
    const quotaToAdd = voucher.quota_gb || 0.0;
    
    let newExpiryDate = user.expiration_date ? new Date(user.expiration_date) : new Date();
    
    // 如果当前到期日小于今天，则从今天开始计算
    if (newExpiryDate.getTime() < Date.now()) {
        newExpiryDate = new Date();
    }
    
    // 叠加天数
    if (daysToAdd > 0) {
        newExpiryDate.setTime(newExpiryDate.getTime() + daysToAdd * 24 * 60 * 60 * 1000);
    }
    
    // 叠加流量 (直接加到配额)
    const newQuota = user.quota_gb + quotaToAdd;
    const newExpiryString = newExpiryDate.toISOString().split('T')[0];

    try {
        await db.run('BEGIN TRANSACTION');
        
        // 1. 更新用户表
        await db.run(
            'UPDATE users SET expiration_date = ?, quota_gb = ?, status = ? WHERE username = ?',
            newExpiryString, newQuota, 'active', username
        );

        // 2. 标记卡密已使用
        await db.run(
            'UPDATE vouchers SET is_used = 1, used_by = ?, used_at = ? WHERE code = ?',
            username, redeem_time, code.toUpperCase()
        );
        
        await db.run('COMMIT');
        
        // 3. 异步触发状态更新
        broadcastToFrontends({ type: 'users_changed' });
        await logAction("VOUCHER_REDEEM", username, `Redeemed voucher ${code} (+${daysToAdd} days, +${quotaToAdd} GB) via TG ID ${tgId}.`);

        return {
            daysAdded: daysToAdd,
            quotaAdded: quotaToAdd,
            newExpiry: newExpiryString,
            oldQuota: user.quota_gb,
            newQuota: newQuota
        };

    } catch (e) {
        await db.run('ROLLBACK').catch(() => {});
        throw new Error(`兑换失败: ${e.message}`);
    }
}

// =======================================================
// [V11.0 NEW] Feature 4: 账号绑定 (TG Bindings) 核心逻辑
// =======================================================

/**
 * [V11.0 NEW] 获取 TG ID 对应的绑定信息
 * @param {string} tgId - Telegram ID
 */
async function getTgBinding(tgId) {
    return db.get('SELECT * FROM tg_bindings WHERE tg_id = ?', tgId.toString());
}

/**
 * [V11.0 NEW] 获取 WSS 用户名对应的绑定信息
 * @param {string} username - WSS 用户名
 */
async function getTgBindingByUsername(username) {
    return db.get('SELECT * FROM tg_bindings WHERE username = ?', username);
}

/**
 * [V11.0 NEW] 绑定 WSS 账号到 Telegram ID
 */
async function bindTgUser(tgId, username, password) {
    const user = await getUserByUsername(username);
    if (!user) {
        throw new Error("WSS 账号不存在。");
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
        throw new Error("用户名或密码错误。");
    }

    const existingBinding = await getTgBinding(tgId);
    if (existingBinding) {
        throw new Error(`您的 Telegram ID 已绑定到账号 ${existingBinding.username}。请先解绑。`);
    }
    
    const isUserBound = await getTgBindingByUsername(username);
    if (isUserBound) {
        throw new Error(`WSS 账号 ${username} 已被其他 Telegram ID 绑定。`);
    }
    
    const passwordHash = user.password_hash; // 直接使用 user table 的哈希值

    const bind_time = new Date().toISOString().slice(0, 19).replace('T', ' ');
    await db.run(
        'INSERT INTO tg_bindings (tg_id, username, password_hash, bind_time) VALUES (?, ?, ?, ?)',
        tgId.toString(), username, passwordHash, bind_time
    );

    await logAction("TG_BIND", username, `WSS user ${username} bound to TG ID ${tgId}.`);
}

/**
 * [V11.0 NEW] 解绑 WSS 账号
 */
async function unbindTgUser(tgId) {
    const result = await db.run('DELETE FROM tg_bindings WHERE tg_id = ?', tgId.toString());
    if (result.changes === 0) {
        throw new Error("您的 Telegram ID 未绑定任何 WSS 账号。");
    }
    await logAction("TG_UNBIND", tgId, `TG ID ${tgId} unbound successfully.`);
}

/**
 * [V11.0 NEW] 获取所有已绑定的 TG ID 列表 (用于广播)
 */
async function getAllTgBindings() {
    return db.all('SELECT tg_id FROM tg_bindings');
}

/**
 * [V11.0 NEW] Feature 3: 系统健康监控和报警
 * @param {Function} alarmCallback - 报警回调函数 (bot.sendMessage)
 */
async function checkSystemHealthAndAlarm(alarmCallback) {
    const data = await getSystemStatusData();
    const cpuUsage = data.cpu_usage;
    const threshold = globalTrialSettings.tg_alarm_threshold;

    lastCpuUsage = cpuUsage; // 更新上次 CPU 使用率

    if (cpuUsage >= threshold) {
        if (!isCpuAlarmTriggered) {
            const message = `🚨 **系统 CPU 报警** 🚨\n\n当前 CPU 负载: **${cpuUsage.toFixed(1)}%**\n报警阈值: ${threshold}%\n\n服务器可能处于高负载状态，请立即检查！`;
            alarmCallback(message);
            isCpuAlarmTriggered = true;
            await logAction("SYSTEM_ALARM", "SYSTEM", `CPU alarm triggered: ${cpuUsage.toFixed(1)}%`);
        }
    } else if (isCpuAlarmTriggered && cpuUsage < threshold * 0.8) {
        // 只有当负载低于阈值一定比例时才解除警报 (防止频繁波动)
        const message = `✅ **系统 CPU 负载解除** ✅\n\n当前 CPU 负载: ${cpuUsage.toFixed(1)}%\n\n系统负载已恢复正常。`;
        alarmCallback(message);
        isCpuAlarmTriggered = false;
        await logAction("SYSTEM_ALARM_CLEAR", "SYSTEM", `CPU alarm cleared: ${cpuUsage.toFixed(1)}%`);
    }
    
    // 检查核心服务状态
    for (const [id, service] of Object.entries(data.services)) {
        // 忽略 Panel 自身的状态，因为它可能在重启
        if (id !== 'wss_panel' && service.status !== 'running') {
            const message = `⚠️ **服务故障警告** ⚠️\n\n服务 **${service.name}** (${id}) 处于 **失败** 状态。\n请立即检查日志并重启服务！`;
            alarmCallback(message);
            await logAction("SERVICE_FAIL_ALARM", "SYSTEM", `Service ${id} is down.`);
        }
    }
}


// --- Authentication Middleware ---

function loadSecretKey() {
    try {
        return fsSync.readFileSync(SECRET_KEY_PATH, 'utf8').trim();
    } catch (e) {
        const key = require('crypto').randomBytes(32).toString('hex');
        fsSync.writeFileSync(SECRET_KEY_PATH, key, 'utf8');
        return key;
    }
}

const sessionMiddleware = session({
    secret: loadSecretKey(),
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false, httpOnly: true,
        maxAge: 3600000 * 24, sameSite: 'lax'
    }
});
app.use(sessionMiddleware);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

function loginRequired(req, res, next) {
    if (req.session.loggedIn) {
        next();
    } else {
        if (req.path.startsWith('/api/')) {
            return res.status(401).json({ success: false, message: "Authentication failed or session expired" });
        }
        return res.redirect('/login.html');
    }
}

// --- Business Logic / System Sync ---

function broadcastToFrontends(message) {
    if (!wssUiPool || wssUiPool.size === 0) {
        return; 
    }
    const payload = JSON.stringify(message);
    wssUiPool.forEach((client) => {
        if (client.readyState === 1) { 
            client.send(payload, (err) => {
                if (err) {
                    console.error(`[IPC_UI] 发送消息到前端失败: ${err.message}`);
                }
            });
        }
    });
}

function broadcastToProxies(message) {
    if (!wssIpc || wssIpc.clients.size === 0) {
        console.warn("[IPC_WSS] 无法广播: 没有连接的数据平面 (Proxy) 实例。");
        return;
    }
    const payload = JSON.stringify(message);
    console.log(`[IPC_WSS] 正在广播 (-> ${wssIpc.clients.size} 个代理): ${payload}`);
    wssIpc.clients.forEach((client) => {
        if (client.readyState === 1) { 
            client.send(payload, (err) => {
                if (err) {
                    console.error(`[IPC_WSS] 发送消息到代理失败: ${err.message}`);
                }
            });
        }
    });
}


async function kickUserFromProxy(username) {
    broadcastToProxies({
        action: 'kick',
        username: username
    });
    return true; 
}

/**
 * [AXIOM V5.5 FIX A2/B2] 核心优化: 批量写入流量增量到 DB
 * @param {object} workerStatsMap - Key: WorkerId, Value: {stats: {username: {traffic_delta_up, traffic_delta_down}}}
 */
async function persistTrafficDelta(workerStatsMap) {
    const today = new Date().toISOString().split('T')[0];
    let userDeltaMap = new Map();
    
    // 1. 聚合所有 Worker 的流量增量
    for (const [workerId, workerData] of workerStatsCache.entries()) {
        const stats = workerData.stats || {};
        // [V6.0 UPDATE] 遍历新的紧凑 stats 结构
        for (const username in stats) {
            const currentStats = stats[username];
            const deltaBytes = (currentStats.traffic_delta_up || 0) + (currentStats.traffic_delta_down || 0);
            if (deltaBytes > 0) {
                const deltaGb = (deltaBytes / GIGA_BYTE);
                userDeltaMap.set(username, (userDeltaMap.get(username) || 0) + deltaGb);
            }
        }
    }

    if (userDeltaMap.size === 0) return;

    // 2. 批量写入 DB
    try {
        await db.run('BEGIN TRANSACTION');
        
        // --- A. 更新主表总流量 ---
        const userUpdates = [];
        const historyUpdates = [];
        
        for (const [username, deltaGb] of userDeltaMap.entries()) {
            // 1. 更新主表总流量
            userUpdates.push(db.run('UPDATE users SET usage_gb = usage_gb + ? WHERE username = ?',
                [deltaGb, username]));
            
            // 2. 准备历史表更新数据
            historyUpdates.push(db.run('INSERT OR IGNORE INTO traffic_history (username, date, usage_gb) VALUES (?, ?, 0.0)', [username, today]));
            historyUpdates.push(db.run('UPDATE traffic_history SET usage_gb = usage_gb + ? WHERE username = ? AND date = ?', [deltaGb, username, today]));
        }
        
        await Promise.all(userUpdates);
        await Promise.all(historyUpdates);
        
        await db.run('COMMIT');
    } catch (e) {
        await db.run('ROLLBACK').catch(()=>{});
        console.error(`[TRAFFIC_ASYNC] 流量增量DB批量写入失败: ${e.message}`);
    }
}

/**
 * [V6.0 NEW] 僵尸清理：检查并清理超过 TTL 的 Worker 统计数据
 */
function clearStaleWorkerStats() {
    if (!isRealtimePushing) return; // 只有在前端活跃时才进行清理
    
    let statsChanged = false;
    const now = Date.now();
    
    for (const [workerId, workerData] of workerStatsCache.entries()) {
        const usersStats = workerData.stats || {};
        
        for (const username in usersStats) {
            const userStats = usersStats[username];
            const lastUpdate = userStats.timestamp || 0;
            
            // 检查是否超过 TTL 且当前连接数不为零
            if (userStats.conn > 0 && (now - lastUpdate) > STALE_TIMEOUT_MS) {
                
                // [BUGFIX] 发现僵尸，将其连接数和速度强制归零
                console.warn(`[TTL_FENCE] Worker ${workerId}, User ${username} stats stale (${((now - lastUpdate)/1000).toFixed(1)}s). Forcing status to zero.`);
                
                userStats.conn = 0;
                userStats.up_speed = 0.0;
                userStats.down_speed = 0.0;
                userStats.timestamp = now; // 更新时间戳，防止在下次检查时再次触发警告
                
                statsChanged = true;
            }
        }
        
        // [V6.0 FIX] 移除不再包含任何用户的 Worker 数据
        const hasActiveUser = Object.values(usersStats).some(u => u.conn > 0);
        if (!hasActiveUser) {
             // 移除整个 Worker 的数据，因为其没有任何活跃连接
             workerStatsCache.delete(workerId);
             statsChanged = true;
        }
    }
    
    // 如果发生了僵尸清理，立即推送更新
    if (statsChanged) {
        pushLiveUpdates();
    }
}


/**
 * [AXIOM V5.5 FIX A2/B2] 聚合所有 Worker 的统计数据
 * [V6.0 UPDATE] 适配新的缓存结构
 */
function aggregateAllWorkerStats() {
    // 聚合结构: Key: username, Value: { speed_kbps: { upload, download }, connections, timestamp }
    const aggregatedStats = {};
    const aggregatedLiveIps = {};
    let totalActiveConnections = 0;

    for (const [workerId, workerData] of workerStatsCache.entries()) {
        // [V6.0 UPDATE] workerData.stats 现在是 { username: { conn, up_speed, down_speed, ... } }
        for (const username in workerData.stats) {
            const current = workerData.stats[username];
            
            // 排除连接数归零且速度为零的僵尸数据 (这些数据已由 TTL 清理，但防止万一)
            if (current.conn === 0 && current.up_speed < 0.1 && current.down_speed < 0.1) continue; 
            
            if (!aggregatedStats[username]) {
                aggregatedStats[username] = {
                    speed_kbps: { upload: 0, download: 0 },
                    connections: 0,
                    // [V6.0 NEW] 记录最近一次的报告时间
                    lastReportTime: current.timestamp || 0 
                };
            }
            
            const existing = aggregatedStats[username];
            
            // 1. 聚合连接数和速度
            existing.connections += current.conn;
            existing.speed_kbps.upload += current.up_speed;
            existing.speed_kbps.download += current.down_speed;
            
            // 2. 更新最新报告时间
            existing.lastReportTime = Math.max(existing.lastReportTime, current.timestamp || 0);

            totalActiveConnections += current.conn;
        }
        
        // [V9.1 OPT] live_ips 字段已被移除，聚合时跳过
        // Object.assign(aggregatedLiveIps, workerData.live_ips); 
    }
    
    return {
        users: aggregatedStats,
        live_ips: aggregatedLiveIps, // 保持结构兼容性，但此处将为空或不使用
        system: {
            active_connections_total: totalActiveConnections
        }
    };
}

/**
 * [AXIOM V5.0] 核心功能: 1秒实时流量/连接推送
 */
function pushLiveUpdates() {
    if (!isRealtimePushing) return;
    
    const aggregatedData = aggregateAllWorkerStats();
    
    // 1. 检查用户流量/连接数据是否有变化
    const usersToPush = {};
    let usersChanged = false;

    for (const username in aggregatedData.users) {
        const current = aggregatedData.users[username];
        const last = lastAggregatedStats.users[username];

        // 检查连接数、上传速度或下载速度是否有显著变化
        const hasChange = !last ||
            current.connections !== (last.connections || 0) ||
            Math.abs(current.speed_kbps.upload - (last.speed_kbps.upload || 0)) > 0.1 ||
            Math.abs(current.speed_kbps.download - (last.speed_kbps.download || 0)) > 0.1;

        if (hasChange) {
            usersToPush[username] = current;
            usersChanged = true;
        }
        // [AXIOM V5.5 FIX] 如果用户没有连接，且速度为0，从推送中移除，让前端使用 DB 数据
        if (current.connections === 0 && current.speed_kbps.upload < 0.1 && current.speed_kbps.download < 0.1) {
             delete usersToPush[username];
             // [V6.0 FIX] 如果上次推送是活跃的，但现在归零了，需要显式更新缓存
             if (last && last.connections > 0) {
                 usersChanged = true; // 强制更新，以确保前端显示 0
             }
        }
    }
    
    // 2. 检查全局活跃 IP 数量是否有变化 (基于连接总数，因为 live_ips 已经被移除)
    // live_ips 聚合已移除，此处的 liveIpCount 统计将依赖总连接数来决定是否更新系统状态
    const currentLiveIpCount = aggregatedData.system.active_connections_total; 
    const lastLiveIpCount = lastAggregatedStats.system ? lastAggregatedStats.system.active_connections_total : -1;
    
    let systemChanged = false;
    if (currentLiveIpCount !== lastLiveIpCount) {
        systemChanged = true;
    }
    
    // 3. 推送有变化的数据
    if (usersChanged || systemChanged || Object.keys(usersToPush).length > 0) {
         broadcastToFrontends({
            type: 'live_update',
            payload: { 
                users: usersToPush,
                system: { 
                    active_connections_total: aggregatedData.system.active_connections_total 
                } 
            }
        });
        
        // 4. 更新上次推送缓存 (仅更新被推送的数据)
        for (const username in usersToPush) {
            lastAggregatedStats.users[username] = aggregatedData.users[username];
        }
        // 更新全局连接数缓存
        lastAggregatedStats.system = aggregatedData.system; 
    }
}

/**
 * [AXIOM V5.0] 核心功能: 3秒系统状态推送
 */
async function pushSystemUpdates() {
    if (!isRealtimePushing) return;
    
    const systemStatusData = await getSystemStatusData();
    let isChanged = false;

    // 检查 CPU/内存/磁盘是否有变化 (使用 JSON.stringify 快速比较，但忽略 user_stats)
    const currentStatus = { ...systemStatusData };
    delete currentStatus.user_stats;
    
    const lastJSON = JSON.stringify(lastSystemStatus);
    const currentJSON = JSON.stringify(currentStatus);

    if (lastJSON !== currentJSON) {
        isChanged = true;
    }

    if (isChanged) {
        broadcastToFrontends({
            type: 'system_update',
            payload: systemStatusData
        });
        
        // 更新上次推送缓存
        lastSystemStatus = currentStatus;
    }
}


/**
 * [AXIOM V5.0] 启动/停止实时推送机制 (由 UI 连接/断开触发)
 */
function toggleRealtimePush(shouldStart) {
    if (shouldStart && !isRealtimePushing) {
        // 启动实时推送
        console.log("[PUSH] 启动 1秒/3秒 实时推送定时器...");
        isRealtimePushing = true;
        
        // 1. 启动 1 秒流量/连接推送
        if (liveUpdateInterval) clearInterval(liveUpdateInterval);
        liveUpdateInterval = setInterval(pushLiveUpdates, 1000);
        
        // 2. 启动 3 秒系统状态推送
        if (systemUpdateInterval) clearInterval(systemUpdateInterval);
        systemUpdateInterval = setInterval(pushSystemUpdates, 3000);
        
        // 3. [V6.0 NEW] 启动 3 秒僵尸清理
        if (staleCheckInterval) clearInterval(staleCheckInterval);
        staleCheckInterval = setInterval(clearStaleWorkerStats, STALE_CHECK_INTERVAL);
        
    } else if (!shouldStart && isRealtimePushing) {
        // 停止实时推送
        console.log("[PUSH] 停止 1秒/3秒 实时推送定时器 (管理员已离线)。");
        isRealtimePushing = false;
        
        if (liveUpdateInterval) clearInterval(liveUpdateInterval);
        if (systemUpdateInterval) clearInterval(systemUpdateInterval);
        if (staleCheckInterval) clearInterval(staleCheckInterval); 
        
        liveUpdateInterval = null;
        systemUpdateInterval = null;
        staleCheckInterval = null;
        
        // 重置缓存以备下次连接时进行全量推送
        lastAggregatedStats = { users: {}, live_ips: {} };
        lastSystemStatus = {};
    }
}


/**
 * [AXIOM V5.5 FIX A3] 异步熔断检查和执行
 */
async function checkAndApplyFuse(username, userSpeedKbps) {
    if (globalFuseLimitKbps <= 0) return; 

    const totalSpeed = (userSpeedKbps.upload || 0) + (userSpeedKbps.download || 0);

    if (totalSpeed >= globalFuseLimitKbps) {
        const user = await getUserByUsername(username);
        
        // 仅对当前处于 'active' 状态的用户执行熔断
        if (user && user.status === 'active') {
            console.warn(`[FUSE] 用户 ${username} 已触发全局熔断器! 速率: ${totalSpeed.toFixed(0)} KB/s. 为所有代理广播更新状态...`);
            
            // 数据库更新
            await db.run(`UPDATE users SET status = 'fused', status_text = '熔断 (Fused)' WHERE username = ?`, username);
            
            // 系统账户锁定和踢出
            await safeRunCommand(['usermod', '-L', username]);
            await kickUserFromProxy(username); 
            await safeRunCommand(['pkill', '-9', '-u', username]); 
            
            await logAction("USER_FUSED", "SYSTEM", `User ${username} exceeded speed limit (${totalSpeed.toFixed(0)} KB/s). Fused and Kicked.`);
            
            broadcastToFrontends({ type: 'users_changed' });
        }
    }
}


/**
 * [AXIOM V3.0] 60秒维护任务
 */
async function syncUserStatus() {
    const systemLockedUsers = await getSystemLockStatus();
    let allUsers = [];
    try {
        allUsers = await db.all('SELECT * FROM users');
    } catch (e) {
        console.error(`[SYNC] 无法从 DB 获取用户: ${e.message}`);
        return;
    }
    
    const usersToUpdate = []; 
    
    for (const user of allUsers) {
        const username = user.username;
        
        let isExpired = false, isOverQuota = false;
        
        if (user.expiration_date) {
            // [AXIOM V5.5 FIX A4] 增强日期解析的健壮性
            try { 
                const expiry = new Date(user.expiration_date);
                // 确保日期有效，并且小于当前时间
                if (!isNaN(expiry.getTime()) && expiry.getTime() < Date.now()) { 
                    isExpired = true; 
                }
            } catch (e) { 
                console.warn(`[SYNC] 日期解析失败 for ${username}: ${user.expiration_date}`);
            }
        }
        
        if (user.quota_gb > 0 && user.usage_gb >= user.quota_gb) { isOverQuota = true; }
        
        const currentDbStatus = user.status; 
        let newDbStatus = currentDbStatus;
        let statusChanged = false;
        
        if (isExpired) {
            if (currentDbStatus !== 'expired') { newDbStatus = 'expired'; statusChanged = true; }
        } else if (isOverQuota) {
            if (currentDbStatus !== 'exceeded') { newDbStatus = 'exceeded'; statusChanged = true; }
        } else if (currentDbStatus === 'paused' || currentDbStatus === 'fused') {
            newDbStatus = currentDbStatus; 
        } else {
            if (currentDbStatus !== 'active') { newDbStatus = 'active'; statusChanged = true; }
        }
        
        user.status = newDbStatus;

        const systemLocked = systemLockedUsers.has(username);
        const shouldBeLocked_SYS = (user.status !== 'active');
        
        if (shouldBeLocked_SYS && !systemLocked) {
            await safeRunCommand(['usermod', '-L', username]);
            statusChanged = true; 
        } else if (!shouldBeLocked_SYS && systemLocked) {
            await safeRunCommand(['usermod', '-U', username]);
            statusChanged = true; 
        }
        
        let newStatusText = user.status_text;
        if (user.status === 'active') { newStatusText = '启用 (Active)'; } 
        else if (user.status === 'paused') { newStatusText = '暂停 (Manual)'; } 
        else if (user.status === 'expired') { newStatusText = '已到期 (Expired)'; } 
        else if (user.status === 'exceeded') { newStatusText = '超额 (Quota)'; } 
        else if (user.status === 'fused') { newStatusText = '熔断 (Fused)'; } 
        else { newStatusText = '未知'; }

        if (statusChanged || user.status_text !== newStatusText) {
             user.status_text = newStatusText;
             usersToUpdate.push(user);
        }
    }
    
    if (usersToUpdate.length > 0) {
        try {
            await db.run('BEGIN TRANSACTION');
            for (const u of usersToUpdate) {
                await db.run(`UPDATE users SET 
                                status = ?, status_text = ?
                              WHERE username = ?`,
                    u.status, u.status_text, u.username);
            }
            await db.run('COMMIT');
            console.log(`[SYNC] 60秒维护任务完成。更新了 ${usersToUpdate.length} 个用户的状态。`);
            
            if (wssUiPool.size > 0) {
                broadcastToFrontends({ type: 'users_changed' });
            }
            
        } catch (e) {
            await db.run('ROLLBACK').catch(()=>{});
            console.error(`[SYNC] CRITICAL: 60秒维护DB更新失败: ${e.message}`);
        }
    }
}


async function manageIpIptables(ip, action, chainName = BLOCK_CHAIN) {
    if (action === 'check') {
        const result = await asyncExecFile('sudo', ['iptables', '-C', chainName, '-s', ip, '-j', 'DROP'], { timeout: 2000 }).catch(e => e);
        return { success: result.code === 0 };
    }
    let command;
    if (action === 'block') {
        await safeRunCommand(['iptables', '-D', chainName, '-s', ip, '-j', 'DROP']);
        command = ['iptables', '-I', chainName, '1', '-s', ip, '-j', 'DROP'];
    } else if (action === 'unblock') {
        command = ['iptables', '-D', chainName, '-s', ip, '-j', 'DROP'];
    } else {
        return { success: false, output: "Invalid action" };
    }
    const result = await safeRunCommand(command);
    if (result.success) {
        safeRunCommand(['iptables-save'], null, true)
            .then(({ output }) => fs.writeFile('/etc/iptables/rules.v4', output))
            .catch(e => console.error(`Warning: Failed to save iptables rules: ${e.message}`));
    }
    return result;
}

// --- API Routes (Admin Panel) ---

app.use(express.static(PANEL_DIR));

const loginLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, 
	max: 5, 
	message: '登录尝试次数过多，IP已被限制，请 15 分钟后再试',
    handler: (req, res, next, options) => {
        res.redirect(`/login.html?error=${encodeURIComponent(options.message)}`);
    },
	standardHeaders: true, 
	legacyHeaders: false, 
});

app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const rootHash = await loadRootHash(); 
    if (username === ROOT_USERNAME && password && rootHash) {
        try {
            const match = await bcrypt.compare(password, rootHash);
            if (match) {
                req.session.loggedIn = true;
                req.session.username = ROOT_USERNAME;
                await logAction("LOGIN_SUCCESS", ROOT_USERNAME, "Web UI Login");
                return res.redirect('/index.html');
            }
        } catch (e) { console.error(`Bcrypt comparison failed: ${e.message}`); }
    }
    await logAction("LOGIN_FAILED", username, "Wrong credentials or invalid username attempt");
    res.redirect('/login.html?error=' + encodeURIComponent('用户名或密码错误。'));
});

app.get('/logout', (req, res) => {
    logAction("LOGOUT_SUCCESS", req.session.username || ROOT_USERNAME, "Web UI Logout");
    req.session.destroy();
    res.redirect('/login.html');
});

// --- Internal API (For Proxy) ---
const internalApi = express.Router();
internalApi.use((req, res, next) => {
    const clientIp = req.ip;
    if (clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1') {
        next();
    } else {
        console.warn(`[AUTH] Denied external access attempt to /internal API from ${clientIp}`);
        res.status(403).json({ success: false, message: 'Forbidden' });
    }
});

internalApi.post('/auth', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Missing credentials' });
    }
    try {
        const user = await getUserByUsername(username);
        if (!user || !user.password_hash) {
            await logAction("PROXY_AUTH_FAIL", username, "User not found or no password hash in DB.");
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        const match = await bcrypt.compare(password, user.password_hash);
        if (match) {
            if (user.status !== 'active') {
                 await logAction("PROXY_AUTH_LOCKED", username, `User locked in DB (Status: ${user.status}).`);
                 return res.status(403).json({ success: false, message: 'User locked, paused, or disabled' });
            }
            await logAction("PROXY_AUTH_SUCCESS", username, "Proxy auth success.");
            res.json({
                success: true,
                limits: {
                    rate_kbps: user.rate_kbps || 0,
                    max_connections: user.max_connections || 0,
                },
                require_auth_header: user.require_auth_header === 0 ? 0 : 1
            });
        } else {
            await logAction("PROXY_AUTH_FAIL", username, "Invalid password (bcrypt mismatch).");
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (e) {
        await logAction("PROXY_AUTH_ERROR", username, `Internal auth error: ${e.message}`);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

internalApi.get('/auth/user-settings', async (req, res) => {
    const { username } = req.query;
    if (!username) {
        return res.status(400).json({ success: false, message: 'Missing username' });
    }
    try {
        const user = await getUserByUsername(username);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.json({
            success: true,
            require_auth_header: user.require_auth_header === 0 ? 0 : 1,
            // [V6.0 ADD] 增加 limits，以便 Lite Auth 能够更新 Worker 的本地限速器
            limits: {
                rate_kbps: user.rate_kbps || 0,
                max_connections: user.max_connections || 0,
            },
        });
    } catch (e) {
        console.error(`[PROXY_SETTINGS] Internal API error: ${e.message}`);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

/**
 * [AXIOM V5.5 FIX A1] 中央并发检查 API
 * Proxy Worker 在建立连接前调用此 API 来获取中央授权。
 */
internalApi.get('/auth/check-conn', async (req, res) => {
    const { username, worker_id } = req.query;
    if (!username || !worker_id) {
        return res.status(400).json({ success: false, message: 'Missing username or worker_id' });
    }
    
    try {
        const user = await getUserByUsername(username);
        if (!user || user.status !== 'active') {
            return res.json({ success: true, allowed: false, message: "User not active or not found." });
        }
        
        const maxConnections = user.max_connections || 0;
        if (maxConnections === 0) {
            return res.json({ success: true, allowed: true, message: "No limit set." });
        }
        
        const aggregatedData = aggregateAllWorkerStats();
        const globalConnections = aggregatedData.users[username]?.connections || 0;
        
        // 核心逻辑: 如果全局连接数小于最大限制，则允许连接。
        if (globalConnections < maxConnections) {
            return res.json({ success: true, allowed: true, message: `Allowed. Global connections: ${globalConnections}/${maxConnections}` });
        } else {
            return res.json({ success: true, allowed: false, message: `Denied. Global connections: ${globalConnections}/${maxConnections}` });
        }

    } catch (e) {
        console.error(`[AUTH_CONN_CHECK] Central concurrency check failed: ${e.message}`);
        return res.status(500).json({ success: false, message: 'Internal server error during concurrency check.' });
    }
});


app.use('/internal', internalApi);

// --- Public API (For Admin Panel UI) ---
const api = express.Router();

/**
 * [AXIOM V9.7 REFACTOR] 跨 Worker 获取实时连接元数据 (单用户或全局)
 * @param {string | null} username - 如果为 null，则获取所有用户的连接
 */
async function fetchLiveConnections(username = null) {
    if (!wssIpc || wssIpc.clients.size === 0) {
        return { success: false, connections: [], message: 'Proxy workers are disconnected.' };
    }

    const requestId = crypto.randomUUID();
    const workersToWait = wssIpc.clients.size;
    workerMetadataResponses.clear();
    
    // 1. 广播请求到所有 Worker
    // 新增 GET_ALL_METADATA action 以获取所有用户的连接
    const actionType = username ? 'GET_METADATA' : 'GET_ALL_METADATA'; 
    const requestMessage = JSON.stringify({
        action: actionType,
        username: username, // null for global
        requestId: requestId
    });
    
    wssIpc.clients.forEach(client => {
        if (client.readyState === 1) {
            client.send(requestMessage);
        }
    });

    // 2. 等待 Worker 响应 (设置超时 3000ms)
    return new Promise((resolve) => {
        const timer = setTimeout(() => {
            console.warn(`[METADATA:${actionType}] Timeout waiting for worker responses. Received ${workerMetadataResponses.size}/${workersToWait} responses.`);
            resolve(aggregateResponses());
        }, 3000);

        function checkResponses() {
            if (workerMetadataResponses.size >= workersToWait) {
                clearTimeout(timer);
                resolve(aggregateResponses());
            }
        }

        function aggregateResponses() {
            const allConnections = [];
            let successfulWorkers = 0;
            
            workerMetadataResponses.forEach(response => {
                if (response.connections && Array.isArray(response.connections)) {
                    allConnections.push(...response.connections);
                    successfulWorkers++;
                }
            });
            
            return {
                success: true,
                connections: allConnections,
                message: `Aggregated metadata from ${successfulWorkers}/${workersToWait} workers.`
            };
        }
        
        // 临时存储响应的函数 (被 IPC 消息处理器调用)
        fetchLiveConnections.onResponse = (response) => {
            if (response.requestId === requestId) {
                workerMetadataResponses.set(response.workerId, response);
                checkResponses();
            }
        };

        // 清理函数 (确保在 Promise 结束后移除临时回调)
        const originalResolve = resolve;
        resolve = (value) => {
            delete fetchLiveConnections.onResponse;
            originalResolve(value);
        };
    });
}


/**
 * [AXIOM V5.2] 新增 API：获取用户的实时连接元数据 (单用户)
 */
api.get('/users/connections', async (req, res) => {
    const { username } = req.query;
    if (!username) {
        return res.status(400).json({ success: false, message: 'Missing username.' });
    }
    
    try {
        const result = await fetchLiveConnections(username);
        if (result.success) {
            return res.json({ success: true, connections: result.connections, message: result.message });
        } else {
            return res.status(503).json({ success: false, message: result.message });
        }
    } catch (e) {
        console.error(`[API] Failed to get connection metadata for ${username}: ${e.message}`);
        return res.status(500).json({ success: false, message: 'Internal server error during metadata aggregation.' });
    }
});


/**
 * [AXIOM V5.0] 提取: 获取系统状态的核心逻辑
 * [AXIOM V11.0.1 UPDATE] 恢复 udpgw 状态监控
 */
async function getSystemStatusData() {
    let diskUsedPercent = 55.0; 
    try {
         const { stdout } = await promisify(exec)('df -P / | tail -1'); 
         const parts = stdout.trim().split(/\s+/);
         if (parts.length >= 5) { diskUsedPercent = parseFloat(parts[4].replace('%', '')); }
    } catch (e) { /* ignore */ }
    const mem = os.totalmem();
    const memFree = os.freemem();
    
    const serviceStatuses = {};
    for (const [id, name] of Object.entries(CORE_SERVICES)) {
        // [AXIOM V5.5 FIX A7] 使用 systemctl is-active 命令作为完整参数传递
        const { success } = await safeRunCommand(['systemctl', 'is-active', id]);
        const status = success ? 'running' : 'failed';
        serviceStatuses[id] = { name, status, label: status === 'running' ? "运行中" : "失败" };
    }
    
    // [AXIOM V11.0.1 UPDATE] 恢复 udpgw 端口
    const ports = [
        { name: 'WSS_HTTP', port: config.wss_http_port, protocol: 'TCP', status: 'LISTEN' },
        { name: 'WSS_TLS', port: config.wss_tls_port, protocol: 'TCP', status: 'LISTEN' },
        { name: 'STUNNEL', port: config.stunnel_port, protocol: 'TCP', status: 'LISTEN' },
        { name: 'NATIVE_UDPGW', port: config.udpgw_port, protocol: 'TCP', status: 'LISTEN' }, // [RESTORED]
        { name: 'UDP_CUSTOM', port: config.udp_custom_port, protocol: 'UDP', status: 'LISTEN' }, // [V5.7 NEW]
        { name: 'PANEL', port: config.panel_port, protocol: 'TCP', status: 'LISTEN' },
        { name: 'SSH_INTERNAL', port: config.internal_forward_port, protocol: 'TCP', status: 'LISTEN' }
    ];
    
    let liveIpCount = 0;
    try {
        const aggregatedData = aggregateAllWorkerStats();
        // liveIpCount 依赖于总连接数
        liveIpCount = aggregatedData.system.active_connections_total; 

    } catch (e) {
        console.warn(`[SYSTEM_STATUS] 无法从 workerStatsCache 聚合 IP: ${e.message}`);
    }

    const users = await db.all('SELECT * FROM users');
    let totalTraffic = 0, pausedCount = 0, expiredCount = 0, exceededCount = 0, fusedCount = 0;
    for (const user of users) {
        totalTraffic += user.usage_gb || 0;
        if (user.status === 'paused') pausedCount++;
        else if (user.status === 'expired') expiredCount++;
        else if (user.status === 'exceeded') exceededCount++;
        else if (user.status === 'fused') fusedCount++;
    }
    
    const cpuLoadAvg = (os.loadavg()[0] / os.cpus().length) * 100;

    return {
        cpu_usage: cpuLoadAvg,
        memory_used_gb: (mem - memFree) / GIGA_BYTE,
        memory_total_gb: mem / GIGA_BYTE,
        disk_used_percent: diskUsedPercent,
        services: serviceStatuses,
        ports: ports,
        user_stats: {
            total: users.length, active: liveIpCount, paused: pausedCount,
            expired: expiredCount, exceeded: exceededCount,
            fused: fusedCount, total_traffic_gb: totalTraffic
        }
    };
}


api.get('/system/status', async (req, res) => {
    try {
        const data = await getSystemStatusData();
        res.json({ success: true, ...data });
    } catch (e) {
        await logAction("SYSTEM_STATUS_ERROR", req.session.username, `Status check failed: ${e.message}`);
        res.status(500).json({ success: false, message: `System status check failed: ${e.message}` });
    }
});


api.post('/system/control', async (req, res) => {
    const { service, action } = req.body;
    // [AXIOM V11.0.1 FIX] 确保 udpgw 在可控服务范围内
    if (!CORE_SERVICES[service] || action !== 'restart') {
        return res.status(400).json({ success: false, message: "无效的服务或操作" });
    }
    const { success, output } = await safeRunCommand(['systemctl', action, service]);
    if (success) {
        await logAction("SERVICE_CONTROL_SUCCESS", req.session.username, `Successfully executed ${action} on ${service}`);
        res.json({ success: true, message: `服务 ${CORE_SERVICES[service]} 已成功执行 ${action} 操作。` });
    } else {
        await logAction("SERVICE_CONTROL_FAIL", req.session.username, `Failed to ${action} ${service}: ${output}`);
        res.status(500).json({ success: false, message: `服务 ${CORE_SERVICES[service]} 操作失败: ${output}` });
    }
});

api.post('/system/logs', async (req, res) => {
    const serviceName = req.body.service;
    if (!CORE_SERVICES[serviceName]) { return res.status(400).json({ success: false, message: "无效的服务名称。" }); }
    try {
        const { success, output } = await safeRunCommand(['journalctl', '-u', serviceName, '-n', '50', '--no-pager', '--utc']);
        res.json({ success: true, logs: success ? output : `错误: 无法获取 ${serviceName} 日志. ${output}` });
    } catch (e) {
        res.status(500).json({ success: false, message: `日志获取异常: ${e.message}` });
    }
});

api.get('/system/audit_logs', async (req, res) => {
    try {
        const logContent = await fs.readFile(AUDIT_LOG_PATH, 'utf8');
        const logs = logContent.trim().split('\n').filter(line => line.trim().length > 0).slice(-20);
        res.json({ success: true, logs });
    } catch (e) {
        res.json({ success: true, logs: ["读取日志失败或日志文件为空。"] });
    }
});

api.get('/system/active_ips', async (req, res) => {
    try {
        // [V9.7 FIX] 使用 IPC 机制实时聚合所有 Worker 的连接 IP 列表
        const result = await fetchLiveConnections(null); // <-- Fetch all connections

        if (!result.success) {
            return res.status(503).json({ success: false, message: result.message });
        }
        
        // 1. 从聚合的连接列表中提取 IP 和用户名
        const ipMap = new Map(); // key: ip, value: username
        // connections 数组中的每个元素现在是 { id, ip, start, workerId, username }
        result.connections.forEach(conn => {
            // 使用 Map 确保 IP 唯一，并记录其关联的用户名
            ipMap.set(conn.ip, conn.username || 'N/A');
        });
        
        // 2. 检查每个 IP 的封禁状态
        const ipList = await Promise.all(
            Array.from(ipMap.keys()).map(async ip => {
                const isBanned = (await manageIpIptables(ip, 'check')).success;
                // [V9.7 FIX] 返回 IP 对应的 username
                return { ip: ip, is_banned: isBanned, username: ipMap.get(ip) }; 
            })
        );
        
        // 由于前端 UI 的 live-ips 视图需要这些数据，我们直接返回
        res.json({ success: true, active_ips: ipList });
        
    } catch (e) {
        console.error(`[API] Failed to get active IPs: ${e.message}`);
        res.status(500).json({ success: false, message: e.message });
    }
});

api.get('/users/list', async (req, res) => {
    try {
        let users = await db.all('SELECT *, realtime_speed_up, realtime_speed_down, active_connections, status_text, allow_shell FROM users');
        users.forEach(u => {
            u.status_text = u.status_text || (u.status === 'active' ? '启用 (Active)' : 
                               (u.status === 'paused' ? '暂停 (Manual)' : 
                               (u.status === 'expired' ? '已到期 (Expired)' : 
                               (u.status === 'exceeded' ? '超额 (Quota)' :
                               (u.status === 'fused' ? '熔断 (Fused)' : '未知')))));
            u.allow_shell = u.allow_shell || 0;
        });
        res.json({ success: true, users: users });
    } catch (e) {
        res.status(500).json({ success: false, message: `Failed to fetch users: ${e.message}` });
    }
});


api.post('/users/add', async (req, res) => {
    const { username, password, expiration_days, quota_gb, rate_kbps, max_connections, require_auth_header, allow_shell } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: "缺少用户名或密码" });
    if (!/^[a-z0-9_]{3,16}$/.test(username)) return res.status(400).json({ success: false, message: "用户名格式不正确" });
    const existingUser = await getUserByUsername(username);
    if (existingUser) return res.status(409).json({ success: false, message: `用户组 ${username} 已存在于面板` });
    try {
        const shell = SHELL_DEFAULT; 
        const { success: userAddSuccess, output: userAddOutput } = await safeRunCommand(['useradd', '-m', '-s', shell, username]);
        if (!userAddSuccess && !userAddOutput.includes("already exists")) {
            throw new Error(`创建系统用户失败: ${userAddOutput}`);
        }
        
        const chpasswdInput = `${username}:${password}`;
        const { success: chpassSuccess, output: chpassOutput } = await safeRunCommand(['chpasswd'], chpasswdInput);
        if (!chpassSuccess) { throw new Error(`设置系统密码失败: ${chpassOutput}`); }
        
        const lockCmd = ['usermod', '-U', username];
        const { success: lockSuccess, output: lockOutput } = await safeRunCommand(lockCmd);
        if (!lockSuccess) { throw new Error(`解锁账户失败: ${lockOutput}`); }

        if (allow_shell) {
            const { success: groupSuccess, output: groupOutput } = await safeRunCommand(['usermod', '-a', '-G', 'shell_users', username]);
            if (!groupSuccess) {
                console.warn(`[V1.6.0] Failed to add ${username} to shell_users group: ${groupOutput}. Maybe group doesn't exist?`);
            }
        }

        const passwordHash = await bcrypt.hash(password, 12);
        const expiryDate = new Date(Date.now() + expiration_days * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
        
        const newStatus = "active";
        const newStatusText = "启用 (Active)";
        
        const newUser = {
            username: username, password_hash: passwordHash,
            created_at: new Date().toISOString().replace('T', ' ').substring(0, 19),
            status: newStatus,
            expiration_date: expiryDate, 
            quota_gb: parseFloat(quota_gb), usage_gb: 0.0, 
            rate_kbps: parseInt(rate_kbps), 
            max_connections: parseInt(max_connections) || 0,
            require_auth_header: require_auth_header ? 1 : 0,
            realtime_speed_up: 0.0, realtime_speed_down: 0.0,
            active_connections: 0, 
            status_text: newStatusText,
            allow_shell: allow_shell ? 1 : 0
        };
        await db.run(`INSERT INTO users (
                        username, password_hash, created_at, status, expiration_date, 
                        quota_gb, usage_gb, rate_kbps, max_connections, 
                        require_auth_header, realtime_speed_up, realtime_speed_down, active_connections, status_text,
                        allow_shell
                      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                      Object.values(newUser));
        await logAction("USER_ADD_SUCCESS", req.session.username, `User ${username} created (Shell: ${shell}, Lock: UNLOCKED, Shell Group: ${allow_shell})`);
        
        broadcastToProxies({
            action: 'update_limits',
            username: username,
            limits: {
                rate_kbps: newUser.rate_kbps,
                max_connections: newUser.max_connections,
                require_auth_header: newUser.require_auth_header
            }
        });
        
        broadcastToFrontends({ type: 'users_changed' });
        
        res.json({ success: true, message: `用户 ${username} 创建成功，有效期至 ${expiryDate}` });
    } catch (e) {
        await safeRunCommand(['userdel', '-r', username]);
        await logAction("USER_ADD_FAIL", req.session.username, `Failed to create user ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});


api.post('/users/delete', async (req, res) => {
    const { username } = req.body;
    const userToDelete = await getUserByUsername(username);
    if (!userToDelete) return res.status(404).json({ success: false, message: `用户组 ${username} 不存在` });
    try {
        await kickUserFromProxy(username); 
        await safeRunCommand(['pkill', '-9', '-u', username]); 
        await safeRunCommand(['userdel', '-r', username]); 
        await db.run('DELETE FROM users WHERE username = ?', username);
        await db.run('DELETE FROM traffic_history WHERE username = ?', username);
        // [V11.0 NEW] 删除绑定的 TG 记录
        await db.run('DELETE FROM tg_bindings WHERE username = ?', username);
        
        broadcastToProxies({
            action: 'delete',
            username: username
        });
        
        broadcastToFrontends({ type: 'users_changed' });
        
        await logAction("USER_DELETE_SUCCESS", req.session.username, `Deleted user ${username}`);
        res.json({ success: true, message: `用户组 ${username} 已删除，会话已终止` });
    } catch (e) {
        await logAction("USER_DELETE_FAIL", req.session.username, `Failed to delete user ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `删除操作失败: ${e.message}` });
    }
});

api.post('/users/set_settings', async (req, res) => {
    const { username, expiry_date, quota_gb, rate_kbps, max_connections, new_password, require_auth_header, allow_shell } = req.body;
    
    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ success: false, message: `用户 ${username} 不存在` });
    
    try {
        const new_allow_shell = allow_shell ? 1 : 0;
        
        let updateFields = {
            expiration_date: expiry_date || "", 
            quota_gb: parseFloat(quota_gb), 
            rate_kbps: parseInt(rate_kbps), 
            max_connections: parseInt(max_connections) || 0,
            require_auth_header: require_auth_header ? 1 : 0,
            allow_shell: new_allow_shell
        };
        
        let updateSql = 'UPDATE users SET ';
        const updateValues = [];
        const fieldNames = Object.keys(updateFields);

        if (new_password) {
            const chpasswdInput = `${username}:${new_password}`;
            const { success, output } = await safeRunCommand(['chpasswd'], chpasswdInput);
            if (!success) throw new Error(`Failed to update system password: ${output}`);
            const passwordHash = await bcrypt.hash(new_password, 12);
            updateSql += 'password_hash = ?, ';
            updateValues.push(passwordHash);
            
            // [V11.0 NEW] 如果用户已绑定 TG，则更新 TG 绑定表中的密码哈希
            const tgBinding = await getTgBindingByUsername(username);
            if (tgBinding) {
                await db.run('UPDATE tg_bindings SET password_hash = ? WHERE username = ?', passwordHash, username);
            }
            
            await kickUserFromProxy(username); 
            await safeRunCommand(['pkill', '-9', '-u', username]); 
            await logAction("USER_PASS_CHANGE", req.session.username, `Password changed (DB + System) for ${username}. Kicking sessions.`);
        }
        
        if (user.allow_shell != new_allow_shell) {
            let groupCmd, groupActionLog;
            if (new_allow_shell === 1) {
                groupCmd = ['usermod', '-a', '-G', 'shell_users', username];
                groupActionLog = "Added to shell_users group";
            } else {
                groupCmd = ['gpasswd', '-d', username, 'shell_users'];
                groupActionLog = "Removed from shell_users group";
                await safeRunCommand(['pkill', '-9', '-u', username]);
            }
            const { success: groupSuccess, output: groupOutput } = await safeRunCommand(groupCmd);
            if (!success) {
                if (!groupOutput.includes("is not a member")) {
                    throw new Error(`Failed to update group membership: ${groupOutput}`);
                }
            }
            await logAction("USER_SHELL_CHANGE", req.session.username, `Stunnel (444) access for ${username} ${new_allow_shell ? 'ENABLED' : 'DISABLED'}. ${groupActionLog}.`);
        }

        fieldNames.forEach(field => {
            updateSql += `${field} = ?, `;
            updateValues.push(updateFields[field]);
        });
        
        updateSql = updateSql.slice(0, -2); 
        updateSql += ' WHERE username = ?';
        updateValues.push(username);
        await db.run(updateSql, updateValues);
        
        broadcastToProxies({
            action: 'update_limits',
            username: username,
            limits: {
                rate_kbps: updateFields.rate_kbps,
                max_connections: updateFields.max_connections,
                require_auth_header: updateFields.require_auth_header
            }
        });
        
        broadcastToFrontends({ type: 'users_changed' });
        
        setTimeout(syncUserStatus, 1000); 

        await logAction("USER_SETTINGS_UPDATE", req.session.username, `Settings updated for ${username}.`);
        res.json({ success: true, message: `用户 ${username} 的设置已保存。` });

    } catch (e) {
        await logAction("USER_SETTINGS_FAIL", req.session.username, `Failed to update settings for ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});

api.post('/users/status', async (req, res) => {
    const { username, action } = req.body;
    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ success: false, message: `用户 ${username} 不存在` });
    try {
        let newStatus = 'active';
        let newStatusText = '启用 (Active)';
        
        if (action === 'pause') {
            newStatus = 'paused';
            newStatusText = '暂停 (Manual)';
            await safeRunCommand(['usermod', '-L', username]); 
            await kickUserFromProxy(username);
            await safeRunCommand(['pkill', '-9', '-u', username]);
            await logAction("USER_PAUSE", req.session.username, `User ${username} manually paused (System Locked).`);
        
        } else if (action === 'enable') {
            newStatus = 'active';
            newStatusText = '启用 (Active)';
            await safeRunCommand(['usermod', '-U', username]); 
            await logAction("USER_ENABLE", req.session.username, `User ${username} manually enabled (System Unlocked).`);
        }
        
        await db.run(`UPDATE users SET status = ?, status_text = ? WHERE username = ?`, newStatus, newStatusText, username);
        
        broadcastToFrontends({ type: 'users_changed' });
        
        res.json({ success: true, message: `用户 ${username} 状态已更新。` });
    } catch (e) {
        await logAction("USER_STATUS_FAIL", req.session.username, `Failed to change status for ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});

api.post('/users/reset_traffic', async (req, res) => {
    const { username } = req.body;
    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ success: false, message: `用户 ${username} 不存在` });
    try {
        await db.run('BEGIN TRANSACTION');
        await db.run(`UPDATE users SET usage_gb = 0.0 WHERE username = ?`, username);
        await db.run(`DELETE FROM traffic_history WHERE username = ?`, username);
        
        broadcastToProxies({
            action: 'reset_traffic',
            username: username
        });
        
        await db.run('COMMIT');
        
        if (user.status === 'exceeded') {
             await db.run(`UPDATE users SET status = 'active', status_text = '启用 (Active)' WHERE username = ?`, username);
        }
        
        broadcastToFrontends({ type: 'users_changed' });
        
        setTimeout(syncUserStatus, 1000);

        await logAction("USER_TRAFFIC_RESET", req.session.username, `Traffic usage reset for ${username}.`);
        res.json({ success: true, message: `用户 ${username} 的流量使用量和历史记录已重置。` });
    } catch (e) {
        await db.run('ROLLBACK').catch(() => {});
        await logAction("USER_TRAFFIC_FAIL", req.session.username, `Failed to reset traffic for ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});

api.post('/users/kill_all', async (req, res) => {
    const { username } = req.body;
    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ success: false, message: `用户 ${username} 不存在` });
    try {
        const wss_success = await kickUserFromProxy(username);
        const ssh_success = (await safeRunCommand(['pkill', '-9', '-u', username])).success;
        if (wss_success || ssh_success) {
            await logAction("USER_KILL_SESSIONS", req.session.username, `All active sessions (WSS + SSHD) killed for ${username}.`);
            res.json({ success: true, message: `用户 ${username} 的所有活跃连接已强制断开。` });
        } else {
            throw new Error("Proxy /kick and pkill API failed.");
        }
    } catch (e) {
        await logAction("USER_KILL_FAIL", req.session.username, `Failed to kill sessions for ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});

api.post('/users/batch-action', async (req, res) => {
    const { action, usernames, days } = req.body;
    if (!action || !Array.isArray(usernames) || usernames.length === 0) {
        return res.status(400).json({ success: false, message: "无效的请求参数。" });
    }
    let successCount = 0, failedCount = 0; const errors = [];
    try {
        if (action === 'delete') {
            await db.run('BEGIN TRANSACTION');
            for (const username of usernames) {
                try {
                    await kickUserFromProxy(username); 
                    await safeRunCommand(['pkill', '-9', '-u', username]);
                    await safeRunCommand(['userdel', '-r', username]); 
                    await db.run('DELETE FROM users WHERE username = ?', username);
                    await db.run('DELETE FROM traffic_history WHERE username = ?', username);
                    await db.run('DELETE FROM tg_bindings WHERE username = ?', username); // [V11.0 NEW]
                    broadcastToProxies({ action: 'delete', username: username });
                    successCount++;
                } catch(e) { failedCount++; errors.push(`${username}: ${e.message}`); }
            }
            await db.run('COMMIT');
        } else if (action === 'pause') {
            await db.run('BEGIN TRANSACTION');
            for (const username of usernames) {
                try {
                    await db.run(`UPDATE users SET status = 'paused', status_text = '暂停 (Manual)' WHERE username = ?`, username);
                    await safeRunCommand(['usermod', '-L', username]); 
                    await kickUserFromProxy(username); 
                    await safeRunCommand(['pkill', '-9', '-u', username]);
                    successCount++;
                } catch(e) { failedCount++; errors.push(`${username}: ${e.message}`); }
            }
            await db.run('COMMIT');
        } else if (action === 'enable') {
            await db.run('BEGIN TRANSACTION');
            for (const username of usernames) {
                try {
                    const user = await getUserByUsername(username);
                    if (!user) { throw new Error("User not found"); }
                    
                    await db.run(`UPDATE users SET status = 'active', status_text = '启用 (Active)' WHERE username = ?`, username);
                    await safeRunCommand(['usermod', '-U', username]); 
                    successCount++;
                } catch(e) { failedCount++; errors.push(`${username}: ${e.message}`); }
            }
            await db.run('COMMIT');
        } else if (action === 'renew') {
            const renewDays = parseInt(days) || 30; const today = new Date();
            await db.run('BEGIN TRANSACTION');
            for (const username of usernames) {
                try {
                    const user = await getUserByUsername(username);
                    if (!user) { failedCount++; errors.push(`${username}: not found`); continue; }
                    let currentExpiry = null;
                    
                    // [AXIOM V5.5 FIX A4] 增强日期解析的健壮性
                    try { 
                        if (user.expiration_date) { 
                            currentExpiry = new Date(user.expiration_date); 
                        } 
                    } catch(e) { /* ignore parse error */ }
                    
                    let baseDate = today;
                    if (currentExpiry && !isNaN(currentExpiry.getTime()) && currentExpiry.getTime() > today.getTime()) { baseDate = currentExpiry; }
                    const newExpiryDate = new Date(baseDate.getTime() + renewDays * 24 * 60 * 60 * 1000);
                    const newExpiryString = newExpiryDate.toISOString().split('T')[0];
                    
                    await db.run(`UPDATE users SET expiration_date = ?, status = 'active', status_text = '启用 (Active)' WHERE username = ?`, newExpiryString, username);
                    await safeRunCommand(['usermod', '-U', username]); 
                    successCount++;
                } catch(e) { failedCount++; errors.push(`${username}: ${e.message}`); }
            }
            await db.run('COMMIT');
        } else {
            return res.status(400).json({ success: false, message: "无效的动作。" });
        }
        
        broadcastToFrontends({ type: 'users_changed' });
        
        await logAction("USER_BATCH_ACTION", req.session.username, `Action: ${action}, Days: ${days || 'N/A'}, Success: ${successCount}, Failed: ${failedCount}.`);
        res.json({ success: true, message: `批量操作 "${action}" 完成。成功 ${successCount} 个, 失败 ${failedCount} 个。`, errors: errors });
    } catch (e) {
        await db.run('ROLLBACK').catch(() => {});
        await logAction("USER_BATCH_FAIL", req.session.username, `Action: ${action} failed: ${e.message}`);
        res.status(500).json({ success: false, message: `批量操作失败: ${e.message}` });
    }
});


api.get('/users/traffic-history', async (req, res) => {
    const { username } = req.query;
    if (!username) { return res.status(400).json({ success: false, message: "缺少用户名。" }); }
    try {
        const history = await db.all(`SELECT date, usage_gb FROM traffic_history WHERE username = ? ORDER BY date DESC LIMIT 30`, [username]);
        res.json({ success: true, history: history.reverse() }); 
    } catch (e) {
        res.status(500).json({ success: false, message: `获取流量历史失败: ${e.message}` });
    }
});


api.get('/settings/hosts', async (req, res) => {
    const hosts = await loadHosts();
    res.json({ success: true, hosts });
});

api.post('/settings/hosts', async (req, res) => {
    const { hosts: newHostsRaw } = req.body;
    if (!Array.isArray(newHostsRaw)) return res.status(400).json({ success: false, message: "Hosts 必须是列表格式" });
    try {
        const newHosts = newHostsRaw.map(h => String(h).trim().toLowerCase()).filter(h => h);
        await fs.writeFile(HOSTS_DB_PATH, JSON.stringify(newHosts, null, 4), 'utf8');
        
        broadcastToProxies({
            action: 'reload_hosts'
        });
        
        broadcastToFrontends({ type: 'hosts_changed' });
        
        await logAction("HOSTS_UPDATE", req.session.username, `Updated host whitelist. Count: ${newHosts.length}`);
        res.json({ success: true, message: `Host 白名单已更新，WSS 代理将自动热重载。` });
    } catch (e) {
        res.status(500).json({ success: false, message: `保存 Hosts 配置失败: ${e.message}` });
    }
});

api.get('/settings/global', async (req, res) => {
    try {
        // [V11.0 NEW] 扩展全局设置 API 以包含 TG 报警阈值
        const fuseSetting = await db.get("SELECT value FROM global_settings WHERE key = 'fuse_threshold_kbps'");
        const alarmSetting = await db.get("SELECT value FROM global_settings WHERE key = 'tg_alarm_threshold'");
        res.json({
            success: true,
            settings: {
                fuse_threshold_kbps: fuseSetting ? parseInt(fuseSetting.value) : 0,
                tg_alarm_threshold: alarmSetting ? parseInt(alarmSetting.value) : 90 
            }
        });
    } catch (e) {
        res.status(500).json({ success: false, message: `获取全局设置失败: ${e.message}` });
    }
});

api.post('/settings/global', async (req, res) => {
    const { fuse_threshold_kbps, tg_alarm_threshold } = req.body;
    
    // [V11.0 NEW] 支持同时修改多个全局设置
    const updates = [];
    
    if (fuse_threshold_kbps !== undefined) {
        const threshold = parseInt(fuse_threshold_kbps) || 0;
        globalFuseLimitKbps = threshold;
        updates.push({ key: 'fuse_threshold_kbps', value: threshold.toString(), log: `Global fuse threshold set to ${threshold} KB/s.` });
    }
    
    if (tg_alarm_threshold !== undefined) {
        const threshold = parseInt(tg_alarm_threshold) || 90;
        updates.push({ key: 'tg_alarm_threshold', value: threshold.toString(), log: `TG alarm threshold set to ${threshold}%.` });
    }
    
    if (updates.length === 0) {
        return res.status(400).json({ success: false, message: "缺少配置项。" });
    }

    try {
        await db.run('BEGIN TRANSACTION');
        for (const update of updates) {
            await db.run(
                "INSERT OR REPLACE INTO global_settings (key, value) VALUES (?, ?)", 
                update.key, 
                update.value
            );
            await logAction("GLOBAL_SETTINGS_UPDATE", req.session.username, update.log);
        }
        await db.run('COMMIT');
        await loadGlobalSettingsFromDb(); // 重新加载内存缓存
        
        res.json({ success: true, message: "全局安全/TG设置已保存。" });

    } catch (e) {
        await db.run('ROLLBACK').catch(()=>{});
        await logAction("GLOBAL_SETTINGS_FAIL", req.session.username, `Failed to save global settings: ${e.message}`);
        res.status(500).json({ success: false, message: `保存设置失败: ${e.message}` });
    }
});

api.get('/settings/config', (req, res) => {
    const { internal_api_secret, ...safeConfig } = config;
    res.json({ success: true, config: safeConfig });
});

/**
 * [AXIOM V5.0] 增强端口配置修改的稳定性，并兼容 Native UDPGW
 * [AXIOM V11.0.1 UPDATE] 兼容 Native UDPGW 端口的修改
 */
api.post('/settings/config', async (req, res) => {
    const newConfigData = req.body;
    if (!newConfigData) {
        return res.status(400).json({ success: false, message: "无效的配置数据。" });
    }
    
    try {
        let currentConfig = { ...config };
        
        const oldStunnelPort = currentConfig.stunnel_port;
        const oldUdpCustomPort = currentConfig.udp_custom_port;
        // [RESTORED]
        const oldUdgGwPort = currentConfig.udpgw_port; 
        
        const fieldsToUpdate = [
            'panel_port', 'wss_http_port', 'wss_tls_port', 
            'stunnel_port', 
            'udpgw_port', // [RESTORED]
            'udp_custom_port', // [NEW]
            'internal_forward_port'
        ];
        
        let requiresWssRestart = false;
        let requiresPanelRestart = false;
        let requiresStunnelRestart = false;
        let requiresUdpCustomRestart = false;
        let requiresUdgGwRestart = false; // [RESTORED]

        fieldsToUpdate.forEach(key => {
            const newValue = parseInt(newConfigData[key]);
            if (newValue && newValue !== currentConfig[key]) {
                console.log(`[CONFIG] 端口变更: ${key} 从 ${currentConfig[key]} -> ${newValue}`);
                
                currentConfig[key] = newValue;
                
                if (key === 'panel_port') requiresPanelRestart = true;
                if (key === 'wss_http_port' || key === 'wss_tls_port' || key === 'internal_forward_port') requiresWssRestart = true;
                if (key === 'stunnel_port') requiresStunnelRestart = true;
                if (key === 'udpgw_port') requiresUdgGwRestart = true; // [RESTORED]
                if (key === 'udp_custom_port') requiresUdpCustomRestart = true;
            }
        });
        
        currentConfig.panel_api_url = `http://127.0.0.1:${currentConfig.panel_port}/internal`;
        
        try {
            // 1. 处理 Stunnel 端口变更
            if (requiresStunnelRestart) {
                const newPort = currentConfig.stunnel_port;
                console.log(`[CONFIG_FIX] 正在更新 ${STUNNEL_CONF}: ${oldStunnelPort} -> ${newPort}`);
                // [AXIOM V5.5 FIX A7] 使用 sed 命令作为完整参数传递
                const sedResult = await safeRunCommand(['sed', '-i', `s/accept = 0.0.0.0:${oldStunnelPort}/accept = 0.0.0.0:${newPort}/g`, STUNNEL_CONF]);
                if (!sedResult.success) throw new Error(`Failed to update ${STUNNEL_CONF}: ${sedResult.output}`);
            }

            // 2. [NEW] 处理 UDP Custom 端口变更
            if (requiresUdpCustomRestart) {
                const newPort = currentConfig.udp_custom_port;
                console.log(`[CONFIG_FIX] 正在更新 UDP Custom 配置: ${oldUdpCustomPort} -> ${newPort}`);
                
                // 因为文件权限为 600 (root)，必须通过 sudo sed 修改
                const sedResult = await safeRunCommand(['sed', '-i', `s/"listen": ":[0-9]*"/"listen": ":${newPort}"/g`, UDP_CUSTOM_CONFIG_PATH]);
                if (!sedResult.success) {
                    console.error(`[CONFIG_FIX] UDP Custom config update failed: ${sedResult.output}`);
                     // 尝试重新生成配置文件（回退方案）
                    const newContent = JSON.stringify({
                        listen: `:${newPort}`,
                        stream_buffer: 33554432,
                        receive_buffer: 83886080,
                        auth: { mode: "passwords" }
                    }, null, 2);
                    
                    // 使用临时文件 + mv 技巧来写入受保护文件
                    const tempFile = path.join(os.tmpdir(), 'udp_custom_temp.json');
                    await fs.writeFile(tempFile, newContent, 'utf8');
                    await safeRunCommand(['mv', tempFile, UDP_CUSTOM_CONFIG_PATH]);
                }
            }
            
            // 3. [RESTORED] 处理 BadVPN UDPGW 端口变更
            if (requiresUdgGwRestart) {
                 const newPort = currentConfig.udpgw_port;
                 console.log(`[CONFIG_FIX] 正在更新 BadVPN UDPGW 服务文件端口: ${oldUdgGwPort} -> ${newPort}`);
                 // 警告: 这里我们不能直接修改 service 文件，因为 service 文件是部署脚本生成的。
                 // 我们的安装脚本 install.sh 实际上是在启动时通过 sed 替换模板。
                 // 但为了在运行时生效，我们需要确保 wss_proxy.js 读取的配置是正确的，并且重启 udpgw 服务。
                 // wss_proxy.js 会读取 config.json 中的 udpgw_port，所以只需要重启 udpgw 服务。
                 // **唯一可能的问题是 ExecStart 字段的硬编码。**
                 // 如果 ExecStart 被硬编码为 7300，我们需要修改它。
                 // 假设 udpgw.service 是一个模板，我们不能修改它。
                 // 最佳做法是：如果端口变更，则必须重启 udpgw 服务，因为它依赖命令行参数。
                 // 这一步由后续的 `restartServices` 处理。这里不需要修改系统文件，只需要更新 config.json。
                 // 但是，我们仍然要确保 udpgw 服务的 ExecStart 参数在 service 文件中被更新。
                 // 这里我们假设 `udpgw.service` 文件 (如安装脚本所示) 是可修改的，并使用 sed 修复。
                 // 注意：ExecStart 路径在安装脚本中被硬编码替换，这里也需要模仿这个替换逻辑，但我们只替换端口号。
                 
                 const UDPGW_SERVICE_PATH = '/etc/systemd/system/udpgw.service';
                 const sedResult = await safeRunCommand(['sed', '-i', `s/--listen-addr 127.0.0.1:[0-9]*/--listen-addr 127.0.0.1:${newPort}/g`, UDPGW_SERVICE_PATH]);
                 if (!sedResult.success) {
                     console.warn(`[CONFIG_FIX] BadVPN UDPGW service file update failed (Non-critical here): ${sedResult.output}`);
                 }
                 
            }
            
        } catch (e) {
            await logAction("CONFIG_FIX_FAIL", req.session.username, `Failed to patch service files: ${e.message}`);
            res.status(500).json({ success: false, message: `保存 config.json 成功，但应用到服务文件失败: ${e.message}` });
            return; 
        }

        // 4. 立即写入主 config.json
        await fs.writeFile(CONFIG_PATH, JSON.stringify(currentConfig, null, 2), 'utf8');
        
        // 5. 更新面板自身的内存配置
        config = { ...currentConfig };
        
        await logAction("CONFIG_SAVE_SUCCESS", req.session.username, `配置已保存到 ${CONFIG_PATH} 并且服务文件已修补。`);
        
        // 6. 异步重启所有受影响的服务
        const restartServices = async () => {
            // [AXIOM V5.5 FIX A7] 使用 systemctl restart 命令作为完整参数传递
            if (requiresWssRestart) {
                await safeRunCommand(['systemctl', 'restart', 'wss']);
            }
            if (requiresStunnelRestart) {
                await safeRunCommand(['systemctl', 'restart', 'stunnel4']);
            }
            if (requiresUdpCustomRestart) {
                await safeRunCommand(['systemctl', 'restart', 'wss-udp-custom']);
            }
            if (requiresUdgGwRestart) { // [RESTORED]
                await safeRunCommand(['systemctl', 'restart', 'udpgw']);
            }
            if (requiresPanelRestart) {
                setTimeout(async () => {
                    await safeRunCommand(['systemctl', 'restart', 'wss_panel']);
                }, 1000);
            }
        };
        restartServices(); 

        res.json({ success: true, message: `配置已保存并成功应用！相关服务正在后台重启... (面板可能会在 ${requiresPanelRestart ? '1秒' : '0秒'} 后刷新)` });

    } catch (e) {
        await logAction("CONFIG_SAVE_FAIL", req.session.username, `Failed to save config: ${e.message}`);
        res.status(500).json({ success: false, message: `保存配置失败: ${e.message}` });
    }
});


api.post('/settings/change-password', async (req, res) => {
    const { old_password, new_password } = req.body;
    if (!old_password || !new_password) { return res.status(400).json({ success: false, message: "新旧密码均不能为空。" }); }
    if (new_password.length < 6) { return res.status(400).json({ success: false, message: "新密码长度必须至少为 6 位。" }); }
    try {
        const rootHash = await loadRootHash();
        if (!rootHash) { throw new Error("无法加载 root hash 文件。"); }
        const match = await bcrypt.compare(old_password, rootHash);
        if (!match) {
            await logAction("CHANGE_PASS_FAIL", req.session.username, "Failed to change panel password: Incorrect old password");
            return res.status(403).json({ success: false, message: "当前密码不正确。" });
        }
        const newHash = await bcrypt.hash(new_password, 12);
        await fs.writeFile(ROOT_HASH_FILE, newHash, 'utf8');
        await logAction("CHANGE_PASS_SUCCESS", req.session.username, "Panel admin password changed successfully.");
        res.json({ success: true, message: "管理员密码修改成功。" });
    } catch (e) {
        await logAction("CHANGE_PASS_FAIL", req.session.username, `Failed to change panel password: ${e.message}`);
        res.status(500).json({ success: false, message: `密码修改失败: ${e.message}` });
    }
});

api.post('/ips/ban_global', async (req, res) => {
    const { ip, reason } = req.body;
    if (!ip) return res.status(400).json({ success: false, message: "IP 地址不能为空" });
    try {
        const iptablesResult = await manageIpIptables(ip, 'block');
        if (!iptablesResult.success) throw new Error(iptablesResult.output);
        const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
        await db.run(`INSERT OR REPLACE INTO ip_bans (ip, reason, added_by, timestamp) VALUES (?, ?, ?, ?)`,
            ip, reason || 'Manual Panel Ban', req.session.username, timestamp
        );
        await logAction("IP_BAN_GLOBAL", req.session.username, `Globally banned IP ${ip}. Reason: ${reason}`);
        res.json({ success: true, message: `IP 地址 ${ip} 已全局封禁。` });
    } catch (e) {
        await logAction("IP_BAN_FAIL", req.session.username, `Failed to ban IP ${ip}: ${e.message}`);
        res.status(500).json({ success: false, message: `封禁操作失败: ${e.message}` });
    }
});

api.post('/ips/unban_global', async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ success: false, message: "IP 地址不能为空" });
    try {
        const iptablesResult = await manageIpIptables(ip, 'unblock');
        if (!iptablesResult.success && !iptablesResult.output.includes('No chain/target/match')) {
            throw new Error(iptablesResult.output);
        }
        await db.run(`DELETE FROM ip_bans WHERE ip = ?`, ip);
        await logAction("IP_UNBAN_GLOBAL", req.session.username, `Globally unbanned IP ${ip}.`);
        res.json({ success: true, message: `IP 地址 ${ip} 已解除全局封禁。` });
    } catch (e) {
        await logAction("IP_UNBAN_FAIL", req.session.username, `Failed to unban IP ${ip}: ${e.message}`);
        res.status(500).json({ success: false, message: `解除封禁失败: ${e.message}` });
    }
});

api.get('/ips/global_list', async (req, res) => {
    try {
        const bans = await db.all('SELECT * FROM ip_bans ORDER BY timestamp DESC');
        const bansMap = bans.reduce((acc, item) => {
            acc[item.ip] = { reason: item.reason, timestamp: item.timestamp };
            return acc;
        }, {});
        res.json({ success: true, global_bans: bansMap });
    } catch (e) {
        res.status(500).json({ success: false, message: `Failed to fetch ban list: ${e.message}` });
    }
});

api.post('/utils/find_sni', async (req, res) => {
    const { hostname } = req.body;
    if (!hostname) {
        return res.status(400).json({ success: false, message: "Hostname 不能为空。" });
    }
    try {
        const { address: ip_address } = await dns.promises.lookup(hostname);
        const promise = new Promise((resolve, reject) => {
            const options = {
                port: 443,
                host: ip_address, 
                servername: hostname, 
                timeout: 8000, 
                rejectUnauthorized: true 
            };
            const socket = tls.connect(options, () => {
                const cert = socket.getPeerCertificate();
                socket.end();
                if (!cert || !cert.subjectaltname) {
                    return resolve([]); 
                }
                const altNames = cert.subjectaltname
                    .split(',')
                    .map(s => s.trim())
                    .filter(s => s.startsWith('DNS:'))
                    .map(s => s.substring(4)); 
                resolve(altNames);
            });
            socket.on('timeout', () => {
                socket.destroy();
                reject(new Error(`连接到 ${hostname} (port 443) 超时。`));
            });
            socket.on('error', (err) => {
                if (err.code === 'CERT_HAS_EXPIRED' || err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
                     reject(new Error(`SSL 证书验证失败: ${err.message}`));
                } else {
                     reject(new Error(`TLS 错误: ${err.message}`));
                }
            });
        });
        const sniHosts = await promise;
        res.json({ success: true, hosts: sniHosts, ip: ip_address });
    } catch (e) {
        let errorMessage = e.message;
        if (e.code === 'ENOTFOUND' || e.message.includes('getaddrinfo')) {
            errorMessage = `无法解析域名 '${hostname}'。`;
        }
        res.status(500).json({ success: false, message: errorMessage });
    }
});

// [V11.0 NEW] API: 创建卡密
api.post('/vouchers/create', async (req, res) => {
    const { days, quota_gb } = req.body;
    const daysInt = parseInt(days) || 0;
    const quotaFloat = parseFloat(quota_gb) || 0.0;

    if (daysInt <= 0 && quotaFloat <= 0) {
        return res.status(400).json({ success: false, message: "天数或流量至少有一项大于 0。" });
    }
    
    try {
        const code = await createVoucher(daysInt, quotaFloat);
        broadcastToFrontends({ type: 'vouchers_changed' }); // 通知前端更新列表
        res.json({ success: true, code: code, message: `卡密 ${code} 已创建。` });
    } catch (e) {
        res.status(500).json({ success: false, message: `创建卡密失败: ${e.message}` });
    }
});

// [V11.0 NEW] API: 获取卡密列表
api.get('/vouchers/list', async (req, res) => {
    try {
        const vouchers = await db.all('SELECT * FROM vouchers ORDER BY created_at DESC');
        res.json({ success: true, vouchers: vouchers });
    } catch (e) {
        res.status(500).json({ success: false, message: `获取卡密列表失败: ${e.message}` });
    }
});

app.use('/api', loginRequired, api);


// --- IPC (WebSocket) 服务器 ---


function startWebSocketServers(httpServer) {
    console.log(`[AXIOM V6.0] 正在启动实时 WebSocket 服务...`);
    
    // --- 1. IPC (Proxy) 服务器 (/ipc) ---
    wssIpc = new WebSocketServer({
        noServer: true, 
        path: '/ipc'
    });
    
    wssIpc.on('connection', (ws, req) => {
        const workerId = req.headers['x-worker-id'] || req.socket.remoteAddress;
        ws.workerId = workerId;
        console.log(`[IPC_WSS] 一个数据平面 (Proxy Worker: ${workerId}) 已连接。`);
        
        ws.on('message', async (data) => {
            try {
                const message = JSON.parse(data.toString());
                
                // [V9.1 UPDATE] 适配新的紧凑数组消息类型
                if (message.type === 'stats_update_compact' && Array.isArray(message.payload)) {
                    
                    const workerIdKey = message.workerId || ws.workerId;
                    const now = Date.now();
                    
                    if (!workerStatsCache.has(workerIdKey)) {
                         workerStatsCache.set(workerIdKey, { stats: {}, live_ips: {} });
                    }
                    const workerData = workerStatsCache.get(workerIdKey);
                    
                    // 批量更新 Worker 的用户统计数据
                    let needsPersist = false;
                    
                    // Compact Array Format: [username, connections, up_speed, down_speed, up_delta, down_delta]
                    for (const userStatsArray of message.payload) {
                        if (userStatsArray.length !== 6) continue;
                        
                        const [username, conn, up_speed, down_speed, traffic_delta_up, traffic_delta_down] = userStatsArray;
                        
                        // [V6.0 UPDATE] 缓存新的结构，并添加时间戳
                        workerData.stats[username] = {
                            conn: conn,
                            up_speed: up_speed,
                            down_speed: down_speed,
                            traffic_delta_up: traffic_delta_up,
                            traffic_delta_down: traffic_delta_down,
                            timestamp: now 
                        };
                        
                        // 只要有流量增量，就需要持久化
                        if (traffic_delta_up > 0 || traffic_delta_down > 0) {
                            needsPersist = true;
                        }
                        
                        // 如果连接数归零，则将其从 workerData.stats 中删除，避免内存膨胀
                        if (conn === 0 && traffic_delta_up === 0 && traffic_delta_down === 0) {
                             delete workerData.stats[username];
                        }
                    }
                    
                    // [AXIOM V5.5 FIX A3] 异步处理阻塞 I/O 和熔断检查
                    process.nextTick(async () => {
                        try {
                            if (needsPersist) {
                                // 1. 批量持久化流量数据 (传入整个 workerStatsCache 以便聚合所有 Worker 的 delta)
                                await persistTrafficDelta(workerStatsCache); 
                            }
                            
                            if (wssUiPool.size > 0) {
                                // 2. 聚合数据并检查熔断
                                const aggregatedStats = aggregateAllWorkerStats();
                                
                                if (globalFuseLimitKbps > 0) {
                                    for (const username in aggregatedStats.users) {
                                        const userSpeed = aggregatedStats.users[username].speed_kbps;
                                        // 异步执行熔断，防止阻塞
                                        await checkAndApplyFuse(username, userSpeed);
                                    }
                                }
                            }
                        } catch(e) {
                            console.error(`[IPC_ASYNC_TASK] 异步处理失败: ${e.message}`);
                        }
                    });

                } 
                // [AXIOM V5.2] 处理 Worker 的元数据响应
                else if (message.type === 'METADATA_RESPONSE') {
                     // [V9.7 FIX] 检查新的 fetchLiveConnections 上的临时回调
                     if (typeof fetchLiveConnections.onResponse === 'function') {
                         fetchLiveConnections.onResponse(message);
                     }
                }
                
            } catch (e) {
                console.error(`[IPC_WSS] 解析 Proxy 消息失败: ${e.message}`);
            }
        });

        ws.on('close', () => {
            // [V6.0 UPDATE] Worker 断开时，保留其缓存数据 5 秒（以确保其最后的归零状态被处理）
            // 如果 Worker 在线，会由 TTL 机制负责清理其数据。
            // 为了避免立即删除而导致并发连接数统计突然下降，我们让 TTL 机制来接管清理。
            // 简单标记 Worker 的所有数据为旧数据，等待 TTL 清理
            const workerData = workerStatsCache.get(ws.workerId);
            if (workerData && workerData.stats) {
                const now = Date.now() - STALE_TIMEOUT_MS;
                for (const username in workerData.stats) {
                     workerData.stats[username].timestamp = now; 
                }
            }
            console.log(`[IPC_WSS] 一个数据平面 (Proxy Worker: ${ws.workerId}) 已断开连接。TTL 清理机制将接管。`);
        });
        
        ws.on('error', (err) => {
            console.error(`[IPC_WSS] 客户端 WebSocket 错误: ${err.message}`);
        });
    });
    
    wssIpc.on('error', (err) => {
         console.error(`[IPC_WSS] 实时 IPC 服务器错误: ${err.message}`);
    });
    
    // --- 2. UI (Frontend) 服务器 (/ws/ui) ---
    const wssUi = new WebSocketServer({
        noServer: true,
        path: '/ws/ui'
    });

    wssUi.on('connection', (ws, req) => {
        if (!req.session || !req.session.loggedIn) {
            console.warn("[IPC_UI] 拒绝连接: 未经身份验证的前端尝试连接 WebSocket。");
            ws.send(JSON.stringify({ type: 'auth_failed', message: 'Authentication required.' }));
            ws.terminate();
            return;
        }

        console.log(`[IPC_UI] 一个已验证的管理员前端 (User: ${req.session.username}) 已连接。`);
        wssUiPool.add(ws);
        
        if (wssUiPool.size === 1) {
            toggleRealtimePush(true);
        }
        
        ws.send(JSON.stringify({ type: 'status_connected', message: 'WebSocket 连接成功' }));

        ws.on('close', () => {
            console.log(`[IPC_UI] 一个管理员前端已断开连接。`);
            wssUiPool.delete(ws);
            
            if (wssUiPool.size === 0) {
                toggleRealtimePush(false);
            }
        });

        ws.on('error', (err) => {
            console.error(`[IPC_UI] 前端 WebSocket 错误: ${err.message}`);
            wssUiPool.delete(ws);
        });
    });
    
    wssUi.on('error', (err) => {
         console.error(`[IPC_UI] 前端 WS 服务器错误: ${err.message}`);
    });

    // --- 3. HTTP 服务器 'upgrade' 路由 ---
    httpServer.on('upgrade', (request, socket, head) => {
        
        const secret = request.headers['x-internal-secret'];
        const pathname = request.url;

        if (pathname === '/ipc') {
            if (secret !== config.internal_api_secret) {
                console.error("[IPC_WSS] 拒绝连接: 内部 API 密钥 (x-internal-secret) 无效。");
                socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
                socket.destroy();
                return;
            }
            wssIpc.handleUpgrade(request, socket, head, (ws) => {
                wssIpc.emit('connection', ws, request);
            });
        
        } else if (pathname === '/ws/ui') {
            sessionMiddleware(request, {}, () => {
                wssUi.handleUpgrade(request, socket, head, (ws) => {
                    wssUi.emit('connection', ws, request);
                });
            });
            
        } else {
             console.error(`[WS] 拒绝连接: 无效的 WebSocket 路径 (${pathname})。`);
             socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
             socket.destroy();
        }
    });
    
    console.log(`[AXIOM V6.0] 实时 WebSocket 服务已附加到主 HTTP 服务器。`);
}


// --- [AXIOM V3.0] 重构: Startup ---
async function startApp() {
    try {
        await initDb();
        
        const server = http.createServer(app);
        
        // 启动 WebSocket 服务器和 HTTP 升级处理器
        startWebSocketServers(server);
        
        // [TG_BOT] 初始化 Telegram 机器人模块
        const botContext = {
            config,
            db,
            safeRunCommand,
            kickUserFromProxy,
            getSystemStatusData,
            broadcastToFrontends,
            logAction,
            // Trial Context
            globalTrialSettings,    
            getTrialStatus,         
            getPendingTrialRequests,
            addTrialRequest,        
            updateTrialRequestStatus,
            createTrialUser,        
            updateGlobalSetting,    
            getUserByUsername,
            // [V11.0 NEW] Feature Context
            createVoucher,
            redeemVoucher,
            getAllTgBindings,
            getTgBinding,
            bindTgUser,
            unbindTgUser,
            checkSystemHealthAndAlarm, // 暴露给 TG Bot Timer
            // 确保能访问到配置端口
            wss_http_port: config.wss_http_port,
            wss_tls_port: config.wss_tls_port,
            stunnel_port: config.stunnel_port,
            udpgw_port: config.udpgw_port, // [RESTORED]
            udp_custom_port: config.udp_custom_port
        };
        
        initTelegramBot(botContext);
        
        // 60秒维护任务 (无论管理员是否在线，都保持运行)
        setInterval(syncUserStatus, BACKGROUND_SYNC_INTERVAL);
        setTimeout(syncUserStatus, 5000); 
        
        // [V11.0 NEW] 启动系统健康检查定时器
        if (config.tg_bot_token && config.tg_admin_id) {
             console.log(`[HEALTH_CHECK] 启动系统健康检查定时器 (${SYSTEM_HEALTH_CHECK_INTERVAL / 60000} 分钟).`);
             // 第一次延迟检查，给服务启动留出时间
             setTimeout(() => {
                 // Alarm callback sends to admin directly
                 checkSystemHealthAndAlarm(async (message) => {
                      // 这里需要引入 TG Bot 的实例来发送消息，所以只能在 tg_bot_logic.js 内部实现回调
                      // 我们在 tg_bot_logic.js 中实现了这个回调函数。
                      console.log(`[HEALTH_CHECK] Sending alarm to Admin: ${message}`);
                 }); 
             }, 10000); // 延迟 10 秒启动第一次检查
             
             systemHealthTimer = setInterval(() => {
                 // 重新运行健康检查，它会根据内部状态决定是否发送报警
                 checkSystemHealthAndAlarm(async (message) => {
                    console.log(`[HEALTH_CHECK] Sending alarm to Admin: ${message}`);
                 });
             }, SYSTEM_HEALTH_CHECK_INTERVAL);
        }

        server.listen(config.panel_port, '0.0.0.0', () => {
            console.log(`[AXIOM V7.0] WSS Panel (HTTP) 运行在 port ${config.panel_port}`);
            console.log(`[AXIOM V7.0] 实时 IPC (WSS) 运行在 port ${config.panel_port} (路径: /ipc)`);
            console.log(`[AXIOM V7.0] 实时 UI (WSS) 运行在 port ${config.panel_port} (路径: /ws/ui)`);
            console.log(`[AXIOM V7.0] 60秒维护任务已启动。`);
        });
        
        server.on('error', (err) => {
             if (err.code === 'EADDRINUSE') {
                console.error(`[CRITICAL] 启动失败: 端口 ${config.panel_port} 已被占用。`);
             } else {
                console.error(`[CRITICAL] Panel HTTP 服务器错误: ${err.message}`);
             }
             process.exit(1);
        });

    } catch (e) {
        console.error(`[CRITICAL] Panel App 启动失败: ${e.message}`);
        // 确保打印出错误信息
        console.error(`ERROR STACK: ${e.stack}`); 
        process.exit(1);
    }
}

startApp();
