/**
 * WSS Proxy Core (Node.js)
 * V10.1.0 (Axiom - Binary UDPGW Restoration)
 *
 * [ARCHITECT REVIEW V10.1.0]
 * - [REVERT] 移除了 Node.js 原生 UDP (dgram) 处理模块。
 * - [FEATURE] 恢复了对本地 BadVPN-UDPGW (127.0.0.1:7300) 的 TCP 管道转发。
 * - [PERFORMANCE] 回归纯 TCP 事件循环，降低 CPU 占用，由 C++ 二进制处理 UDP 包。
 */

const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const http = require('http'); 
const { URLSearchParams } = require('url');
const WebSocket = require('ws');
const cluster = require('cluster');
const os = require('os');
const crypto = require('crypto'); 

// --- [AXIOM V2.0] 配置加载 ---
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');
let config = {};

function loadConfig() {
    try {
        const configData = fs.readFileSync(CONFIG_PATH, 'utf8');
        config = JSON.parse(configData);
        // [V10.1 FIX] 确保 udpgw_port 存在，默认为 7300
        if (!config.udpgw_port) config.udpgw_port = 7300;
        
        if (cluster.isWorker) {
            console.log(`[AXIOM V10.1] Worker ${cluster.worker.id} 配置加载成功。UDPGW Port: ${config.udpgw_port}`);
        }
    } catch (e) {
        console.error(`[CRITICAL] 无法加载 ${CONFIG_PATH}: ${e.message}。服务将退出。`);
        process.exit(1); 
    }
}
loadConfig(); 
// --- 结束配置加载 ---


// --- 核心常量 ---
const LISTEN_ADDR = '0.0.0.0';
const WSS_LOG_FILE = path.join(PANEL_DIR, 'wss.log'); 
const HOSTS_DB_PATH = path.join(PANEL_DIR, 'hosts.json');
const HTTP_PORT = config.wss_http_port;
const TLS_PORT = config.wss_tls_port;
const INTERNAL_FORWARD_PORT = config.internal_forward_port;
const INTERNAL_API_PORT = config.internal_api_port;
const PANEL_API_URL = config.panel_api_url;
const INTERNAL_API_SECRET = config.internal_api_secret;

// [TARGETS]
const TCP_TARGET = { host: '127.0.0.1', port: INTERNAL_FORWARD_PORT };
const UDPGW_TARGET = { host: '127.0.0.1', port: config.udpgw_port }; // [V10.1 RESTORE]

// [STEALTH] 真实回落目标 (可以是任何 HTTP 网站)
const FALLBACK_TARGET = { host: 'www.bing.com', port: 80 }; 

// [SECURITY] DoS 防护：最大允许的 HTTP 头部大小 (16KB)
const MAX_HEADER_SIZE = 16 * 1024;
const TIMEOUT = 86400000; 
const CERT_FILE = '/etc/stunnel/certs/stunnel.pem';
const KEY_FILE = '/etc/stunnel/certs/stunnel.key';

// [SECURITY] 真实的业务响应
const SWITCH_RESPONSE = Buffer.from('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
const INTERNAL_ERROR_RESPONSE = Buffer.from('HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n');

let HOST_WHITELIST = new Set();
let logStream; 

// --- 令牌桶 (Token Bucket) 限速器 ---
class TokenBucket {
    constructor(capacityKbps, fillRateKbps) {
        this.capacity = Math.max(0, capacityKbps * 1024); 
        this.fillRate = Math.max(0, fillRateKbps * 1024 / 1000); 
        this.tokens = this.capacity; 
        this.lastFill = Date.now();
    }
    _fillTokens() {
        const now = Date.now();
        const elapsed = now - this.lastFill;
        if (elapsed > 0) {
            const newTokens = elapsed * this.fillRate;
            this.tokens = Math.min(this.capacity, this.tokens + newTokens);
            this.tokens = Math.max(0, this.tokens); // 确保令牌不为负
            this.lastFill = now;
        }
    }
    consume(bytesToConsume) {
        if (this.fillRate === 0) return bytesToConsume; 
        this._fillTokens();
        if (bytesToConsume <= this.tokens) {
            this.tokens -= bytesToConsume;
            return bytesToConsume; 
        }
        if (this.tokens > 0) {
             const allowedBytes = this.tokens;
             this.tokens = 0;
             return allowedBytes; 
        }
        return 0; 
    }
    updateRate(newCapacityKbps, newFillRateKbps) {
        this._fillTokens();
        this.capacity = Math.max(0, newCapacityKbps * 1024);
        this.fillRate = Math.max(0, newFillRateKbps * 1024 / 1000);
        this.tokens = Math.min(this.capacity, this.tokens);
        this.lastFill = Date.now();
    }
}

// --- 全局状态管理 ---
// userStats 结构: Map<username, { connections: Map<net.Socket, {id, clientIp, startTime, username}>, ... }>
const userStats = new Map(); 
const SPEED_CALC_INTERVAL = 1000; 

const pending_traffic_delta = {}; 
const WORKER_ID = cluster.isWorker ? cluster.worker.id : 'master';

function getUserStat(username) {
    if (!userStats.has(username)) {
        userStats.set(username, {
            connections: new Map(), 
            ip_map: new Map(), 
            traffic_delta: { upload: 0, download: 0 }, 
            traffic_live: { upload: 0, download: 0 }, 
            speed_kbps: { upload: 0, download: 0 },
            lastSpeedCalc: { upload: 0, download: 0, time: Date.now() }, 
            bucket_up: new TokenBucket(0, 0),
            bucket_down: new TokenBucket(0, 0),
            limits: { rate_kbps: 0, max_connections: 0, require_auth_header: 1 },
            hasChanged: false, 
            lastPushConn: 0,
            lastPushSpeedUp: 0,
            lastPushSpeedDown: 0
        });
    }
    return userStats.get(username);
}

/** 实时速度计算器 */
function calculateSpeeds() {
    const now = Date.now();
    for (const [username, stats] of userStats.entries()) {
        const elapsed = now - stats.lastSpeedCalc.time;
        if (elapsed < (SPEED_CALC_INTERVAL / 2)) continue; 
        const elapsedSeconds = elapsed / 1000.0;
        
        const uploadDelta = stats.traffic_live.upload - stats.lastSpeedCalc.upload;
        const newSpeedUp = (uploadDelta / 1024) / elapsedSeconds;
        
        const downloadDelta = stats.traffic_live.download - stats.lastSpeedCalc.download;
        const newSpeedDown = (downloadDelta / 1024) / elapsedSeconds;
        
        const speedChanged = Math.abs(newSpeedUp - stats.speed_kbps.upload) > 0.1 || 
                             Math.abs(newSpeedDown - stats.speed_kbps.download) > 0.1;
        
        const deltaTraffic = stats.traffic_delta.upload + stats.traffic_delta.download;
        const connChanged = stats.connections.size !== stats.lastPushConn;
        
        if (speedChanged || deltaTraffic > 0 || connChanged) {
             stats.hasChanged = true;
        }

        stats.speed_kbps.upload = newSpeedUp;
        stats.lastSpeedCalc.upload = stats.traffic_live.upload;

        stats.speed_kbps.download = newSpeedDown;
        stats.lastSpeedCalc.download = stats.traffic_live.download;
        
        stats.lastSpeedCalc.time = now;
        
        if (!ipcWsClient || ipcWsClient.readyState !== WebSocket.OPEN) {
            if (!pending_traffic_delta[username]) {
                pending_traffic_delta[username] = { upload: 0, download: 0 };
            }
            pending_traffic_delta[username].upload += stats.traffic_delta.upload;
            pending_traffic_delta[username].download += stats.traffic_delta.download;
            
            stats.traffic_delta.upload = 0;
            stats.traffic_delta.download = 0; 
        }
        
        const hasPending = pending_traffic_delta[username] && 
                           (pending_traffic_delta[username].upload > 0 || pending_traffic_delta[username].download > 0);
                           
        if (stats.connections.size === 0 && !hasPending) {
            if (stats.lastPushConn > 0) {
                 pushZeroStatus(username);
            }
            userStats.delete(username);
            if (pending_traffic_delta[username]) {
                delete pending_traffic_delta[username];
            }
        }
    }
}
setInterval(calculateSpeeds, SPEED_CALC_INTERVAL);


// --- [AXIOM V5.0] 实时 IPC 客户端 ---

let ipcWsClient = null;
let statsPusherIntervalId = null;
let ipcHeartbeatTimer = null;
let ipcIsAlive = true;

let ipcReconnectTimer = null;
let ipcReconnectAttempts = 0;
const MAX_RECONNECT_DELAY_MS = 60000; 
const IPC_HEARTBEAT_INTERVAL = 30000; 

function pushZeroStatus(username) {
    if (!ipcWsClient || ipcWsClient.readyState !== WebSocket.OPEN) {
        return; 
    }
     const stats = userStats.get(username);
     if (!stats) return; 
     
     stats.lastPushConn = 0;
     stats.lastPushSpeedUp = 0;
     stats.lastPushSpeedDown = 0;

     const zeroPacket = [
        [
             username, 
             0, 
             0, 
             0, 
             stats.traffic_delta.upload,
             stats.traffic_delta.download
        ]
     ];
     
     stats.traffic_delta.upload = 0;
     stats.traffic_delta.download = 0;
     
     try {
        ipcWsClient.send(JSON.stringify({
            type: 'stats_update_compact',
            workerId: WORKER_ID, 
            payload: zeroPacket
        }));
    } catch (e) {
        console.error(`[IPC_WSC Worker ${WORKER_ID}] 推送归零状态失败: ${e.message}`);
    }
}

function pushStatsToControlPlane(ws_client) {
    if (!ws_client || ws_client.readyState !== WebSocket.OPEN) {
        return; 
    }

    for (const username in pending_traffic_delta) {
        const stats = getUserStat(username); 
        stats.traffic_delta.upload += pending_traffic_delta[username].upload;
        stats.traffic_delta.download += pending_traffic_delta[username].download;
        if (stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0) {
             stats.hasChanged = true;
        }
        delete pending_traffic_delta[username];
    }
    
    const compactStatsArray = [];
    
    for (const [username, stats] of userStats.entries()) {
        const speedUp = parseFloat(stats.speed_kbps.upload.toFixed(1));
        const speedDown = parseFloat(stats.speed_kbps.download.toFixed(1));
        
        const hasSignificantChange = 
            stats.hasChanged || 
            stats.connections.size !== stats.lastPushConn || 
            speedUp !== stats.lastPushSpeedUp || 
            speedDown !== stats.lastPushSpeedDown; 

        if (hasSignificantChange) {
            compactStatsArray.push([
                username, 
                stats.connections.size, 
                speedUp, 
                speedDown,
                stats.traffic_delta.upload,
                stats.traffic_delta.download
            ]);
            
            stats.traffic_delta.upload = 0;
            stats.traffic_delta.download = 0;
            stats.lastPushConn = stats.connections.size;
            stats.lastPushSpeedUp = speedUp;
            stats.lastPushSpeedDown = speedDown;
            stats.hasChanged = false; 
        }
    }

    if (compactStatsArray.length > 0) {
         try {
            ws_client.send(JSON.stringify({
                type: 'stats_update_compact', 
                workerId: WORKER_ID, 
                payload: compactStatsArray 
            }));
        } catch (e) {
            console.error(`[IPC_WSC Worker ${WORKER_ID}] 推送紧凑统计数据失败: ${e.message}`);
        }
    }
}

function startHeartbeat(ws) {
    if (ipcHeartbeatTimer) clearInterval(ipcHeartbeatTimer);
    ipcIsAlive = true;

    ipcHeartbeatTimer = setInterval(() => {
        if (ws.readyState !== WebSocket.OPEN) {
             clearInterval(ipcHeartbeatTimer);
             return;
        }
        if (!ipcIsAlive) {
            console.warn(`[IPC_WSC Worker ${WORKER_ID}] 心跳超时，连接断开。`);
            ws.terminate(); 
            return;
        }

        ipcIsAlive = false;
        try {
             ws.ping(() => {});
        } catch (e) {}
    }, IPC_HEARTBEAT_INTERVAL);
}

function stopHeartbeat() {
    if (ipcHeartbeatTimer) {
        clearInterval(ipcHeartbeatTimer);
        ipcHeartbeatTimer = null;
    }
}


function kickUser(username) {
    const stats = userStats.get(username);
    if (stats && stats.connections.size > 0) {
        console.log(`[IPC_CMD Worker ${WORKER_ID}] 正在踢出用户 ${username} (${stats.connections.size} 个连接)...`);
        for (const socket of stats.connections.keys()) {
            socket.destroy(); 
        }
        stats.connections.clear();
        stats.ip_map.clear();
    }
}

function updateUserLimits(username, limits) {
    if (!limits) return;
    const stats = getUserStat(username); 
    stats.limits = {
        rate_kbps: limits.rate_kbps || 0,
        max_connections: limits.max_connections || 0,
        require_auth_header: limits.require_auth_header === 0 ? 0 : 1
    };
    const rateUp = stats.limits.rate_kbps;
    stats.bucket_up.updateRate(rateUp * 2, rateUp); 
    const rateDown = stats.limits.rate_kbps; 
    stats.bucket_down.updateRate(rateDown * 2, rateDown); 
}

function resetUserTraffic(username) {
    const stats = userStats.get(username);
    if (stats) {
        console.log(`[IPC_CMD Worker ${WORKER_ID}] 正在重置用户 ${username} 的流量计数器...`);
        stats.traffic_delta = { upload: 0, download: 0 };
        stats.traffic_live = { upload: 0, download: 0 };
        stats.lastSpeedCalc = { upload: 0, download: 0, time: Date.now() };
        stats.hasChanged = true; 
        if (pending_traffic_delta[username]) {
             delete pending_traffic_delta[username];
        }
    }
}

function attemptIpcReconnect() {
    if (ipcReconnectTimer) {
        clearTimeout(ipcReconnectTimer);
        ipcReconnectTimer = null;
    }
    const baseDelay = Math.pow(2, ipcReconnectAttempts) * 1000;
    const delay = Math.min(baseDelay, MAX_RECONNECT_DELAY_MS);
    ipcReconnectAttempts++;
    console.warn(`[IPC_WSC Worker ${WORKER_ID}] 正在重试连接 (尝试次数: ${ipcReconnectAttempts}, 延迟: ${delay / 1000}s)...`);
    ipcReconnectTimer = setTimeout(connectToIpcServer, delay);
}

function getConnectionsMetadata(username) {
    const connections = [];
    if (username) {
        const stats = userStats.get(username);
        if (stats) {
            stats.connections.forEach(meta => {
                connections.push({
                    id: meta.id,
                    ip: meta.clientIp,
                    start: meta.startTime,
                    workerId: WORKER_ID,
                    username: meta.username
                });
            });
        }
    } else {
        for (const [user, stats] of userStats.entries()) {
             stats.connections.forEach(meta => {
                connections.push({
                    id: meta.id,
                    ip: meta.clientIp,
                    start: meta.startTime,
                    workerId: WORKER_ID,
                    username: meta.username
                });
            });
        }
    }
    return connections;
}


function connectToIpcServer() {
    if (ipcReconnectTimer) {
        clearTimeout(ipcReconnectTimer);
        ipcReconnectTimer = null;
    }
    if (ipcWsClient && (ipcWsClient.readyState === WebSocket.OPEN || ipcWsClient.readyState === WebSocket.CONNECTING)) {
        return;
    }

    const ipcUrl = `ws://127.0.0.1:${config.panel_port}/ipc`;
    
    if (ipcWsClient) {
        ipcWsClient.removeAllListeners(); 
        ipcWsClient.close();
        ipcWsClient = null;
    }

    const ws = new WebSocket(ipcUrl, {
        headers: {
            'X-Internal-Secret': config.internal_api_secret,
            'X-Worker-ID': WORKER_ID 
        }
    });

    ipcWsClient = ws;

    ws.on('open', () => {
        console.log(`[IPC_WSC Worker ${WORKER_ID}] 成功连接到控制平面 (Panel)。实时推送已激活。`);
        ipcReconnectAttempts = 0;
        
        stopHeartbeat(); 
        startHeartbeat(ws); 

        if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
        
        statsPusherIntervalId = setInterval(() => {
            pushStatsToControlPlane(ipcWsClient); 
        }, 1000); 
    });

    ws.on('message', (data) => {
        ipcIsAlive = true; 
        try {
            const message = JSON.parse(data.toString());
            
            switch (message.action) {
                case 'kick':
                    if (message.username) {
                        kickUser(message.username);
                    }
                    break;
                case 'update_limits':
                    if (message.username && message.limits) {
                        updateUserLimits(message.username, message.limits);
                    }
                    break;
                case 'reset_traffic':
                     if (message.username) {
                        resetUserTraffic(message.username);
                    }
                    break;
                case 'delete':
                    if (message.username) {
                        kickUser(message.username); 
                        pushZeroStatus(message.username);
                        if (userStats.has(message.username)) {
                            userStats.delete(message.username); 
                        }
                    }
                    break;
                case 'reload_hosts':
                    console.log(`[IPC_CMD Worker ${WORKER_ID}] 收到重载 Hosts 命令...`);
                    loadHostWhitelist();
                    break;
                case 'GET_METADATA':
                case 'GET_ALL_METADATA': 
                     if (message.requestId) {
                         const targetUsername = (message.action === 'GET_METADATA' && message.username) ? message.username : null;
                         
                         const connections = getConnectionsMetadata(targetUsername); 

                         ws.send(JSON.stringify({
                             type: 'METADATA_RESPONSE',
                             requestId: message.requestId,
                             username: targetUsername, 
                             workerId: WORKER_ID,
                             connections: connections
                         }));
                     }
                    break;
            }
        } catch (e) {
            console.error(`[IPC_WSC Worker ${WORKER_ID}] 解析 IPC 消息失败: ${e.message}`);
        }
    });

    ws.on('close', (code, reason) => {
        console.warn(`[IPC_WSC Worker ${WORKER_ID}] 与控制平面的连接已断开。代码: ${code}.`);
        stopHeartbeat();
        if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
        statsPusherIntervalId = null;
        ipcWsClient = null;
        attemptIpcReconnect();
    });
    
    ws.on('pong', () => {
        ipcIsAlive = true;
    });

    ws.on('error', (err) => {
        console.error(`[IPC_WSC Worker ${WORKER_ID}] WebSocket 发生错误: ${err.message}`);
    });
}


// --- 异步日志设置 ---
function setupLogStream() {
    try {
        logStream = fs.createWriteStream(WSS_LOG_FILE, { flags: 'a' });
        logStream.on('error', (err) => {
            console.error(`[CRITICAL] Error in WSS log stream: ${err.message}`);
        });
    } catch (e) {
        console.error(`[CRITICAL] Failed to create log stream: ${e.message}`);
    }
}

function logConnection(clientIp, clientPort, localPort, username, status) {
    if (!logStream) return;
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const workerId = cluster.isWorker ? `Worker ${WORKER_ID}` : 'Master(N/A)';
    const logEntry = `[${timestamp}] [${status}] [${workerId}] USER=${username} CLIENT_IP=${clientIp} LOCAL_PORT=${localPort}\n`;
    logStream.write(logEntry);
}

// --- Host 白名单管理 ---
function loadHostWhitelist() {
    try {
        if (!fs.existsSync(HOSTS_DB_PATH)) {
            HOST_WHITELIST = new Set();
            return;
        }
        const data = fs.readFileSync(HOSTS_DB_PATH, 'utf8');
        const hosts = JSON.parse(data);
        if (Array.isArray(hosts)) {
            const cleanHosts = new Set();
            hosts.forEach(host => {
                if (typeof host === 'string') {
                    let h = host.trim().toLowerCase();
                    if (h.includes(':')) h = h.split(':')[0]; 
                    if (h) cleanHosts.add(h);
                }
            });
            HOST_WHITELIST = cleanHosts;
            if (cluster.isWorker) {
                console.log(`[Worker ${WORKER_ID}] Host Whitelist loaded successfully. Count: ${HOST_WHITELIST.size}`);
            }
        } else {
            HOST_WHITELIST = new Set();
        }
    } catch (e) {
        HOST_WHITELIST = new Set();
        console.error(`Error loading Host Whitelist: ${e.message}. Using empty list.`);
    }
}

function checkHost(headers) {
    const hostMatch = headers.match(/Host:\s*([^\s\r\n]+)/i);
    if (!hostMatch) {
        if (HOST_WHITELIST.size > 0) {
            return false;
        }
        return true; 
    }
    let requestedHost = hostMatch[1].trim().toLowerCase();
    if (requestedHost.includes(':')) requestedHost = requestedHost.split(':')[0];
    if (HOST_WHITELIST.size === 0) return true; 
    if (HOST_WHITELIST.has(requestedHost)) return true;
    
    return false;
}

// --- 认证与并发检查 ---

function parseAuth(headers) {
    const authMatch = headers.match(/Proxy-Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i);
    if (!authMatch) return null;
    try {
        const credentials = Buffer.from(authMatch[1], 'base64').toString('utf8');
        const [username, ...passwordParts] = credentials.split(':');
        const password = passwordParts.join(':');
        if (!username || !password) return null;
        return { username, password };
    } catch (e) {
        return null;
    }
}

async function authenticateUser(username, password) {
    try {
        const response = await fetch(PANEL_API_URL + '/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            return { success: false, limits: null, requireAuthHeader: 1, message: errorData.message || `Auth failed with status ${response.status}` };
        }
        const data = await response.json();
        updateUserLimits(username, data.limits);
        return { success: true, limits: data.limits, requireAuthHeader: data.require_auth_header, message: 'Auth successful' };
    } catch (e) {
        console.error(`[AUTH] Failed to fetch Panel /auth API: ${e.message}`);
        return { success: false, limits: null, requireAuthHeader: 1, message: 'Internal API connection error', status: 503 };
    }
}

async function getLiteAuthStatus(username) {
    try {
        const params = new URLSearchParams({ username });
        const response = await fetch(PANEL_API_URL + '/auth/user-settings?' + params.toString(), {
            method: 'GET',
        });
        if (!response.ok) {
            const status = response.status;
            return { exists: false, requireAuthHeader: 1, status };
        }
        const data = await response.json();
        if (data.success && data.require_auth_header === 0) {
            if (data.limits) {
                updateUserLimits(username, data.limits);
            }
        }
        return { exists: data.success, requireAuthHeader: data.require_auth_header || 1, status: 200 };
    } catch (e) {
        console.error(`[LITE_AUTH] Failed to fetch Panel /auth/user-settings API: ${e.message}`);
        return { exists: false, requireAuthHeader: 1, status: 503 };
    }
}

async function checkConcurrency(username, maxConnections) {
    if (maxConnections === 0) return true; 
    
    const stats = getUserStat(username); 
    if (stats.connections.size >= maxConnections) {
        return false;
    }
    
    try {
        const params = new URLSearchParams({ username, worker_id: WORKER_ID });
        const response = await fetch(PANEL_API_URL + '/auth/check-conn?' + params.toString(), {
            method: 'GET'
        });
        const data = await response.json();
        
        if (!response.ok || !data.success || !data.allowed) {
            return false;
        }
        return data.allowed;
    } catch (e) {
        return (stats.connections.size < maxConnections);
    }
}

// --- Client Handler (Core Logic with Fallback) ---
function handleClient(clientSocket, isTls) {
    
    let clientIp = clientSocket.remoteAddress;
    if (clientIp.startsWith('::ffff:')) {
        clientIp = clientIp.substring(7);
    }
    
    let clientPort = clientSocket.remotePort;
    let localPort = clientSocket.localPort;

    let fullRequest = Buffer.alloc(0);
    
    let state = 'handshake';
    let remoteSocket = null;
    let username = null; 
    let limits = null; 
    let requireAuthHeader = 1; 
    
    // [V10.1 NEW] 标志位：是否转发到本地 BadVPN
    let isUdpMode = false;

    clientSocket.setTimeout(TIMEOUT);
    clientSocket.setKeepAlive(true, 60000);

    // [STEALTH] 核心功能：将非法流量透明转发到回落目标 (Real-Site)
    const proxyToFallback = (initialData) => {
        if (state === 'fallback' || clientSocket.destroyed) return;
        state = 'fallback';

        logConnection(clientIp, clientPort, localPort, 'N/A', `REDIRECTING_TO_FALLBACK (${FALLBACK_TARGET.host})`);

        const fallbackSocket = net.connect(FALLBACK_TARGET.port, FALLBACK_TARGET.host, () => {
            if (initialData && initialData.length > 0) {
                fallbackSocket.write(initialData);
            }
            clientSocket.pipe(fallbackSocket).pipe(clientSocket);
        });

        fallbackSocket.on('error', (err) => {
            clientSocket.destroy();
        });
        
        fallbackSocket.on('close', () => {
            if (!clientSocket.destroyed) clientSocket.end(); 
        });
        
        clientSocket.on('error', () => fallbackSocket.destroy());
    };
    
    const cleanup = () => {
        if (remoteSocket) remoteSocket.destroy();
        if (username) {
            try {
                const stats = getUserStat(username);
                stats.connections.delete(clientSocket);
                stats.ip_map.delete(clientIp);
                stats.hasChanged = true;
            } catch (e) {}
            logConnection(clientIp, clientPort, localPort, username, 'CONN_END');
        }
    };

    clientSocket.on('error', (err) => {
        cleanup();
        clientSocket.destroy();
    });

    clientSocket.on('timeout', () => {
        cleanup();
        clientSocket.destroy();
    });
    
    clientSocket.on('close', cleanup);

    clientSocket.on('data', async (data) => {
        
        if (state === 'forwarding') {
            const stats = getUserStat(username);
            
            // 流量统计和限速
            const allowedBytes = stats.bucket_up.consume(data.length);
            if (allowedBytes === 0) return; 
            const dataToWrite = (allowedBytes < data.length) ? data.subarray(0, allowedBytes) : data;
            stats.traffic_delta.upload += dataToWrite.length;
            stats.traffic_live.upload += dataToWrite.length;
            stats.hasChanged = true; 

            if (remoteSocket && remoteSocket.writable) {
                remoteSocket.write(dataToWrite);
            }
            return;
        }

        if (state === 'fallback') {
            return;
        }

        // [SECURITY] DoS 防护
        if (fullRequest.length + data.length > MAX_HEADER_SIZE) {
            logConnection(clientIp, clientPort, localPort, 'N/A', 'REJECTED_DOS_HEADER_SIZE');
            clientSocket.destroy(); 
            return;
        }

        fullRequest = Buffer.concat([fullRequest, data]);

        while (state === 'handshake' && fullRequest.length > 0) {
            
            const headerEndIndex = fullRequest.indexOf('\r\n\r\n');

            if (headerEndIndex === -1) {
                return; // 等待更多数据
            }

            const headersRaw = fullRequest.subarray(0, headerEndIndex);
            let dataAfterHeaders = fullRequest.subarray(headerEndIndex + 4);
            const headers = headersRaw.toString('utf8', 0, headersRaw.length);
            
            fullRequest = dataAfterHeaders;
            
            // 1. Host 检查
            if (!checkHost(headers)) {
                logConnection(clientIp, clientPort, localPort, 'N/A', 'REJECTED_HOST_FALLBACK');
                proxyToFallback(Buffer.concat([headersRaw, Buffer.from('\r\n\r\n'), dataAfterHeaders])); 
                return; 
            }
            
            const auth = parseAuth(headers);
            
            const isWebsocketRequest = headers.includes('Upgrade: websocket') || 
                                       headers.includes('Connection: Upgrade') || 
                                       headers.includes('GET-RAY'); 
            
            // [V10.1 NEW] 检测 UDPGW (BadVPN) 协议特征
            // 一些客户端会在 Header 中声明，或者使用 UDPGW 模式
            const isUdpRequest = headers.includes('X-Mode: UDPGW') || headers.includes('X-Mode: UDP');


            // 2. 协议检查
            if (!isWebsocketRequest && !isUdpRequest) {
                 logConnection(clientIp, clientPort, localPort, 'N/A', 'DUMMY_HTTP_REQUEST_FALLBACK');
                 proxyToFallback(Buffer.concat([headersRaw, Buffer.from('\r\n\r\n'), dataAfterHeaders]));
                 return; 
            }
            
            // --- 认证流程 ---
            let authResult;
            if (auth) {
                username = auth.username; 
                authResult = await authenticateUser(auth.username, auth.password);
                
                if (authResult.status === 503) {
                    clientSocket.end(INTERNAL_ERROR_RESPONSE);
                    return;
                }
                if (!authResult.success) {
                    logConnection(clientIp, clientPort, localPort, username, `AUTH_FAILED_FALLBACK (${authResult.message})`);
                    proxyToFallback(Buffer.concat([headersRaw, Buffer.from('\r\n\r\n'), dataAfterHeaders])); 
                    return; 
                }
                limits = authResult.limits; 
                requireAuthHeader = authResult.requireAuthHeader;
                
            } else {
                // URI 免认证
                const uriMatch = headers.match(/GET\s+\/\?user=([a-z0-9_]{3,16})/i);
                
                if (requireAuthHeader === 1) { 
                    logConnection(clientIp, clientPort, localPort, 'N/A', 'AUTH_MISSING_FALLBACK');
                    proxyToFallback(Buffer.concat([headersRaw, Buffer.from('\r\n\r\n'), dataAfterHeaders])); 
                    return;
                }

                if (!uriMatch) {
                    logConnection(clientIp, clientPort, localPort, 'N/A', 'URI_AUTH_MISSING_FALLBACK');
                    proxyToFallback(Buffer.concat([headersRaw, Buffer.from('\r\n\r\n'), dataAfterHeaders]));
                    return; 
                }
                
                const tempUsername = uriMatch[1];
                const liteAuth = await getLiteAuthStatus(tempUsername);

                if (liteAuth.status === 503) {
                     clientSocket.end(INTERNAL_ERROR_RESPONSE);
                     return;
                }
                
                if (liteAuth.exists && liteAuth.requireAuthHeader === 0) {
                    username = tempUsername;
                    limits = getUserStat(username).limits; 
                    requireAuthHeader = 0;
                    logConnection(clientIp, clientPort, localPort, username, 'AUTH_LITE_SUCCESS');
                    
                } else {
                    logConnection(clientIp, clientPort, localPort, tempUsername, 'AUTH_LITE_FAILED_FALLBACK');
                    proxyToFallback(Buffer.concat([headersRaw, Buffer.from('\r\n\r\n'), dataAfterHeaders]));
                    return; 
                }
            }
            
            // --- 并发检查 ---
            if (!await checkConcurrency(username, limits.max_connections)) {
                logConnection(clientIp, clientPort, localPort, username, `REJECTED_CONCURRENCY`);
                proxyToFallback(Buffer.concat([headersRaw, Buffer.from('\r\n\r\n'), dataAfterHeaders])); 
                return; 
            }
            
            // --- 决定模式并升级连接 ---
            clientSocket.write(SWITCH_RESPONSE); 
            
            const initialSshData = fullRequest;
            fullRequest = Buffer.alloc(0); 

            isUdpMode = isUdpRequest;
            
            // --- Payload Eater / 分割载荷处理 ---
            const sshVersionMarker = Buffer.from('SSH-2.0-');
            const sshStartIndex = initialSshData.indexOf(sshVersionMarker);
            
            let dataToSend = initialSshData;
            
            if (sshStartIndex !== -1 && !isUdpMode) { // 仅对 SSH 模式应用 Payload Eater
                dataToSend = initialSshData.subarray(sshStartIndex);
                logConnection(clientIp, clientPort, localPort, username, `PAYLOAD_EATER_SUCCESS (Skipped ${sshStartIndex} bytes)`);
            } else if (initialSshData.length > 0) {
                 logConnection(clientIp, clientPort, localPort, username, `PAYLOAD_EATER_WARNING (No SSH Marker / UDP Mode)`);
            }
            
            // [V10.1 RESTORE] 连接目标选择
            // 如果是 UDP 模式，连接到本地 BadVPN-UDPGW 端口 (7300)
            // 否则连接到 SSH (22)
            const targetHost = isUdpMode ? UDPGW_TARGET.host : TCP_TARGET.host;
            const targetPort = isUdpMode ? UDPGW_TARGET.port : TCP_TARGET.port;
            const modeName = isUdpMode ? 'UDPGW_BINARY' : 'TCP_SSH';

            connectToTarget(targetHost, targetPort, modeName, dataToSend);
            
            return;

        } 
    }); 

    async function connectToTarget(targetHost, targetPort, modeName, initialData) {
        if (remoteSocket) return; 
        try {
            // [V10.1 RESTORE] 建立到本地目标（SSH 或 BadVPN）的纯 TCP 管道
            remoteSocket = net.connect(targetPort, targetHost, () => {
                logConnection(clientIp, clientPort, localPort, username, `CONN_START_${modeName} -> ${targetPort}`); 
                const stats = getUserStat(username);
                
                const connectionId = crypto.randomUUID();
                stats.connections.set(clientSocket, {
                    id: connectionId,
                    clientIp: clientIp,
                    startTime: new Date().toISOString(),
                    workerId: WORKER_ID,
                    username: username,
                    socket: remoteSocket 
                });
                
                stats.ip_map.set(clientIp, clientSocket);
                stats.hasChanged = true; 
                
                state = 'forwarding';
                
                if (initialData.length > 0) {
                    // 对于 BadVPN，我们直接把客户端发来的数据包写入管道
                    // 客户端发来的应该是符合 BadVPN 协议的数据
                    remoteSocket.write(initialData);
                }
                
                // --- Downstream (Download) ---
                remoteSocket.on('data', (data) => {
                    const stats = getUserStat(username);
                    const allowedBytes = stats.bucket_down.consume(data.length);
                    if (allowedBytes === 0) return; 
                    const dataToWrite = (allowedBytes < data.length) ? data.subarray(0, allowedBytes) : data;
                    stats.traffic_delta.download += dataToWrite.length;
                    stats.traffic_live.download += dataToWrite.length;
                    stats.hasChanged = true; 
                    if (clientSocket.writable) {
                        clientSocket.write(dataToWrite);
                    }
                });
                remoteSocket.setKeepAlive(true, 60000);
            });

            remoteSocket.on('error', (err) => {
                if (err.code === 'ECONNREFUSED') {
                    console.error(`[WSS] Connection refused by target ${targetHost}:${targetPort} (${modeName})`);
                }
                clientSocket.destroy();
            });

            remoteSocket.on('close', () => {
                clientSocket.end();
            });
        } catch (e) {
            clientSocket.destroy();
        }
    }
}


// --- Internal API Server (Master Process Only) ---
function startInternalApiServer() {
    
    const internalApiSecretMiddleware = (req, res, next) => {
        if (req.headers['x-internal-secret'] === INTERNAL_API_SECRET) {
            next();
        } else {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Forbidden' }));
        }
    };
    
    const server = http.createServer((req, res) => {
        const clientIp = req.socket.remoteAddress;
        if (clientIp !== '127.0.0.1' && clientIp !== '::1' && clientIp !== '::ffff:127.0.0.1') {
             res.writeHead(403, { 'Content-Type': 'application/json' });
             res.end(JSON.stringify({ success: false, message: 'Forbidden' }));
             return;
        }
        
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', async () => {
            try {
                if (req.method === 'GET' && req.url === '/stats') {
                    internalApiSecretMiddleware(req, res, () => {
                        res.writeHead(501, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ success: false, message: 'API /stats is deprecated. Use IPC.' }));
                    });
                } else {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Not Found' }));
                }
            } catch (e) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Internal Server Error' }));
            }
        });
    });

    server.listen(INTERNAL_API_PORT, '127.0.0.1', () => {}).on('error', (err) => {
        console.error(`[CRITICAL] WSS Internal API failed: ${err.message}`);
        process.exit(1);
    });
}


// --- Server Initialization ---
function startServers() {
    loadHostWhitelist();
    setupLogStream();
    connectToIpcServer(); 

    const httpServer = net.createServer((socket) => {
        handleClient(socket, false);
    });
    httpServer.listen(HTTP_PORT, LISTEN_ADDR, () => {
        console.log(`[WSS Worker ${WORKER_ID}] Listening on ${LISTEN_ADDR}:${HTTP_PORT} (HTTP)`);
    }).on('error', (err) => {
        console.error(`[CRITICAL Worker ${WORKER_ID}] HTTP Server failed to start on port ${HTTP_PORT}: ${err.message}`);
        process.exit(1); 
    });

    try {
        if (!fs.existsSync(CERT_FILE) || !fs.existsSync(KEY_FILE)) {
            return;
        }
        const tlsOptions = {
            key: fs.readFileSync(KEY_FILE),
            cert: fs.readFileSync(CERT_FILE),
            rejectUnauthorized: false
        };
        const tlsServer = tls.createServer(tlsOptions, (socket) => {
            handleClient(socket, true);
        });
        tlsServer.listen(TLS_PORT, LISTEN_ADDR, () => {
            console.log(`[WSS Worker ${WORKER_ID}] Listening on ${LISTEN_ADDR}:${TLS_PORT} (TLS)`);
        }).on('error', (err) => {
            console.error(`[CRITICAL Worker ${WORKER_ID}] TLS Server failed to start on port ${TLS_PORT}: ${err.message}`);
            process.exit(1); 
        });
    } catch (e) {
        console.error(`[WSS Worker ${WORKER_ID}] TLS setup failed: ${e.message}`);
    }
}

process.on('SIGINT', () => {
    if (logStream) logStream.end();
    if (ipcReconnectTimer) clearTimeout(ipcReconnectTimer);
    if (statsPusherIntervalId) clearInterval(statsPusherIntervalId);
    stopHeartbeat();
    process.exit(0);
});

if (cluster.isPrimary) {
    const numCPUs = os.cpus().length;
    console.log(`[AXIOM Cluster Master] Master process ${process.pid} is running.`);
    console.log(`[AXIOM Cluster Master] Forking ${numCPUs} worker processes...`);

    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }
    
    startInternalApiServer();
    
    cluster.on('exit', (worker, code, signal) => {
        console.error(`[AXIOM Cluster Master] Worker ${worker.process.pid} died. Forking replacement...`);
        cluster.fork();
    });

} else {
    console.log(`[AXIOM Cluster Worker] Worker ${process.pid} (ID: ${WORKER_ID}) starting...`);
    startServers();
    process.on('message', (msg) => {});
    process.on('uncaughtException', (err, origin) => {
        console.error(`[AXIOM Cluster Worker ${WORKER_ID}] Uncaught Exception: ${err.message}`, `Origin: ${origin}`);
        process.exit(1); 
    });
}
