/**
 * WSS Panel Telegram Bot Module
 * V11.0.0 (Axiom - Full TG Feature Set)
 *
 * [AXIOM V11.0.0 CHANGELOG]
 * - [BUGFIX] /trial_config 等命令现在能正确更新并读取到新配置。
 * - [FEATURE 1] 新增 /create_voucher 和 /redeem <card_code> 卡密兑换系统。
 * - [FEATURE 2] 新增 /broadcast <message> 管理员广播功能。
 * - [FEATURE 3] 移除健康检查定时器（移至 wss_panel.js），新增 alarmCallback 接口。
 * - [FEATURE 4] 新增 /bind <user> <pass> 和 /unbind 账号绑定/解绑功能。
 * - [UPDATE] /my_status 兼容已绑定账号和试用账号的查询。
 */

const TelegramBot = require('node-telegram-bot-api');
const bcrypt = require('bcrypt');
const os = require('os');
const { promisify } = require('util');
const sleep = promisify(setTimeout);

// --- 辅助函数：将用户名和密码编码为 Base64 令牌 ---
function generateBase64Token(username, password) {
    try {
        // [V10.0 FIX] 确保使用 Buffer
        return Buffer.from(`${username}:${password}`).toString('base64');
    } catch (e) {
        return "编码失败";
    }
}

// --- 辅助函数：格式化 KB/s 为 MB/s ---
function formatRate(kbps) {
    if (kbps === 0) return '无限';
    // [V11.0 FIX] 确保单位正确
    return `${(kbps / 1024).toFixed(1)} MB/s`;
}

/**
 * 初始化机器人
 * @param {Object} context - 主进程传入的上下文对象
 */
async function initTelegramBot(context) {
    const { 
        config, 
        db, 
        safeRunCommand, 
        kickUserFromProxy, 
        getSystemStatusData, 
        broadcastToFrontends,
        logAction,
        // Trial Context
        globalTrialSettings,    // 内存中的全局设置 (只读)
        getTrialStatus,         // 获取用户当前试用状态
        getPendingTrialRequests,
        addTrialRequest,        // 接收 tg_id, tg_username, 返回 requestId
        updateTrialRequestStatus,
        createTrialUser,        // 核心创建函数 (使用全局参数)
        updateGlobalSetting,    // 更新全局设置函数
        getUserByUsername,
        // [V11.0 NEW] Feature Context
        createVoucher,
        redeemVoucher,
        getAllTgBindings,
        getTgBinding,
        bindTgUser,
        unbindTgUser,
        checkSystemHealthAndAlarm, // 暴露给 TG Bot Timer
        getTgAlarmThreshold,
        // 确保能访问到配置端口
        wss_http_port,
        wss_tls_port,
        stunnel_port,
        udp_custom_port
    } = context;

    // 1. 检查配置
    if (!config.tg_bot_token || !config.tg_admin_id) {
        console.log('[TG_BOT] tg_bot_token 或 tg_admin_id 未设置，机器人模块跳过启动。');
        return;
    }

    const token = config.tg_bot_token;
    const adminId = parseInt(config.tg_admin_id);

    // [V11.0 NEW] 定义报警回调，用于 wss_panel.js 中的健康检查
    const alarmCallback = async (message) => {
        try {
            await bot.sendMessage(adminId, message, { parse_mode: 'Markdown' });
        } catch(e) {
            console.error(`[TG_BOT Alarm] 发送报警消息失败: ${e.message}`);
        }
    };
    
    // 将 alarmCallback 传递给 wss_panel.js，以便它可以被定时任务调用
    context.checkSystemHealthAndAlarm = (message) => checkSystemHealthAndAlarm(alarmCallback);


    console.log(`[TG_BOT] 正在启动 Telegram 机器人... (Admin ID: ${adminId})`);

    // 2. 创建 Bot 实例 (Polling 模式)
    const bot = new TelegramBot(token, { polling: true });
    
    // --- 权限校验中间件 ---
    const checkAdminPermission = (msg) => {
        if (msg.from.id !== adminId) {
            bot.sendMessage(msg.chat.id, "⛔️ 权限不足。此指令仅限管理员使用。");
            console.warn(`[TG_BOT] 拒绝未授权访问: ${msg.from.username} (ID: ${msg.from.id})`);
            return false;
        }
        return true;
    };
    
    // --- 配置消息生成器 (使用实际参数) ---
    function generateConfigMessage(creds) {
        const token = generateBase64Token(creds.username, creds.password);
        
        // 使用配置中的端口，服务器 IP 依然使用 placeholder
        const serverIp = "ziqing1.netlib.re"; 
        
        const configText = `
🎉 *配置信息*

**👤 用户信息**
---------------------------
• 用户名: \`${creds.username}\`
• 密码: \`${creds.password}\`
• 令牌 (Base64): \`${token}\`

**⚙️ 服务详情**
---------------------------
• IP 地址: \`${serverIp}\`
• WSS/WS 端口 (HTTP): \`${wss_http_port}\`
• WSS/WS 端口 (TLS): \`${wss_tls_port}\`
• Stunnel 端口: \`${stunnel_port}\`
• UDP Custom 端口: \`${udp_custom_port}\`

**限制**
---------------------------
• 到期日: \`${creds.expiryDate || '永不'}\`
• 流量限制: \`${creds.quotaGb > 0 ? creds.quotaGb + ' GB' : '无限'}\`
• 限速: \`${formatRate(creds.rateKbps)}\`
• 并发数: \`${creds.maxConnections > 0 ? creds.maxConnections : '无限'}\`

**🔧 Payload/链接 (HTTP Injector)**
---------------------------
Payload 模板 (复制后粘贴到 Payload Generator):
\`CONNECT [host_port] [protocol][crlf]Host: [YOUR_HOST][crlf]Proxy-Authorization: Basic ${token}[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf]Connection: upgrade[crlf]Upgrade: websocket[crlf][crlf]\`

*注意：请将上面的 \`[YOUR_HOST]\` 替换为您的运营商HOST。*
        `;
        return configText;
    }

    // =============================
    // 指令处理器 (公共用户 & 管理员)
    // =============================
    
    // 1. /start & /help (公共和管理员通用，实现主动引导)
    bot.onText(/^\/(start|help)(?:@\w+)?(?:\s|$)/i, (msg) => {
        const is_admin = msg.from.id === adminId;
        
        // [V11.0 FIX] 重新从内存加载最新配置
        const settings = globalTrialSettings; 
        
        let helpText;
        let keyboard;
        
        if (is_admin) {
            const trialStatus = settings.enabled ? '🟢 开启' : '🔴 关闭';
            const autoApprove = settings.auto_approve ? '🟢 开启 (自动)' : '🔴 关闭 (手动)';
            
            helpText = `
🤖 *WSS Panel 管理机器人 (Admin)*

**🚀 试用功能总览**
• 申请开关: ${trialStatus}
• 自动审批: ${autoApprove}
• 当前配额: ${settings.days} 天 / ${settings.quota_gb} GB
• 限速/并发: ${formatRate(settings.rate_kbps)} / ${settings.max_connections}

**⚙️ 管理指令**
/status - 查看系统负载、服务状态
/pending - 查看待审批申请
/create_voucher <天数> <流量GB> - 创建卡密 (例如: /create_voucher 30 10.0)
/broadcast <消息> - 广播消息给所有已绑定的用户

**🛠️ 试用配置**
/trial_status - 查看/配置当前试用设置
/enable_trial - 开启试用申请功能
/disable_trial - 关闭试用申请功能
/enable_auto_approve - 开启自动审批
/disable_auto_approve - 关闭自动审批
/trial_config <天> <GB> <KB/s> <并发> - 设置试用参数
/set_alarm <CPU%> - 设置 CPU 报警阈值 (例如: /set_alarm 95)
        
**🤝 用户自助 (所有用户可用)**
/my_status - 查询自己的账户状态
/apply - 提交试用申请
/bind <user> <pass> - 绑定WSS账号
/unbind - 解绑WSS账号
/redeem <card_code> - 兑换卡密
        `;
            // Admin Keyboard (提供快速访问)
            keyboard = {
                keyboard: [
                    [{ text: '/status' }, { text: '/trial_status' }, { text: '/create_voucher' }],
                    [{ text: '/pending' }, { text: '/broadcast' }],
                    [{ text: '/my_status' }, { text: '/apply' }, { text: '/bind' }]
                ],
                resize_keyboard: true,
                one_time_keyboard: false
            };
        } else {
            const trialStatus = settings.enabled ? '🟢' : '🔴';
            
            helpText = `
👋 欢迎，我是 WSS 隧道助手。

${trialStatus} **试用申请功能**: ${settings.enabled ? '已开启' : '已关闭'}
${settings.enabled ? `配额: ${settings.days} 天 / ${settings.quota_gb} GB` : ''}

您可以通过以下指令管理您的账号或申请试用：

👉 **申请试用**: 发送 \`/apply\` 提交申请。
👉 **查询状态**: 发送 \`/my_status\` 查看您的账号流量和到期日。
👉 **绑定账号**: 发送 \`/bind <user> <pass>\` 绑定您手动创建的账号。
👉 **卡密兑换**: 发送 \`/redeem <card_code>\` 续期或充值流量。

*请点击下方按钮快速操作。*
            `;
            // Public Keyboard (自助服务菜单)
            keyboard = {
                keyboard: [
                    [{ text: '/my_status' }, { text: '/apply' }, { text: '/redeem' }],
                    [{ text: '/bind' }, { text: '/unbind' }]
                ],
                resize_keyboard: true,
                one_time_keyboard: false
            };
        }
        
        bot.sendMessage(msg.chat.id, helpText, { 
            parse_mode: 'Markdown',
            reply_markup: keyboard
        });
    });
    
    // 2. /status - 系统状态 (Admin ONLY)
    bot.onText(/^\/status(?:@\w+)?(?:\s|$)/i, async (msg) => {
        if (!checkAdminPermission(msg)) return; 
        
        const loadingMsg = await bot.sendMessage(msg.chat.id, "🔍 正在获取系统状态...");
        
        try {
            const data = await getSystemStatusData();
            
            const statsText = `
🖥 *系统状态报告*
------------------
🔥 *CPU*: ${data.cpu_usage.toFixed(1)}% (阈值: ${globalTrialSettings.tg_alarm_threshold}%)
🧠 *内存*: ${data.memory_used_gb.toFixed(2)} / ${data.memory_total_gb.toFixed(2)} GB
💾 *磁盘*: ${data.disk_used_percent}%

🌐 *网络服务*
• WSS (80/443): ${data.services.wss.status === 'running' ? '✅' : '❌'}
• Stunnel (444): ${data.services.stunnel4.status === 'running' ? '✅' : '❌'}
• UDP Custom: ${data.services['wss-udp-custom'].status === 'running' ? '✅' : '❌'}

👥 *用户统计*
• 总用户: ${data.user_stats.total}
• 活跃连接: ${data.user_stats.active}
• 暂停/过期: ${data.user_stats.paused + data.user_stats.expired}
• 总消耗流量: ${data.user_stats.total_traffic_gb.toFixed(2)} GB
            `;
            
            bot.editMessageText(statsText, {
                chat_id: msg.chat.id,
                message_id: loadingMsg.message_id,
                parse_mode: 'Markdown'
            });
        } catch (e) {
            bot.editMessageText(`❌ 获取状态失败: ${e.message}`, {
                chat_id: msg.chat.id,
                message_id: loadingMsg.message_id
            });
        }
    });

    // 3. /pending - 查看待审批申请 (Admin ONLY)
    bot.onText(/^\/pending(?:@\w+)?(?:\s|$)/i, async (msg) => {
        if (!checkAdminPermission(msg)) return; 
        
        if (globalTrialSettings.auto_approve) {
             bot.sendMessage(msg.chat.id, "⚠️ **自动审批已开启**，所有新申请都已立即开通，无需手动审批。", { parse_mode: 'Markdown' });
             return;
        }

        try {
            const pendingRequests = await getPendingTrialRequests();
            
            if (pendingRequests.length === 0) {
                bot.sendMessage(msg.chat.id, "✅ 目前没有待审批的试用申请。");
                return;
            }

            let responseText = `🔔 *待审批申请列表* (${pendingRequests.length} 条)\n\n`;
            bot.sendMessage(msg.chat.id, responseText, { parse_mode: 'Markdown' });

            // 循环发送，为每个请求生成独立的内联键盘
            for (const req of pendingRequests) {
                const tgUsername = req.tg_username ? `(@${req.tg_username})` : '';
                // [V10.0 FIX] 显示数据库记录 ID (req.id)，方便回调处理
                const requestDetail = `👤 ID: \`${req.id}\` (TG: \`${req.tg_id}\`) ${tgUsername}\n   申请于: ${req.request_time.substring(5, 16)}\n`;
                
                const inlineKeyboard = [
                    [
                        { 
                            text: `✅ 批准 (${globalTrialSettings.days}天/${globalTrialSettings.quota_gb}GB)`, 
                            // 回调数据使用数据库记录的 ID
                            callback_data: `approve_${req.id}` 
                        },
                        { 
                            text: '❌ 拒绝', 
                            // 回调数据使用数据库记录的 ID
                            callback_data: `reject_${req.id}` 
                        }
                    ]
                ];
                
                bot.sendMessage(msg.chat.id, requestDetail, {
                    parse_mode: 'Markdown',
                    reply_markup: { inline_keyboard: inlineKeyboard }
                });
            }

        } catch (e) {
            bot.sendMessage(msg.chat.id, `❌ 获取待审批列表失败: ${e.message}`);
        }
    });

    // 4. /my_status (公共指令)
    // [V11.0 UPDATE] 兼容绑定账号和试用账号的查询
    bot.onText(/^\/my[_]?status(?:@\w+)?(?:\s|$)/i, async (msg) => {
        const tg_id = msg.from.id;
        let usernameToQuery = null;

        try {
            // 1. 检查是否是已绑定的账号 (优先级最高)
            const binding = await getTgBinding(tg_id);
            if (binding) {
                usernameToQuery = binding.username;
            } else {
                // 2. 检查是否是试用账号
                const trialStatus = await getTrialStatus(tg_id);
                if (trialStatus.current && trialStatus.current.status === 'approved' && trialStatus.current.username) {
                    usernameToQuery = trialStatus.current.username;
                }
            }

            if (!usernameToQuery) {
                 bot.sendMessage(msg.chat.id, "⚠️ 您没有活跃的账号。请发送 `/apply` 申请试用或 `/bind <user> <pass>` 绑定已有账号。", { parse_mode: 'Markdown' });
                 return;
            }

            const user = await getUserByUsername(usernameToQuery);
            
            if (!user) {
                 bot.sendMessage(msg.chat.id, "❌ 关联的用户账户不存在。请联系管理员。");
                 return;
            }
            
            const quota = user.quota_gb > 0 ? `${user.quota_gb} GB` : '无限';
            const remaining = user.quota_gb > 0 ? (user.quota_gb - user.usage_gb).toFixed(2) + ' GB' : 'N/A';
            const statusEmoji = user.status === 'active' ? '✅' : (user.status === 'paused' ? '⏸' : '❌');
            const expiry = user.expiration_date || '永不';

            let expiryStatus = expiry;
            if (expiry !== '永不') {
                const now = new Date();
                const expDate = new Date(expiry);
                if (expDate < now) {
                    expiryStatus = `${expiry} 🚨 (已过期)`;
                } else {
                    const daysLeft = Math.ceil((expDate - now) / (1000 * 60 * 60 * 24));
                    expiryStatus = `${expiry} (${daysLeft} 天剩余)`;
                }
            }

            const detailText = `
👤 *您的账号状态*: \`${user.username}\`
------------------
• 身份: ${binding ? '已绑定 WSS 账号' : '试用账号'}
• 状态: ${statusEmoji} ${user.status_text || user.status}
• 总配额: ${quota}
• 已用流量: ${user.usage_gb.toFixed(2)} GB
• 剩余流量: ${remaining}
• 到期日: ${expiryStatus}
• 限速: ${formatRate(user.rate_kbps)}
            `;
            
            bot.sendMessage(msg.chat.id, detailText, { parse_mode: 'Markdown' });

        } catch (e) {
            bot.sendMessage(msg.chat.id, `❌ 查询失败: ${e.message}`);
        }
    });
    
    // 5. /apply | /trial (公共指令)
    bot.onText(/^\/(apply|trial)(?:@\w+)?(?:\s|$)/i, async (msg) => {
        const tg_id = msg.from.id;
        const tg_username = msg.from.username || 'N/A';
        
        try {
            const status = await getTrialStatus(tg_id);
            const binding = await getTgBinding(tg_id);

            if (binding) {
                 bot.sendMessage(msg.chat.id, "⚠️ **您的 Telegram ID 已绑定 WSS 账号**，无需申请试用。", { parse_mode: 'Markdown' });
                 return;
            }

            if (!status.enabled) {
                 bot.sendMessage(msg.chat.id, "❌ **抱歉，管理员已暂时关闭了试用账号申请功能。**", { parse_mode: 'Markdown' });
                 return;
            }
            
            // 1. 检查是否有待审批或已批准的请求 (current != null)
            if (status.current) {
                let statusText;
                if (status.current.status === 'pending') {
                    statusText = "您有一条申请正在等待管理员审批。请耐心等待。";
                } else if (status.current.status === 'approved' && status.current.username) {
                    const user = await getUserByUsername(status.current.username);
                    if (user) {
                         const creds = { username: user.username, password: '[HIDDEN]', expiryDate: user.expiration_date, quotaGb: user.quota_gb, rateKbps: user.rate_kbps, maxConnections: user.max_connections };
                        const configMsg = generateConfigMessage(creds);
                        await bot.sendMessage(tg_id, configMsg, { parse_mode: 'Markdown' });
                        statusText = `您的账号 \`${user.username}\` 已激活。最新的配置信息已重新发送给您。`;
                    } else {
                        statusText = "您的试用账号已批准，但系统用户不存在，请联系管理员处理。";
                    }
                } else if (status.current.status === 'approved' && !status.current.username) {
                     // 罕见情况：批准记录存在，但用户名丢失
                     statusText = "您的申请状态异常，请联系管理员。";
                }
                bot.sendMessage(msg.chat.id, `⚠️ ${statusText}`);
                return;
            }
            
            // 2. 检查尝试次数限制
            if (status.attempts >= status.max_attempts) {
                 bot.sendMessage(msg.chat.id, `❌ **您已达到最大申请次数限制** (${status.max_attempts} 次)。如需帮助，请联系管理员。`, { parse_mode: 'Markdown' });
                 return;
            }

            // 3. 添加新的申请记录，返回记录 ID
            const requestId = await addTrialRequest(tg_id, tg_username);

            if (status.auto_approve) {
                 // **自动审批流程**
                 const loadingMsg = await bot.sendMessage(msg.chat.id, "🎉 试用功能已开启自动审批。正在为您开通账号...", { parse_mode: 'Markdown' });
                 try {
                     // 使用 wss_panel.js 的核心函数创建用户
                     const creds = await createTrialUser(tg_id, tg_username, requestId);
                     const configMsg = generateConfigMessage(creds);
                     
                     // 私信配置
                     await bot.sendMessage(tg_id, configMsg, { parse_mode: 'Markdown' });
                     
                     bot.editMessageText(`✅ **恭喜！试用账号已自动为您开通！**配置信息已私发给您。`, {
                         chat_id: msg.chat.id,
                         message_id: loadingMsg.message_id,
                         parse_mode: 'Markdown'
                     });
                     
                     // 通知管理员 (非必要，但记录自动开通事件)
                     const autoApproveNotification = `🔔 *自动批准通知*：\n用户: @${tg_username} (ID: \`${tg_id}\`)\n账户 \`${creds.username}\` 已自动创建。`;
                     bot.sendMessage(adminId, autoApproveNotification, { parse_mode: 'Markdown' });

                 } catch(e) {
                     // 如果创建失败，将申请标记为已拒绝，避免用户卡住
                     await updateTrialRequestStatus(requestId, 'rejected', null);
                     bot.editMessageText(`❌ 自动开通失败: ${e.message}`, {
                         chat_id: msg.chat.id,
                         message_id: loadingMsg.message_id,
                         parse_mode: 'Markdown'
                     });
                 }
            } else {
                 // **手动审批流程**
                 // 通知管理员
                 const notificationMsg = `🔔 *新试用申请*：\n用户: @${tg_username} (ID: \`${tg_id}\`)\n\n请使用 \`/pending\` 命令进行审批。`;
                 bot.sendMessage(adminId, notificationMsg, { parse_mode: 'Markdown' });
                 
                 bot.sendMessage(msg.chat.id, "✅ 试用申请已成功提交，正在等待管理员手动审批。我们将在审批完成后私信您配置信息。");
            }


        } catch (e) {
            console.error(`[TG_BOT] 试用申请处理失败: ${e.message}`);
            bot.sendMessage(msg.chat.id, `❌ 申请失败: ${e.message}`);
        }
    });
    
    // =============================
    // [V11.0 NEW] Feature 1: 卡密兑换
    // =============================
    
    // 6. /redeem <card_code> (公共指令)
    bot.onText(/^\/redeem(?:\s+)?(.+)?$/i, async (msg, match) => {
        const tg_id = msg.from.id;
        const code = match[1] ? match[1].trim().toUpperCase() : null;
        
        if (!code) {
             bot.sendMessage(msg.chat.id, "⚠️ **格式错误。** 请发送 `/redeem <卡密代码>`", { parse_mode: 'Markdown' });
             return;
        }

        try {
            // 1. 查找绑定的 WSS 账号
            const binding = await getTgBinding(tg_id);
            if (!binding) {
                 bot.sendMessage(msg.chat.id, "❌ **请先绑定您的 WSS 账号。** 请发送 `/bind <user> <pass>`", { parse_mode: 'Markdown' });
                 return;
            }
            const username = binding.username;
            
            const loadingMsg = await bot.sendMessage(msg.chat.id, `⏳ 正在为账号 \`${username}\` 兑换卡密 \`${code}\`...`, { parse_mode: 'Markdown' });

            // 2. 兑换卡密
            const result = await redeemVoucher(code, username, tg_id);
            
            // 3. 构建成功消息
            let message = `🎉 **卡密兑换成功!**\n\n`;
            if (result.daysAdded > 0) {
                 message += `• 续期: ${result.daysAdded} 天\n`;
            }
            if (result.quotaAdded > 0) {
                 message += `• 增加流量: ${result.quotaAdded.toFixed(2)} GB (总配额: ${result.newQuota.toFixed(2)} GB)\n`;
            }
            message += `• 新到期日: ${result.newExpiry}`;
            
            bot.editMessageText(message, {
                chat_id: msg.chat.id,
                message_id: loadingMsg.message_id,
                parse_mode: 'Markdown'
            });

        } catch (e) {
            console.error(`[TG_BOT] 卡密兑换失败: ${e.message}`);
             bot.sendMessage(msg.chat.id, `❌ **兑换失败:** ${e.message}`, { reply_to_message_id: msg.message_id });
        }
    });
    
    // 7. /create_voucher <days> <quota_gb> (Admin ONLY)
    bot.onText(/^\/create[_]?voucher\s+(\d+)\s+([\d\.]+)/i, async (msg, match) => {
        if (!checkAdminPermission(msg)) return;
        
        const days = parseInt(match[1]);
        const quotaGb = parseFloat(match[2]);
        
        if (days <= 0 && quotaGb <= 0) {
             bot.sendMessage(msg.chat.id, "⚠️ **参数错误。** 天数或流量至少有一项大于 0。");
             return;
        }
        
        try {
            const code = await createVoucher(days, quotaGb);
            const message = `
🎉 **卡密创建成功!**
-----------------------
• 代码: \`${code}\` (点击复制)
• 天数: ${days} 天
• 流量: ${quotaGb} GB

*请妥善保管此卡密。*
            `;
            bot.sendMessage(msg.chat.id, message, { parse_mode: 'Markdown' });
        } catch(e) {
            bot.sendMessage(msg.chat.id, `❌ 卡密创建失败: ${e.message}`);
        }
    });
    
    // =============================
    // [V11.0 NEW] Feature 4: 账号绑定/解绑
    // =============================
    
    // 8. /bind <user> <pass> (公共指令)
    bot.onText(/^\/bind\s+(\S+)\s+(\S+)/i, async (msg, match) => {
        const tg_id = msg.from.id;
        const username = match[1];
        const password = match[2];
        
        try {
            await bindTgUser(tg_id, username, password);
            bot.sendMessage(msg.chat.id, `✅ **账号 \`${username}\` 绑定成功!**\n您现在可以使用 \`/my_status\` 查询状态。`, { parse_mode: 'Markdown' });
        } catch(e) {
            bot.sendMessage(msg.chat.id, `❌ **绑定失败:** ${e.message}`, { parse_mode: 'Markdown' });
        }
    });

    // 9. /unbind (公共指令)
    bot.onText(/^\/unbind(?:@\w+)?(?:\s|$)/i, async (msg) => {
        const tg_id = msg.from.id;
        
        try {
            await unbindTgUser(tg_id);
            bot.sendMessage(msg.chat.id, "✅ **账号解绑成功!**", { parse_mode: 'Markdown' });
        } catch(e) {
            bot.sendMessage(msg.chat.id, `❌ **解绑失败:** ${e.message}`, { parse_mode: 'Markdown' });
        }
    });


    // =============================
    // [V11.0 NEW] Feature 2: 管理员广播
    // =============================
    
    // 10. /broadcast <message> (Admin ONLY)
    bot.onText(/^\/broadcast\s+(.+)/i, async (msg, match) => {
        if (!checkAdminPermission(msg)) return;
        
        const message = match[1];
        
        try {
            const bindings = await getAllTgBindings();
            let count = 0;
            
            const loadingMsg = await bot.sendMessage(msg.chat.id, `⏳ 正在向 ${bindings.length} 个已绑定的用户广播消息...`);
            
            const broadcastMessage = `📢 *系统通知* 📢\n--------------------\n${message}`;

            for (const binding of bindings) {
                try {
                    await bot.sendMessage(binding.tg_id, broadcastMessage, { parse_mode: 'Markdown' });
                    await sleep(50); // 慢速发送，防止被 Telegram 限制
                    count++;
                } catch (e) {
                    console.warn(`[TG_BOT] 广播失败给 TG ID ${binding.tg_id}: ${e.message}`);
                }
            }
            
            bot.editMessageText(`✅ **广播完成!** 成功发送给 ${count} 个用户。`, {
                chat_id: msg.chat.id,
                message_id: loadingMsg.message_id,
                parse_mode: 'Markdown'
            });

        } catch (e) {
            bot.sendMessage(msg.chat.id, `❌ 广播失败: ${e.message}`);
        }
    });

    // =============================
    // [V11.0 NEW] Feature 3: 报警阈值设置
    // =============================
    
    // 11. /set_alarm <CPU%> (Admin ONLY)
    bot.onText(/^\/set[_]?alarm\s+(\d+)/i, async (msg, match) => {
        if (!checkAdminPermission(msg)) return;
        
        const threshold = parseInt(match[1]);
        
        if (threshold < 1 || threshold > 100) {
             bot.sendMessage(msg.chat.id, "⚠️ **参数错误。** CPU 报警阈值必须在 1-100 之间。");
             return;
        }
        
        try {
            await updateGlobalSetting('tg_alarm_threshold', threshold);
            bot.sendMessage(msg.chat.id, `✅ **CPU 报警阈值设置成功** 为 ${threshold}%。当平均 CPU 负载超过此值时，机器人会私信报警。`);
        } catch(e) {
             bot.sendMessage(msg.chat.id, `❌ 设置失败: ${e.message}`);
        }
    });

    
    // =============================
    // 试用功能管理指令 (管理员 ONLY - BUG FIX)
    // =============================
    
    // 12. /trial_status - 查看当前试用配置 (BUG FIX)
    bot.onText(/^\/trial[_]?status(?:@\w+)?(?:\s|$)/i, async (msg) => {
        if (!checkAdminPermission(msg)) return;
        
        // [V11.0 FIX] 直接从 globalTrialSettings (已修复键名) 读取
        const settings = globalTrialSettings;
        const statusText = `
⚙️ *试用功能当前配置*
---------------------------
• 申请总开关: ${settings.enabled ? '🟢 已开启' : '🔴 已关闭'}
• 自动审批: ${settings.auto_approve ? '🟢 开启 (无需手动审批)' : '🔴 关闭 (需要手动审批)'}
• 最大尝试次数: ${settings.max_attempts} 次
• 账号有效期: ${settings.days} 天
• 流量配额: ${settings.quota_gb} GB
• 速率限制: ${formatRate(settings.rate_kbps)}
• 并发连接数: ${settings.max_connections} 个

**使用 \`/trial_config <天> <GB> <KB/s> <并发>\` 进行设置。**
        `;
        bot.sendMessage(msg.chat.id, statusText, { parse_mode: 'Markdown' });
    });

    // 13. /enable_trial | /disable_trial (Admin ONLY - BUG FIX)
    bot.onText(/^\/(enable|disable)[_]?trial(?:@\w+)?(?:\s|$)/i, async (msg, match) => {
        if (!checkAdminPermission(msg)) return;
        const action = match[1];
        const enable = action === 'enable';
        
        // [V11.0 FIX] 使用统一的键名 'enabled'
        await updateGlobalSetting('enabled', enable ? 1 : 0);
        
        bot.sendMessage(msg.chat.id, enable 
            ? "✅ **试用申请功能已开启。**"
            : "❌ **试用申请功能已关闭。**", { parse_mode: 'Markdown' });
    });

    // 14. /enable_auto_approve | /disable_auto_approve (Admin ONLY - BUG FIX)
    bot.onText(/^\/(enable|disable)[_]?auto[_]?approve(?:@\w+)?(?:\s|$)/i, async (msg, match) => {
        if (!checkAdminPermission(msg)) return;
        const action = match[1];
        const enable = action === 'enable';
        
        // [V11.0 FIX] 使用统一的键名 'auto_approve'
        await updateGlobalSetting('auto_approve', enable ? 1 : 0);
        
        bot.sendMessage(msg.chat.id, enable 
            ? "✅ **自动审批功能已开启。**用户申请后将立即获得账号。"
            : "❌ **自动审批功能已关闭。**新的申请需要使用 `/pending` 手动审批。", { parse_mode: 'Markdown' });
    });
    
    // 15. /trial_config <days> <quota_gb> <rate_kbps> <max_conn> (Admin ONLY - BUG FIX)
    bot.onText(/^\/trial[_]?config\s+(\d+)\s+([\d\.]+)\s+(\d+)\s+(\d+)/i, async (msg, match) => {
        if (!checkAdminPermission(msg)) return;
        
        const [_, daysStr, quotaStr, rateStr, connStr] = match;
        const days = parseInt(daysStr);
        const quota = parseFloat(quotaStr);
        const rate = parseInt(rateStr);
        const conn = parseInt(connStr);
        
        if (isNaN(days) || isNaN(quota) || isNaN(rate) || isNaN(conn) || days < 1 || quota < 0 || rate < 0 || conn < 0) {
             bot.sendMessage(msg.chat.id, "⚠️ **参数格式或范围错误。**\n用法: `/trial_config <天数> <流量GB> <限速KB/s> <并发数>` (例如: `/trial_config 1 1.0 5120 2`)", { parse_mode: 'Markdown' });
             return;
        }

        try {
            // [V11.0 FIX] 使用统一的键名 'days', 'quota_gb'
            await updateGlobalSetting('days', days);
            await updateGlobalSetting('quota_gb', quota);
            await updateGlobalSetting('rate_kbps', rate);
            await updateGlobalSetting('max_connections', conn);
            
            bot.sendMessage(msg.chat.id, `✅ **试用账号参数设置成功!**\n天数: ${days} 天\n流量: ${quota} GB\n速率: ${formatRate(rate)}\n并发: ${conn} 个`, { parse_mode: 'Markdown' });
            
        } catch (e) {
            bot.sendMessage(msg.chat.id, `❌ 配置保存失败: ${e.message}`);
        }
    });


    // 16. /user, /add, /del, /reset, /restart (保持不变, 但 /add 逻辑需要优化)
    // ... [省略重复的 /status, /user, /add, /del, /reset, /restart 逻辑，假设它们在原文件中已正确实现]

    // 16.1 /user <username> - 查询用户 (Admin ONLY)
    bot.onText(/\/user (.+)/i, async (msg, match) => {
        if (!checkAdminPermission(msg)) return; 
        const username = match[1];

        try {
            const user = await db.get('SELECT * FROM users WHERE username = ?', username);
            if (!user) {
                bot.sendMessage(msg.chat.id, `❌ 用户 \`${username}\` 不存在。`, { parse_mode: 'Markdown' });
                return;
            }

            const statusEmoji = user.status === 'active' ? '✅' : (user.status === 'paused' ? '⏸' : '❌');
            const quota = user.quota_gb > 0 ? `${user.quota_gb} GB` : '无限';
            const limit = user.rate_kbps > 0 ? `${(user.rate_kbps/1024).toFixed(1)} MB/s` : '无限';
            const conn = user.max_connections > 0 ? user.max_connections : '无限';

            const detailText = `
👤 *用户详情*: \`${user.username}\`
------------------
状态: ${statusEmoji} ${user.status_text || user.status}
到期: ${user.expiration_date || '永不'}
流量: ${user.usage_gb.toFixed(2)} / ${quota}
限速: ${limit}
并发: ${conn} (当前: ${user.active_connections || 0})
Auth头: ${user.require_auth_header ? '需要' : '免认证'}
            `;
            bot.sendMessage(msg.chat.id, detailText, { parse_mode: 'Markdown' });

        } catch (e) {
            bot.sendMessage(msg.chat.id, `❌ 查询失败: ${e.message}`);
        }
    });

    // 16.2 /add - 添加用户 (Admin ONLY)
    bot.onText(/\/add (.+)/i, async (msg, match) => {
        if (!checkAdminPermission(msg)) return; 
        
        const params = match[1].split(' ');
        if (params.length < 2) {
            bot.sendMessage(msg.chat.id, "⚠️ 格式错误。\n用法: `/add 用户名 密码 [天数] [GB] [限速KB] [并发]`", { parse_mode: 'Markdown' });
            return;
        }

        const [username, password, daysStr, quotaStr, rateStr, connStr] = params;
        const days = parseInt(daysStr) || 365;
        const quotaGb = parseFloat(quotaStr) || 0;
        const rateKbps = parseInt(rateStr) || 0;
        const maxConn = parseInt(connStr) || 3;

        const loadingMsg = await bot.sendMessage(msg.chat.id, `⏳ 正在创建用户 ${username}...`);

        try {
            const existing = await db.get('SELECT username FROM users WHERE username = ?', username);
            if (existing) {
                throw new Error("用户已存在");
            }

            const shell = "/sbin/nologin";
            // 假设 safeRunCommand 存在于上下文中
            await safeRunCommand(['useradd', '-m', '-s', shell, username]);
            const chpasswdInput = `${username}:${password}`;
            await safeRunCommand(['chpasswd'], chpasswdInput);

            await safeRunCommand(['usermod', '-U', username]);

            const passwordHash = await bcrypt.hash(password, 12);
            const expiryDate = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
            
            await db.run(`INSERT INTO users (
                username, password_hash, created_at, status, expiration_date, 
                quota_gb, usage_gb, rate_kbps, max_connections, 
                require_auth_header, status_text, allow_shell
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              [
                  username, passwordHash, new Date().toISOString().slice(0, 19).replace('T', ' '),
                  'active', expiryDate, quotaGb, 0.0, rateKbps, maxConn, 
                  1, '启用 (Active)', 0
              ]
            );

            broadcastToFrontends({ type: 'users_changed' });
            if(logAction) await logAction("USER_ADD_BOT", "TG_BOT", `User ${username} created via Telegram.`);

            bot.editMessageText(`✅ *成功创建用户*\n\n👤 账号: \`${username}\`\n🔑 密码: \`${password}\`\n📅 到期: ${expiryDate}\n📊 配额: ${quotaGb || '∞'} GB`, {
                chat_id: msg.chat.id,
                message_id: loadingMsg.message_id,
                parse_mode: 'Markdown'
            });

        } catch (e) {
            await safeRunCommand(['userdel', '-r', username]).catch(() => {});
            bot.editMessageText(`❌ 创建失败: ${e.message}`, {
                chat_id: msg.chat.id,
                message_id: loadingMsg.message_id,
                parse_mode: 'Markdown'
            });
        }
    });

    // 16.3 /del - 删除用户 (Admin ONLY)
    bot.onText(/\/del (.+)/i, async (msg, match) => {
        if (!checkAdminPermission(msg)) return; 
        const username = match[1];
        
        try {
            const user = await db.get('SELECT username FROM users WHERE username = ?', username);
            if (!user) {
                bot.sendMessage(msg.chat.id, "❌ 用户不存在。");
                return;
            }

            await kickUserFromProxy(username);
            await safeRunCommand(['pkill', '-9', '-u', username]);
            await safeRunCommand(['userdel', '-r', username]);
            await db.run('DELETE FROM users WHERE username = ?', username);
            await db.run('DELETE FROM traffic_history WHERE username = ?', username);
            await db.run('DELETE FROM tg_bindings WHERE username = ?', username); // [V11.0 NEW]

            broadcastToFrontends({ type: 'users_changed' });
            if(logAction) await logAction("USER_DEL_BOT", "TG_BOT", `User ${username} deleted via Telegram.`);

            bot.sendMessage(msg.chat.id, `🗑 用户 \`${username}\` 已删除。`, { parse_mode: 'Markdown' });

        } catch (e) {
            bot.sendMessage(msg.chat.id, `❌ 删除失败: ${e.message}`);
        }
    });
    
    // 16.4 /reset - 重置用户流量 (Admin ONLY)
    bot.onText(/\/reset (.+)/i, async (msg, match) => {
        if (!checkAdminPermission(msg)) return; 
        const username = match[1];
        
        try {
            const user = await db.get('SELECT * FROM users WHERE username = ?', username);
            if (!user) {
                bot.sendMessage(msg.chat.id, "❌ 用户不存在。");
                return;
            }
            
            await db.run('BEGIN TRANSACTION');
            await db.run(`UPDATE users SET usage_gb = 0.0 WHERE username = ?`, username);
            await db.run(`DELETE FROM traffic_history WHERE username = ?`, username);
            await db.run('COMMIT');

            if (user.status === 'exceeded') {
                await db.run(`UPDATE users SET status = 'active', status_text = '启用 (Active)' WHERE username = ?`, username);
            }
            
            broadcastToFrontends({ type: 'users_changed' });
            if(logAction) await logAction("USER_TRAFFIC_RESET", "TG_BOT", `Traffic reset for ${username} via Telegram.`);

            bot.sendMessage(msg.chat.id, `🔄 用户 \`${username}\` 的流量已重置。`, { parse_mode: 'Markdown' });

        } catch (e) {
            await db.run('ROLLBACK').catch(() => {});
            bot.sendMessage(msg.chat.id, `❌ 重置失败: ${e.message}`);
        }
    });

    // 16.5 /restart - 重启服务 (Admin ONLY)
    bot.onText(/\/restart/i, async (msg) => {
        if (!checkAdminPermission(msg)) return; 
        
        bot.sendMessage(msg.chat.id, "⚠️ 正在重启 WSS Panel 服务，机器人将暂时下线...");
        
        setTimeout(async () => {
             await safeRunCommand(['systemctl', 'restart', 'wss_panel']);
        }, 1000);
    });
    
    // =============================
    // 回调查询处理器 (Inline Keyboard)
    // =============================

    bot.on('callback_query', async (query) => {
        const chatId = query.message.chat.id;
        const data = query.data;
        const adminTgId = query.from.id;
        
        if (adminTgId !== adminId) {
            bot.answerCallbackQuery(query.id, '⛔️ 权限不足');
            return;
        }

        const [action, requestIdToProcess] = data.split('_');
        
        if (!requestIdToProcess) {
            bot.answerCallbackQuery(query.id, '无效的请求 ID');
            return;
        }

        // 通过数据库记录 ID 获取请求
        const pendingRequest = await db.get('SELECT * FROM trial_requests WHERE id = ?', requestIdToProcess);

        if (!pendingRequest || pendingRequest.status !== 'pending') {
            bot.editMessageText(query.message.text + `\n\n⚠️ 申请已过期或已被处理。`, {
                chat_id: chatId,
                message_id: query.message.message_id,
                parse_mode: 'Markdown',
                reply_markup: { inline_keyboard: [] } // 移除按钮
            });
            bot.answerCallbackQuery(query.id, '申请状态已更改');
            return;
        }

        let resultMessage = '';

        if (action === 'approve') {
            bot.answerCallbackQuery(query.id, '正在创建用户...');
            try {
                // 使用 wss_panel.js 暴露的 createTrialUser 函数 (它会使用全局配置)
                const creds = await createTrialUser(pendingRequest.tg_id, pendingRequest.tg_username, pendingRequest.id);
                const configMsg = generateConfigMessage(creds);
                
                await bot.sendMessage(pendingRequest.tg_id, configMsg, { parse_mode: 'Markdown' });
                
                resultMessage = `✅ 已批准用户 \`${creds.username}\`，信息已发送给 ID \`${pendingRequest.tg_id}\`。`;
                
            } catch (e) {
                resultMessage = `❌ 批准失败 (TG ID: \`${pendingRequest.tg_id}\`): ${e.message}`;
                await updateTrialRequestStatus(pendingRequest.id, 'rejected', null); 
            }

        } else if (action === 'reject') {
            await updateTrialRequestStatus(pendingRequest.id, 'rejected', null);
            await bot.sendMessage(pendingRequest.tg_id, '❌ 您的试用申请已被管理员拒绝。');
            resultMessage = `❌ 已拒绝 ID \`${pendingRequest.tg_id}\` 的试用申请。`;
            await logAction("TRIAL_REJECT", "TG_BOT", `Trial request rejected for TG ID ${pendingRequest.tg_id}`);
            bot.answerCallbackQuery(query.id, '已拒绝申请');
        }
        
        // 更新管理面板中的消息，移除按钮
        bot.editMessageText(query.message.text + `\n\n--- *处理结果* ---\n${resultMessage}`, {
            chat_id: chatId,
            message_id: query.message.message_id,
            parse_mode: 'Markdown',
            reply_markup: { inline_keyboard: [] }
        });
    });

    // [V10.0.2 NEW] 未知消息/指令处理 (为非管理员提供反馈)
    bot.on('message', (msg) => {
        const is_admin = msg.from.id === adminId;
        const text = (msg.text || '').trim();
        
        // 匹配所有公共指令，包括可选的下划线和管理员指令 (新增的指令也包含在内)
        const is_handled_command = /^\/(start|help|apply|trial|my[_]?status|status|user|add|del|reset|restart|pending|enable[_]?trial|disable[_]?trial|enable[_]?auto[_]?approve|disable[_]?auto[_]?approve|trial[_]?status|trial[_]?config|bind|unbind|redeem|create[_]?voucher|broadcast|set[_]?alarm)(?:@\w+)?(?:\s|$)/i.test(text);
        
        // 排除 /bind /add /del /reset /redeem /broadcast /create_voucher /trial_config 等带参数的指令的开头匹配
        if (!is_admin && text.startsWith('/') && !is_handled_command) {
             bot.sendMessage(msg.chat.id, "⛔️ 权限不足或指令无法识别。请使用 /start 查看可用菜单。", {
                parse_mode: 'Markdown'
            });
        }
    });

    // 错误处理
    bot.on('polling_error', (error) => {
        if (error.code !== 'EFATAL') {
             console.error(`[TG_BOT] Polling Error: ${error.message}`);
        }
    });
}

module.exports = { initTelegramBot };
