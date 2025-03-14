// @ts-nocheck
/**
 * 域名管理系统 - DomainKeeper
 * 版本: 2.1.0
 */

// 配置常量
const CONFIG = {
  // 应用信息
  VERSION: "2.1.0",
  CUSTOM_TITLE: "域名管理",  
  // API配置
  CF_API_KEY: "",
  WHOIS_PROXY_URL: "",
  
  // 安全配置
  ACCESS_PASSWORD: "", // 可为空
  ADMIN_PASSWORD: "", // 不可为空
  
  // 存储配置
  KV_NAMESPACE: DOMAIN_INFO,
  
  // 缓存配置
  CACHE_TTL: 86400 * 7, // 7天缓存过期时间(秒)
  
  // 状态配置
  STATUS: {
    UNKNOWN: { color: '#808080', title: '未知状态' },
    URGENT: { color: '#ff0000', title: '紧急', days: 7 },
    WARNING: { color: '#ffa500', title: '警告', days: 30 },
    NOTICE: { color: '#ffff00', title: '注意', days: 90 },
    NORMAL: { color: '#00ff00', title: '正常' }
  }
};

// KV 命名空间绑定名称
const KV_NAMESPACE = CONFIG.KV_NAMESPACE;

// footerHTML
const footerHTML = `
  <footer style="
    position: fixed;
    left: 0;
    bottom: 0;
    width: 100%;
    background-color: #f8f9fa;
    color: #6c757d;
    text-align: center;
    padding: 10px 0;
    font-size: 14px;
  ">
    Powered by DomainKeeper v${CONFIG.VERSION} <span style="margin: 0 10px;">|</span> © 2025 lbyan. All rights reserved.
  </footer>
`;

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
});

/**
 * 处理所有请求的主函数
 * @param {Request} request - 请求对象
 * @returns {Promise<Response>} - 响应对象
 */
async function handleRequest(request) {
  try {
    // 清理KV中的错误内容
    await cleanupKV();
    const url = new URL(request.url);
    const path = url.pathname;

    // 路由映射表
    const routes = {
      "/": handleFrontend,
      "/admin": handleAdmin,
      "/api/update": handleApiUpdate,
      "/api/manual-query": handleManualQuery,
      "/login": handleLogin,
      "/admin-login": handleAdminLogin
    };

    // 精确匹配路由
    if (routes[path]) {
      return await routes[path](request);
    }
    
    // 处理前缀匹配路由
    if (path.startsWith("/whois/")) {
      const domain = path.split("/")[2];
      return await handleWhoisRequest(domain);
    }

    // 未找到匹配路由
    return new Response("Not Found", { 
      status: 404,
      headers: { 'Content-Type': 'text/plain' }
    });
  } catch (error) {
    console.error("Request handling error:", error);
    return new Response(`Server Error: ${error.message}`, { 
      status: 500,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
}
async function cleanupKV() {
  const list = await KV_NAMESPACE.list();
  for (const key of list.keys) {
    const value = await KV_NAMESPACE.get(key.name);
    if (value) {
      const { data } = JSON.parse(value);
      if (data.whoisError) {
        await KV_NAMESPACE.delete(key.name);
      }
    }
  }
}
async function handleManualQuery(request) {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const data = await request.json();
  const { domain, apiKey } = data;

  try {
    const whoisInfo = await fetchWhoisInfo(domain, apiKey);
    await cacheWhoisInfo(domain, whoisInfo);
    return new Response(JSON.stringify(whoisInfo), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

/**
 * 处理前台页面请求
 * @param {Request} request - 请求对象
 * @returns {Promise<Response>} - 响应对象
 */
async function handleFrontend(request) {
  try {
    const cookie = request.headers.get("Cookie");
    if (CONFIG.ACCESS_PASSWORD && (!cookie || !cookie.includes(`access_token=${CONFIG.ACCESS_PASSWORD}`))) {
      return Response.redirect(`${new URL(request.url).origin}/login`, 302);
    }

    console.log("Fetching Cloudflare domains info...");
    const domains = await fetchCloudflareDomainsInfo();
    
    console.log("Fetching domain info...");
    const domainsWithInfo = await fetchDomainInfo(domains);
    
    return new Response(generateHTML(domainsWithInfo, false), {
      headers: { 'Content-Type': 'text/html' },
    });
  } catch (error) {
    console.error("Frontend handling error:", error);
    return new Response(`Error loading frontend: ${error.message}`, { 
      status: 500,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
}


/**
 * 处理后台管理页面请求
 * @param {Request} request - 请求对象
 * @returns {Promise<Response>} - 响应对象
 */
async function handleAdmin(request) {
  try {
    const cookie = request.headers.get("Cookie");
    if (!cookie || !cookie.includes(`admin_token=${CONFIG.ADMIN_PASSWORD}`)) {
      return Response.redirect(`${new URL(request.url).origin}/admin-login`, 302);
    }

    const domains = await fetchCloudflareDomainsInfo();
    const domainsWithInfo = await fetchDomainInfo(domains);
    return new Response(generateHTML(domainsWithInfo, true), {
      headers: { 'Content-Type': 'text/html' },
    });
  } catch (error) {
    console.error("Admin handling error:", error);
    return new Response(`Error loading admin page: ${error.message}`, { 
      status: 500,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
}

/**
 * 处理前台登录请求
 * @param {Request} request - 请求对象
 * @returns {Promise<Response>} - 响应对象
 */
async function handleLogin(request) {
  try {
    if (request.method === "POST") {
      const formData = await request.formData();
      const password = formData.get("password");

      if (password === CONFIG.ACCESS_PASSWORD) {
        return new Response("Login successful", {
          status: 302,
          headers: {
            "Location": "/",
            "Set-Cookie": `access_token=${CONFIG.ACCESS_PASSWORD}; HttpOnly; Path=/; SameSite=Strict; Max-Age=86400`
          }
        });
      } else {
        return new Response(generateLoginHTML("前台登录", "/login", "密码错误，请重试。"), {
          headers: { "Content-Type": "text/html" },
          status: 401
        });
      }
    }
    
    return new Response(generateLoginHTML("前台登录", "/login"), {
      headers: { "Content-Type": "text/html" }
    });
  } catch (error) {
    console.error("Login handling error:", error);
    return new Response(`Login error: ${error.message}`, { 
      status: 500,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
}


/**
 * 处理后台登录请求
 * @param {Request} request - 请求对象
 * @returns {Promise<Response>} - 响应对象
 */
async function handleAdminLogin(request) {
  try {
    if (request.method === "POST") {
      const formData = await request.formData();
      const password = formData.get("password");

      if (password === CONFIG.ADMIN_PASSWORD) {
        return new Response("Admin login successful", {
          status: 302,
          headers: {
            "Location": "/admin",
            "Set-Cookie": `admin_token=${CONFIG.ADMIN_PASSWORD}; HttpOnly; Path=/; SameSite=Strict; Max-Age=86400`
          }
        });
      } else {
        return new Response(generateLoginHTML("后台登录", "/admin-login", "密码错误，请重试。"), {
          headers: { "Content-Type": "text/html" },
          status: 401
        });
      }
    }

    return new Response(generateLoginHTML("后台登录", "/admin-login"), {
      headers: { "Content-Type": "text/html" }
    });
  } catch (error) {
    console.error("Admin login handling error:", error);
    return new Response(`Admin login error: ${error.message}`, { 
      status: 500,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
}



/**
 * 处理API更新请求
 * @param {Request} request - 请求对象
 * @returns {Promise<Response>} - 响应对象
 */
async function handleApiUpdate(request) {
  try {
    // 验证请求方法
    if (request.method !== "POST") {
      return new Response(JSON.stringify({ success: false, error: "Method Not Allowed" }), { 
        status: 405,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 验证身份认证
    const auth = request.headers.get("Authorization");
    if (!auth || auth !== `Basic ${btoa(`:${CONFIG.ADMIN_PASSWORD}`)}`) {
      return new Response(JSON.stringify({ success: false, error: "Unauthorized" }), { 
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 解析请求数据
    const data = await request.json();
    const { action, domain, system, registrar, registrationDate, expirationDate } = data;
    
    // 验证必要参数
    if (!domain) {
      return new Response(JSON.stringify({ success: false, error: "Domain is required" }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 根据操作类型处理请求
    switch (action) {
      case 'delete':
        // 删除自定义域名
        await KV_NAMESPACE.delete(`whois_${domain}`);
        break;
        
      case 'update-whois':
        // 更新 WHOIS 信息
        const whoisInfo = await fetchWhoisInfo(domain);
        await cacheWhoisInfo(domain, whoisInfo);
        break;
        
      case 'add':
        // 验证添加域名所需的参数
        if (!system || !registrar || !registrationDate || !expirationDate) {
          return new Response(JSON.stringify({ 
            success: false, 
            error: "Missing required fields for domain addition" 
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        
        // 添加新域名
        const newDomainInfo = {
          domain,
          system,
          registrar,
          registrationDate,
          expirationDate,
          isCustom: true
        };
        await cacheWhoisInfo(domain, newDomainInfo);
        break;
        
        default:
          // 更新域名信息
          let domainInfo = await getCachedWhoisInfo(domain) || {};
          const isCustom = domainInfo.isCustom || false; // 保留现有的 isCustom 状态，默认为 false
          domainInfo = {
            ...domainInfo,
            registrar: registrar || domainInfo.registrar,
            registrationDate: registrationDate || domainInfo.registrationDate,
            expirationDate: expirationDate || domainInfo.expirationDate,
            isCustom: isCustom // 恢复 isCustom 状态
          };
          await cacheWhoisInfo(domain, domainInfo);
      }

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Error in handleApiUpdate:', error);
    return new Response(JSON.stringify({ success: false, error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}


/**
 * 从Cloudflare API获取域名信息
 * @returns {Promise<Array>} - 域名信息数组
 */
async function fetchCloudflareDomainsInfo() {
  try {
    console.log('Fetching domains from Cloudflare API...');
    
    const response = await fetch('https://api.cloudflare.com/client/v4/zones', {
      headers: {
        'Authorization': `Bearer ${CONFIG.CF_API_KEY}`,
        'Content-Type': 'application/json',
      },
      cf: {
        cacheTtl: 300, // 5分钟缓存
        cacheEverything: true
      }
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch domains from Cloudflare: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    if (!data.success) {
      throw new Error(`Cloudflare API request failed: ${data.errors?.[0]?.message || 'Unknown error'}`);
    }

    console.log(`Successfully fetched ${data.result.length} domains from Cloudflare`);
    
    return data.result.map(zone => ({
      domain: zone.name,
      registrationDate: new Date(zone.created_on).toISOString().split('T')[0],
      system: 'Cloudflare',
    }));
  } catch (error) {
    console.error('Error fetching Cloudflare domains:', error);
    // 返回空数组而不是抛出错误，这样即使Cloudflare API失败，系统仍然可以显示自定义域名
    return [];
  }
}


/**
 * 获取所有域名信息，包括Cloudflare域名和自定义域名
 * @param {Array} domains - Cloudflare域名数组
 * @returns {Promise<Array>} - 所有域名信息数组
 */
async function fetchDomainInfo(domains) {
  try {
    console.log('Fetching all domain information...');
    const result = [];
    const domainMap = new Map(); // 用于去重

    // 获取所有自定义域名信息
    const allDomainKeys = await KV_NAMESPACE.list({ prefix: 'whois_' });
    console.log(`Found ${allDomainKeys.keys.length} domain keys in KV storage`);
    
    // 并行获取所有域名数据
    const allDomains = await Promise.all(allDomainKeys.keys.map(async (key) => {
      try {
        const value = await KV_NAMESPACE.get(key.name);
        if (!value) return null;
        
        const parsedValue = JSON.parse(value);
        return parsedValue.data;
      } catch (error) {
        console.error(`Error retrieving data for ${key.name}:`, error);
        return null;
      }
    }));

    // 过滤掉无效的域名数据，只保留自定义域名
    const validCustomDomains = allDomains.filter(d => d && d.isCustom);
    console.log(`Found ${validCustomDomains.length} valid custom domains`);

    // 合并 Cloudflare 域名和自定义域名，确保域名唯一性
    const mergedDomains = [...domains, ...validCustomDomains];
    
    // 批量处理域名信息，提高性能
    const domainPromises = mergedDomains.map(async (domain) => {
      if (!domain) return null; // 跳过无效的域名数据
      
      const domainKey = domain.domain || domain;
      if (domainMap.has(domainKey)) return null; // 跳过重复域名
      domainMap.set(domainKey, true);
      
      let domainInfo = { ...domain };
      const cachedInfo = await getCachedWhoisInfo(domainKey);
      
      if (cachedInfo) {
        // 使用缓存数据
        domainInfo = { ...domainInfo, ...cachedInfo };
      } else if (!domainInfo.isCustom && domainInfo.domain && 
                domainInfo.domain.split('.').length === 2 && 
                CONFIG.WHOIS_PROXY_URL) {
        // 只为顶级域名获取WHOIS信息
        try {
          const whoisInfo = await fetchWhoisInfo(domainInfo.domain);
          domainInfo = { ...domainInfo, ...whoisInfo };
          
          // 只缓存有效的WHOIS信息
          if (!whoisInfo.whoisError) {
            await cacheWhoisInfo(domainInfo.domain, whoisInfo);
          }
        } catch (error) {
          console.error(`Error fetching WHOIS info for ${domainInfo.domain}:`, error);
          domainInfo.whoisError = error.message;
        }
      }
      
      return domainInfo;
    });
    
    // 等待所有域名处理完成
    const processedDomains = await Promise.all(domainPromises);
    
    // 过滤掉无效结果并返回
    return processedDomains.filter(Boolean);
  } catch (error) {
    console.error('Error in fetchDomainInfo:', error);
    // 返回空数组而不是抛出错误，确保页面仍然可以加载
    return [];
  }
}


/**
 * 处理WHOIS查询请求
 * @param {string} domain - 要查询的域名
 * @returns {Promise<Response>} - 响应对象
 */
async function handleWhoisRequest(domain) {
  try {
    if (!domain) {
      throw new Error('Domain parameter is required');
    }
    
    console.log(`Handling WHOIS request for domain: ${domain}`);
    
    // 构建WHOIS API请求URL
    const whoisUrl = `${CONFIG.WHOIS_PROXY_URL}/whois/${domain}`;
    console.log(`Fetching WHOIS data from: ${whoisUrl}`);
    
    // 发送请求并设置超时
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10秒超时
    
    const response = await fetch(whoisUrl, {
      signal: controller.signal,
      cf: {
        cacheTtl: 3600, // 1小时缓存
        cacheEverything: true
      }
    }).finally(() => clearTimeout(timeoutId));

    if (!response.ok) {
      throw new Error(`WHOIS API responded with status: ${response.status} ${response.statusText}`);
    }

    const whoisData = await response.json();
    
    // 返回成功响应
    return new Response(JSON.stringify({
      error: false,
      rawData: whoisData.rawData
    }), {
      headers: { 
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=3600'
      }
    });
  } catch (error) {
    console.error(`Error fetching WHOIS data for ${domain}:`, error);
    
    // 返回错误响应，但保持200状态码以便前端处理
    return new Response(JSON.stringify({
      error: true,
      message: `Failed to fetch WHOIS data for ${domain}. Error: ${error.message}`
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

/**
 * 获取域名的WHOIS信息
 * @param {string} domain - 要查询的域名
 * @param {string|null} apiKey - 可选的API密钥
 * @param {number} timeout - 请求超时时间(毫秒)，默认10秒
 * @param {number} retries - 请求失败重试次数，默认0
 * @returns {Promise<Object>} - 包含域名注册商、注册日期和到期日期的对象
 */
async function fetchWhoisInfo(domain, apiKey = null, timeout = 10000, retries = 0) {
  if (!domain) {
    console.error('Domain parameter is required');
    return createErrorResponse('Domain parameter is required');
  }

  console.log(`Fetching WHOIS info for domain: ${domain}${apiKey ? ' with API key' : ''}`);
  
  let currentTry = 0;
  let lastError = null;

  // 重试逻辑
  while (currentTry <= retries) {
    try {
      if (currentTry > 0) {
        console.log(`Retry attempt ${currentTry} for domain ${domain}`);
      }

      // 构建请求URL
      let url = `${CONFIG.WHOIS_PROXY_URL}/whois/${domain}`;
      if (apiKey) {
        url += `?apiKey=${encodeURIComponent(apiKey)}`;
      }

      // 设置请求超时
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      // 发送请求
      const response = await fetch(url, {
        signal: controller.signal,
        cf: {
          cacheTtl: 3600, // 1小时缓存
          cacheEverything: true
        }
      }).finally(() => clearTimeout(timeoutId));

      // 检查响应状态
      if (!response.ok) {
        throw new Error(`WHOIS proxy responded with status: ${response.status} ${response.statusText}`);
      }

      // 解析响应数据
      const whoisData = await response.json();
      
      // 记录原始响应数据（仅在开发环境或调试时使用）
      if (whoisData) {
        console.log(`Successfully fetched WHOIS data for ${domain}`);
        // 仅记录关键字段，避免日志过大
        console.log('WHOIS data fields:', Object.keys(whoisData).join(', '));
      }

      // 处理响应数据
      if (whoisData && (whoisData.registrar || whoisData.creationDate || whoisData.expirationDate)) {
        return {
          registrar: whoisData.registrar || 'Unknown',
          registrationDate: formatDate(whoisData.creationDate) || 'Unknown',
          expirationDate: formatDate(whoisData.expirationDate) || 'Unknown'
        };
      } else if (whoisData && whoisData.rawData) {
        // 尝试从原始数据中提取信息
        console.log('Using rawData to extract WHOIS information');
        return extractWhoisInfoFromRawData(whoisData.rawData, domain);
      } else {
        console.warn(`Incomplete WHOIS data for ${domain}`);
        return createErrorResponse('Incomplete WHOIS data');
      }
    } catch (error) {
      lastError = error;
      console.error(`Error fetching WHOIS info for ${domain} (attempt ${currentTry + 1}/${retries + 1}):`, error);
      
      // 判断是否需要重试
      if (error.name === 'AbortError') {
        console.warn(`Request timeout for ${domain}`);
      } else if (!navigator.onLine) {
        console.warn('Network appears to be offline');
      }
      
      // 如果还有重试次数，则继续
      if (currentTry < retries) {
        currentTry++;
        // 指数退避策略
        const delay = Math.min(1000 * Math.pow(2, currentTry), 8000);
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      
      // 已达到最大重试次数，返回错误响应
      return createErrorResponse(error.message);
    }
  }
  
  // 不应该到达这里，但以防万一
  return createErrorResponse(lastError ? lastError.message : 'Unknown error');
}

/**
 * 从原始WHOIS数据中提取关键信息
 * @param {string} rawData - 原始WHOIS数据
 * @param {string} domain - 域名
 * @returns {Object} - 提取的WHOIS信息
 */
function extractWhoisInfoFromRawData(rawData, domain) {
  if (!rawData) return createErrorResponse('No raw WHOIS data available');
  
  try {
    // 尝试提取注册商信息
    let registrar = 'Unknown';
    const registrarMatches = rawData.match(/Registrar:\s*([^\n]+)/i) || 
                            rawData.match(/Sponsoring Registrar:\s*([^\n]+)/i);
    if (registrarMatches && registrarMatches[1]) {
      registrar = registrarMatches[1].trim();
    }
    
    // 尝试提取创建日期
    let creationDate = null;
    const creationMatches = rawData.match(/Creation Date:\s*([^\n]+)/i) || 
                           rawData.match(/Registered on:\s*([^\n]+)/i) ||
                           rawData.match(/Registration Date:\s*([^\n]+)/i);
    if (creationMatches && creationMatches[1]) {
      creationDate = creationMatches[1].trim();
    }
    
    // 尝试提取过期日期
    let expirationDate = null;
    const expirationMatches = rawData.match(/Expir\w+ Date:\s*([^\n]+)/i) ||
                             rawData.match(/Registry Expiry Date:\s*([^\n]+)/i);
    if (expirationMatches && expirationMatches[1]) {
      expirationDate = expirationMatches[1].trim();
    }
    
    return {
      registrar: registrar,
      registrationDate: formatDate(creationDate) || 'Unknown',
      expirationDate: formatDate(expirationDate) || 'Unknown'
    };
  } catch (error) {
    console.error(`Error extracting WHOIS info from raw data for ${domain}:`, error);
    return createErrorResponse('Failed to parse raw WHOIS data');
  }
}

/**
 * 创建标准错误响应对象
 * @param {string} errorMessage - 错误消息
 * @returns {Object} - 标准错误响应对象
 */
function createErrorResponse(errorMessage) {
  return {
    registrar: 'Unknown',
    registrationDate: 'Unknown',
    expirationDate: 'Unknown',
    whoisError: errorMessage
  };
}

function formatDate(dateString) {
  // 如果输入为空，直接返回null
  if (!dateString) return null;
  
  // 尝试创建日期对象
  const date = new Date(dateString);
  
  // 检查日期是否有效
  if (isNaN(date.getTime())) {
    // 无效日期，返回原始字符串
    return dateString;
  }
  
  // 返回YYYY-MM-DD格式的日期字符串
  return date.toISOString().split('T')[0];
}



async function getCachedWhoisInfo(domain) {
  const cacheKey = `whois_${domain}`;
  const cachedData = await KV_NAMESPACE.get(cacheKey);
  if (cachedData) {
    const { data, timestamp } = JSON.parse(cachedData);
    
    // 检查是否有错误内容，如果有，删除它
    if (data.whoisError) {
      await KV_NAMESPACE.delete(cacheKey);
      return null;
    }
    
    // 检查缓存是否过期 (使用CONFIG.CACHE_TTL配置，默认7天)
    const cacheAge = Date.now() - timestamp;
    const cacheTtlMs = CONFIG.CACHE_TTL * 1000; // 转换为毫秒
    
    if (cacheAge > cacheTtlMs) {
      console.log(`Cache expired for domain ${domain}, age: ${Math.floor(cacheAge / 86400000)} days`);
      await KV_NAMESPACE.delete(cacheKey);
      return null;
    }
    
    return data;
  }
  return null;
}


/**
 * 缓存域名的WHOIS信息
 * @param {string} domain - 域名
 * @param {Object} whoisInfo - WHOIS信息对象
 * @returns {Promise<void>}
 */
async function cacheWhoisInfo(domain, whoisInfo) {
  const cacheKey = `whois_${domain}`;
  await KV_NAMESPACE.put(cacheKey, JSON.stringify({
    data: whoisInfo,
    timestamp: Date.now() // 记录缓存时间戳，用于后续判断缓存是否过期
  }));
  console.log(`WHOIS info cached for domain ${domain}, will expire in ${CONFIG.CACHE_TTL/86400} days`);
}


function generateLoginHTML(title, action, errorMessage = "") {
  return `
  <!DOCTYPE html>
  <html lang="zh-CN" class="light-mode">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#4CAF50">
    <title>${title} - ${CONFIG.CUSTOM_TITLE}</title>
     <style>
      /* 统一的颜色变量 - 使用RGB格式便于透明度调整 */
      :root {
        --primary-color: #4CAF50;
        --primary-color-rgb: 76, 175, 80;
        --error-color: #f44336;
        --error-color-rgb: 244, 67, 54;
        --success-color: #43a047;
        --success-color-rgb: 67, 160, 71;
        --card-bg: rgba(255, 255, 255, 0.95);
        --text-color: #333333;
        --text-color-secondary: #666666;
        --border-color: #dddddd;
        --input-bg: #f9f9f9;
        --input-border: #cccccc;
        --button-bg: var(--primary-color);
        --button-text: white;
        --button-hover-bg: var(--success-color);
        --focus-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.2);
        --box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        --transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
      }

      /* 暗黑模式下的颜色变量 */
      .dark-mode {
        --primary-color: #81c995;
        --primary-color-rgb: 129, 201, 149;
        --card-bg: rgba(45, 45, 45, 0.95);
        --text-color: #ffffff;
        --text-color-secondary: #bbbbbb;
        --border-color: #404040;
        --input-bg: rgba(255, 255, 255, 0.1);
        --input-border: #404040;
        --button-bg: #333333;
        --button-text: #ffffff;
        --button-hover-bg: #555555;
        --focus-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.3);
        --box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      }
      
      /* 自动检测系统暗黑模式 */
      @media (prefers-color-scheme: dark) {
        .light-mode:not(.dark-mode-override) {
          --primary-color: #81c995;
          --primary-color-rgb: 129, 201, 149;
          --card-bg: rgba(45, 45, 45, 0.95);
          --text-color: #ffffff;
          --text-color-secondary: #bbbbbb;
          --border-color: #404040;
          --input-bg: rgba(255, 255, 255, 0.1);
          --input-border: #404040;
          --button-bg: #333333;
          --button-text: #ffffff;
          --button-hover-bg: #555555;
          --focus-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.3);
          --box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
      }

      /* 动画效果 - 性能优化 */
      @keyframes gradientBG {
        0% {
          background-position: 0% 50%;
        }
        50% {
          background-position: 100% 50%;
        }
        100% {
          background-position: 0% 50%;
        }
      }

      @keyframes float {
        0% {
          transform: translatey(0px);
        }
        50% {
          transform: translatey(-20px);
        }
        100% {
          transform: translatey(0px);
        }
      }

      @keyframes fadeIn {
        from {
          opacity: 0;
          transform: translateY(-10px);
        }
        to {
          opacity: 1;
          transform: translateY(0);
        }
      }

      /* 页面通用样式 */
      body {
        margin: 0;
        padding: 0;
        min-height: 100vh;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: linear-gradient(-45deg, #ee7752, #e73c7e, #23a6d5, #23d5ab);
        background-size: 400% 400%;
        animation: gradientBG 15s ease infinite;
        position: relative;
        overflow: hidden;
        will-change: background-position;
        transition: var(--transition);
      }

      /* 动画背景形状 - 性能优化 */
      .animated-shapes {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 1;
        pointer-events: none;
      }

      .shape {
        position: absolute;
        border-radius: 50%;
        background: rgba(255, 255, 255, 0.1);
        animation: float 6s ease-in-out infinite;
        backdrop-filter: blur(5px);
        will-change: transform;
        transform: translateZ(0);
      }

      .shape:nth-child(1) {
        width: 100px;
        height: 100px;
        left: 10%;
        top: 20%;
        animation-delay: 0s;
      }

      .shape:nth-child(2) {
        width: 150px;
        height: 150px;
        right: 15%;
        top: 30%;
        animation-delay: -2s;
      }

      .shape:nth-child(3) {
        width: 80px;
        height: 80px;
        left: 20%;
        bottom: 20%;
        animation-delay: -4s;
      }

      .shape:nth-child(4) {
        width: 120px;
        height: 120px;
        right: 25%;
        bottom: 25%;
        animation-delay: -6s;
      }

      /* 登录容器 - 增强视觉效果和性能 */
      .login-container {
        background: var(--card-bg);
        padding: 2.5rem;
        border-radius: 20px;
        box-shadow: var(--box-shadow);
        width: 100%;
        max-width: 400px;
        margin: 1rem;
        position: relative;
        z-index: 2;
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.2);
        transform: translateZ(0);
        will-change: transform, opacity;
        animation: fadeIn 0.5s ease-out;
        transition: var(--transition);
      }
      
      /* 登录容器顶部装饰条 */
      .login-container::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 5px;
        background: var(--primary-color);
        border-radius: 20px 20px 0 0;
      }
      
      /* 暗黑模式切换按钮 */
      .mode-toggle {
        position: absolute;
        top: 15px;
        right: 15px;
        background: transparent;
        border: none;
        color: var(--text-color-secondary);
        cursor: pointer;
        font-size: 1.2rem;
        padding: 5px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: var(--transition);
        z-index: 3;
      }
      
      .mode-toggle:hover {
        background: rgba(var(--primary-color-rgb), 0.1);
      }
      
      .mode-toggle:focus {
        outline: none;
        box-shadow: var(--focus-shadow);
      }
      
      .sun-icon, .moon-icon {
        width: 20px;
        height: 20px;
      }
      
      .moon-icon {
        display: none;
      }

      /* 标题 */
      h1 {
        text-align: center;
        color: var(--text-color);
        margin-bottom: 1.5rem;
        font-size: 1.8rem;
        font-weight: 600;
        transition: var(--transition);
      }

      /* 表单 */
      form {
        display: flex;
        flex-direction: column;
        gap: 1.2rem;
      }

      /* 输入框 - 增强可访问性 */
      input {
        padding: 1rem;
        border: 2px solid var(--input-border);
        border-radius: 12px;
        font-size: 1rem;
        transition: var(--transition);
        background: var(--input-bg);
        color: var(--text-color);
        width: 100%;
        box-sizing: border-box;
      }

      input:focus {
        outline: none;
        border-color: var(--primary-color);
        box-shadow: var(--focus-shadow);
        transform: translateY(-2px);
      }
      
      /* 键盘焦点样式 */
      input:focus-visible {
        outline: 2px solid var(--primary-color);
        outline-offset: 1px;
      }

      /* 提交按钮 - 增强视觉反馈 */
      input[type="submit"] {
        background: var(--button-bg);
        color: var(--button-text);
        border: none;
        padding: 1rem;
        font-weight: 600;
        cursor: pointer;
        transition: var(--transition);
        border-radius: 12px;
        position: relative;
        overflow: hidden;
        will-change: transform;
      }

      input[type="submit"]::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(255, 255, 255, 0.1);
        transform: translateX(-100%);
        transition: transform 0.3s ease;
      }

      input[type="submit"]:hover {
        background: var(--button-hover-bg);
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
      }

      input[type="submit"]:hover::before {
        transform: translateX(0);
      }

      input[type="submit"]:active {
        transform: translateY(0);
      }

      input[type="submit"]:focus {
        box-shadow: var(--focus-shadow);
      }

      /* 错误消息 - 增强视觉反馈 */
      .error-message {
        color: var(--error-color);
        background: rgba(var(--error-color-rgb), 0.1);
        padding: 1rem;
        border-radius: 12px;
        text-align: center;
        margin-bottom: 1rem;
        border: 1px solid rgba(var(--error-color-rgb), 0.2);
        backdrop-filter: blur(5px);
        animation: shake 0.5s cubic-bezier(0.36, 0.07, 0.19, 0.97) both;
        transform: translateZ(0);
      }
      
      @keyframes shake {
        10%, 90% { transform: translateX(-1px); }
        20%, 80% { transform: translateX(2px); }
        30%, 50%, 70% { transform: translateX(-4px); }
        40%, 60% { transform: translateX(4px); }
      }

      /* 响应式布局 - 优化移动端体验 */
      @media (max-width: 480px) {
        .login-container {
          margin: 1rem;
          padding: 1.5rem;
          width: calc(100% - 2rem);
        }

        h1 {
          font-size: 1.5rem;
        }
        
        input {
          font-size: 16px; /* 防止iOS缩放 */
          padding: 0.8rem;
        }
        
        .shape {
          opacity: 0.5; /* 减少移动端视觉干扰 */
        }
      }

      /* 页脚 */
      .footer-wrapper {
        position: relative;
        z-index: 2;
        margin-top: 2rem;
        text-align: center;
        width: 100%;
      }
      
      footer {
        background: transparent !important;
        color: rgba(255, 255, 255, 0.8) !important;
        font-size: 0.9rem;
        padding: 1rem;
        transition: var(--transition);
      }
    </style>
  </head>
  <body>
    <div class="animated-shapes">
      <div class="shape"></div>
      <div class="shape"></div>
      <div class="shape"></div>
      <div class="shape"></div>
    </div>
    <div class="login-container">
      <button id="modeToggle" class="mode-toggle" aria-label="切换暗黑/明亮模式">
        <svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
        <svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
      </button>
      <h1>${title}</h1>
      ${errorMessage ? `<div class="error-message" role="alert">${errorMessage}</div>` : ''}
      <form method="POST" action="${action}">
        <div class="input-container">
          <input type="password" name="password" id="password" placeholder="请输入密码" required aria-label="密码">
        </div>
        <input type="submit" value="登录">
      </form>
    </div>
    <div class="footer-wrapper">
      ${footerHTML}
    </div>
    
    <script>
      // 暗黑/明亮模式切换
      const modeToggle = document.getElementById('modeToggle');
      const html = document.documentElement;
      const sunIcon = document.querySelector('.sun-icon');
      const moonIcon = document.querySelector('.moon-icon');
      
      // 检查本地存储的模式偏好
      const savedMode = localStorage.getItem('colorMode');
      if (savedMode === 'dark') {
        html.classList.add('dark-mode');
        sunIcon.style.display = 'none';
        moonIcon.style.display = 'block';
      }
      
      modeToggle.addEventListener('click', () => {
        html.classList.toggle('dark-mode');
        
        if (html.classList.contains('dark-mode')) {
          localStorage.setItem('colorMode', 'dark');
          sunIcon.style.display = 'none';
          moonIcon.style.display = 'block';
        } else {
          localStorage.setItem('colorMode', 'light');
          sunIcon.style.display = 'block';
          moonIcon.style.display = 'none';
        }
      });
    </script>
  </body>
  </html>
  `;
}


function generateHTML(domains, isAdmin) {
  const categorizedDomains = categorizeDomains(domains);

  console.log("Categorized domains:", categorizedDomains);
  const generateTable = (domainList, isCFTopLevel) => {
    if (!domainList || !Array.isArray(domainList)) {
      console.error('Invalid domainList:', domainList);
      return '';
    }
    return domainList.map(info => {
      const today = new Date();
      const expirationDate = new Date(info.expirationDate);
      const daysRemaining = info.expirationDate === 'Unknown' ? 'N/A' : Math.ceil((expirationDate - today) / (1000 * 60 * 60 * 24));
      const totalDays = info.registrationDate === 'Unknown' || info.expirationDate === 'Unknown' ? 'N/A' : Math.ceil((expirationDate - new Date(info.registrationDate)) / (1000 * 60 * 60 * 24));
      const progressPercentage = isNaN(daysRemaining) || isNaN(totalDays) ? 0 : 100 - (daysRemaining / totalDays * 100);
      const whoisErrorMessage = info.whoisError
        ? `<br><span style="color: red;">WHOIS错误: ${info.whoisError}</span><br><span style="color: blue;">建议：请检查域名状态或API配置</span>`
        : '';

      let operationButtons = '';
      if (isAdmin) {
        // 在 generateTable 函数中修改操作按钮的 HTML 代码
        if (isCFTopLevel) {
          operationButtons = `
    <button class="edit-btn" onclick="editDomain('${info.domain}', this)">编辑</button>
    <button class="update-btn" data-action="update-whois" data-domain="${info.domain}">更新WHOIS信息</button>
    <button class="query-btn" data-action="query-whois" data-domain="${info.domain}">查询WHOIS信息</button>
  `;
        } else {
          operationButtons = `
    <button class="edit-btn" onclick="editDomain('${info.domain}', this)">编辑</button>
    <button class="delete-btn" onclick="deleteDomain('${info.domain}')">删除</button>
  `;
        }
      }

      return `
        <tr data-domain="${info.domain}">
          <td class="status-column"><span class="status-dot" style="background-color: ${getStatusColor(daysRemaining)};" title="${getStatusTitle(daysRemaining)}"></span></td>
          <td class="domain-column" title="${info.domain}">${info.domain}</td>
          <td class="system-column" title="${info.system}">${info.system}</td>
          <td class="registrar-column editable" title="${info.registrar}${whoisErrorMessage}">${info.registrar}${whoisErrorMessage}</td>
          <td class="date-column editable" title="${info.registrationDate}">${info.registrationDate}</td>
          <td class="date-column editable" title="${info.expirationDate}">${info.expirationDate}</td>
          <td class="days-column" title="${daysRemaining}">${daysRemaining}</td>
          <td class="progress-column">
            <div class="progress-bar">
              <div class="progress" style="width: ${progressPercentage}%;" title="${progressPercentage.toFixed(2)}%"></div>
            </div>
          </td>
          ${isAdmin ? `<td class="operation-column">${operationButtons}</td>` : ''}
        </tr>
      `;
    }).join('');
  };

  const cfTopLevelTable = generateTable(categorizedDomains.cfTopLevel, true);
  const cfSecondLevelAndCustomTable = generateTable(categorizedDomains.cfSecondLevelAndCustom, false);

  const adminLink = isAdmin
    ? '<span>当前为后台管理页面</span> | <a href="/">返回前台</a>'
    : '<a href="/admin">进入后台管理</a>';

  return `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${CONFIG.CUSTOM_TITLE}${isAdmin ? ' - 后台管理' : ''}</title>
  <style>
    /* 统一的颜色变量 */
    :root {
      --primary-color: #4CAF50;
      --text-color: #333;
      --table-bg: #fff;
      --table-border: #ddd;
      --header-bg: #f2f2f2;
      --hover-bg: #f5f5f5;
      --progress-bg: #e0e0e0;
      --button-bg: #fff;
      --button-text: #333;
      --input-bg: #fff;
      --input-text: #333;
    }

    /* 暗黑模式样式 */
    [data-theme="dark"] {
      --bg-color: #1a1a1a;
      --text-color: #e0e0e0;
      --table-bg: #2d2d2d;
      --table-border: #404040;
      --header-bg: #333;
      --hover-bg: #404040;
      --progress-bg: #404040;
      --button-bg: #4a4a4a;
      --button-text: #fff;
      --input-bg: #333;
      --input-text: #fff;
    }

    /* 页面通用样式 */
    body {
      font-family: Arial, sans-serif;
      line-height: 1.6;
      margin: 0;
      padding: 20px;
      background-color: var(--bg-color);
      color: var(--text-color);
      transition: background-color 0.3s, color 0.3s;
    }

    /* 容器 */
    .container {
      margin: 0 auto;
      padding: 0 15px;
      padding-bottom: 60px; /* 根据页脚高度调整 */
      background-color: var(--table-bg);
    }

    /* 页脚 */
    footer {
      position: relative;
      left: 0;
      bottom: 0;
      width: 100%;
      background-color: var(--table-bg) !important;
      color: var(--text-color) !important;
    }

    /* 表格容器 */
    .table-wrapper {
      width: 100%;
      overflow-x: auto;
    }

    /* 表格标题 */
    h2.table-title {
      font-size: 1.5em;
      margin-top: 30px;
      margin-bottom: 15px;
      padding-bottom: 10px;
      border-bottom: 2px solid #ddd;
    }

    /* 分割线 */
    .table-separator {
      height: 2px;
      background-color: #eee;
      margin: 30px 0;
    }

    /* 表格 */
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 20px;
      table-layout: auto;
      background-color: var(--table-bg);
      border-color: var(--table-border);
    }

    /* 表格头部和单元格 */
    th, td {
      padding: 8px;
      text-align: left;
      border-bottom: 1px solid #ddd;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    /* 表格头部 */
    th {
      background-color: var(--header-bg);
      font-weight: bold;
    }

    /* 表格行悬停效果 */
    tr:hover {
      background-color: var(--hover-bg);
    }

    /* 状态列 */
    .status-column { width: 30px; min-width: 30px; max-width: 50px; }

    /* 域名列 */
    .domain-column { min-width: 120px; max-width: 25%; }

    /* 系统和注册商列 */
    .system-column, .registrar-column { min-width: 80px; max-width: 15%; }

    /* 日期列 */
    .date-column { min-width: 90px; max-width: 12%; }

    /* 剩余天数列 */
    .days-column { min-width: 60px; max-width: 10%; }

    /* 进度列 */
    .progress-column { min-width: 100px; max-width: 20%; }

    /* 操作列 */
    .operation-column { min-width: 120px; max-width: 20%; }

    /* 状态点 */
    .status-dot {
      display: inline-block;
      width: 10px;
      height: 10px;
      border-radius: 50%;
    }

    /* 进度条 */
    .progress-bar {
      width: 100%;
      background-color: var(--progress-bg);
      border-radius: 5px;
      overflow: hidden;
    }

    /* 进度条内部 */
    .progress {
      height: 20px;
      background-color: #4CAF50;
      transition: width 0.5s ease-in-out;
    }

    /* 按钮 */
    button {
      padding: 5px 10px;
      margin: 2px;
      cursor: pointer;
      background-color: var(--button-bg);
      color: var(--button-text);
      border: none;
      border-radius: 4px;
      transition: background-color 0.3s;
    }

    /* 编辑按钮 */
    button.edit-btn {
      background-color: #4CAF50;
      color: white;
    }

    /* 更新按钮 */
    button.update-btn {
      background-color: #2196F3;
      color: white;
    }

    /* 查询按钮 */
    button.query-btn {
      background-color: #9C27B0;
      color: white;
    }

    /* 删除按钮 */
    button.delete-btn {
      background-color: #f44336;
      color: white;
    }

    /* 按钮悬停效果 */
    button:hover {
      opacity: 0.8;
    }

    /* 输入框 */
    input {
      background-color: var(--input-bg);
      color: var(--input-text);
      border: 1px solid var(--table-border);
      border-radius: 4px;
      padding: 5px;
    }

    /* 分区头部 */
    .section-header {
      font-weight: bold;
    }

    /* 分区头部单元格 */
    .section-header td {
      padding: 10px;
    }

    /* 响应式布局 */
    @media (max-width: 768px) {
      table {
        font-size: 12px;
      }

      th, td {
        padding: 6px;
      }

      .system-column, .registrar-column {
        display: none;
      }

      .operation-column {
        width: auto;
      }

      button {
        padding: 3px 6px;
        font-size: 12px;
      }

      .less-important-column {
        display: none;
      }
    }
  </style>
  </head>
  <body>
  <button class="theme-switch" id="themeSwitch" title="切换主题">
  🌓
</button>
    <div class="container">
        <h1>${CONFIG.CUSTOM_TITLE}${isAdmin ? ' - 后台管理' : ''}</h1>
        <div class="admin-link">${adminLink}</div>
  
        <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th class="status-column">状态</th>
              <th class="domain-column">域名</th>
              <th class="system-column">系统</th>
              <th class="registrar-column">注册商</th>
              <th class="date-column">注册日期</th>
              <th class="date-column">到期日期</th>
              <th class="days-column">剩余天数</th>
              <th class="progress-column">进度</th>
              ${isAdmin ? '<th class="operation-column">操作</th>' : ''}
            </tr>
          </thead>
          <tbody>
            <tr class="section-header"><td colspan="${isAdmin ? '9' : '8'}"><h2>CF顶级域名</h2></td></tr>
            ${cfTopLevelTable}
            <tr class="section-separator"><td colspan="${isAdmin ? '9' : '8'}"></td></tr>
            <tr class="section-header"><td colspan="${isAdmin ? '9' : '8'}"><h2>CF二级域名or自定义域名</h2></td></tr>
            ${cfSecondLevelAndCustomTable}
          </tbody>
        </table>
      </div>
  
      ${isAdmin ? `
        <div>
          <h2>添加CF二级域名or自定义域名</h2>
          <form id="addCustomDomainForm">
            <input type="text" id="newDomain" placeholder="域名" required>
            <input type="text" id="newSystem" placeholder="系统" required>
            <input type="text" id="newRegistrar" placeholder="注册商" required>
            <input type="date" id="newRegistrationDate" required>
            <input type="date" id="newExpirationDate" required>
            <button type="submit">添加</button>
          </form>
        </div>
      ` : ''}
    </div>
    <script>
    // 添加主题切换功能
    function setupThemeSwitch() {
      const themeSwitch = document.getElementById('themeSwitch');
      const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)');
      
      // 从本地存储获取主题设置
      const currentTheme = localStorage.getItem('theme') || 
        (prefersDarkScheme.matches ? 'dark' : 'light');
      
      // 应用初始主题
      document.documentElement.setAttribute('data-theme', currentTheme);
      
      // 更新主题图标
      updateThemeIcon(currentTheme);
      
      // 添加切换事件监听
      themeSwitch.addEventListener('click', () => {
        const newTheme = document.documentElement.getAttribute('data-theme') === 'dark' 
          ? 'light' 
          : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeIcon(newTheme);
        
        // 添加过渡动画
        document.body.classList.add('theme-transition');
        setTimeout(() => {
          document.body.classList.remove('theme-transition');
        }, 500);
      });
      
      // 监听系统主题变化
      prefersDarkScheme.addEventListener('change', (e) => {
        if (!localStorage.getItem('theme')) {
          const newTheme = e.matches ? 'dark' : 'light';
          document.documentElement.setAttribute('data-theme', newTheme);
          updateThemeIcon(newTheme);
        }
      });
    }

    function updateThemeIcon(theme) {
      const themeSwitch = document.getElementById('themeSwitch');
      themeSwitch.textContent = theme === 'dark' ? '🌞' : '🌓';
      themeSwitch.title = theme === 'dark' ? '切换到明亮模式' : '切换到暗黑模式';
      
      // 添加图标动画
      themeSwitch.classList.add('rotate-icon');
      setTimeout(() => {
        themeSwitch.classList.remove('rotate-icon');
      }, 500);
    }

    // 页面加载完成后初始化主题切换
    document.addEventListener('DOMContentLoaded', setupThemeSwitch);

      async function editDomain(domain, button) {
      const row = button.closest('tr');
      const cells = row.querySelectorAll('.editable');
      
      if (button.textContent === '编辑') {
        button.textContent = '保存';
        cells.forEach(cell => {
          const input = document.createElement('input');
          input.value = cell.textContent;
          cell.textContent = '';
          cell.appendChild(input);
        });
      } else {
        button.textContent = '编辑';
        const updatedData = {
          domain: domain,
          registrar: cells[0].querySelector('input').value,
          registrationDate: cells[1].querySelector('input').value,
          expirationDate: cells[2].querySelector('input').value
        };
    
        try {
          const response = await fetch('/api/update', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Basic ' + btoa(':${CONFIG.ADMIN_PASSWORD}')
            },
            body: JSON.stringify(updatedData)
          });
    
          if (response.ok) {
            cells.forEach(cell => {
              cell.textContent = cell.querySelector('input').value;
            });
            alert('更新成功');
          } else {
            throw new Error('更新失败');
          }
        } catch (error) {
          alert('更新失败: ' + error.message);
          location.reload();
        }
      }
    }
    
    async function deleteDomain(domain) {
      if (confirm('确定要删除这个域名吗？')) {
        try {
          const response = await fetch('/api/update', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Basic ' + btoa(':${CONFIG.ADMIN_PASSWORD}')
            },
            body: JSON.stringify({
              action: 'delete',
              domain: domain
            })
          });
    
          if (response.ok) {
            alert('删除成功');
            location.reload();
          } else {
            throw new Error('删除失败');
          }
        } catch (error) {
          alert('删除失败: ' + error.message);
        }
      }
    }
    
    document.addEventListener('click', function(event) {
      if (event.target.dataset.action === 'update-whois') {
        updateWhoisInfo(event.target.dataset.domain);
      } else if (event.target.dataset.action === 'query-whois') {
        queryWhoisInfo(event.target.dataset.domain);
      }
    });
    
    async function updateWhoisInfo(domain) {
      try {
        const response = await fetch('/api/update', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Basic ' + btoa(':${CONFIG.ADMIN_PASSWORD}')
          },
          body: JSON.stringify({
            action: 'update-whois',
            domain: domain
          })
        });
    
        if (response.ok) {
          alert('WHOIS信息更新成功');
          location.reload();
        } else {
          throw new Error('WHOIS信息更新失败');
        }
      } catch (error) {
        alert('WHOIS信息更新失败: ' + error.message);
      }
    }
    
    async function queryWhoisInfo(domain) {
      try {
        const response = await fetch('/whois/' + domain);
        const data = await response.json();
    
        if (data.error) {
          alert('查询WHOIS信息失败: ' + data.message);
        } else {
          alert('WHOIS信息：\\n' + data.rawData);
        }
      } catch (error) {
        alert('查询WHOIS信息失败: ' + error.message);
      }
    }

    ${isAdmin ? `
      document.getElementById('addCustomDomainForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // 获取表单元素
        const form = e.target;
        const submitButton = form.querySelector('button[type="submit"]');
        
        // 获取表单数据
        const formData = {
          domain: document.getElementById('newDomain').value.trim(),
          system: document.getElementById('newSystem').value.trim(),
          registrar: document.getElementById('newRegistrar').value.trim(),
          registrationDate: document.getElementById('newRegistrationDate').value,
          expirationDate: document.getElementById('newExpirationDate').value
        };
    
        // 验证表单数据
        if (!formData.domain) {
          showNotification('域名不能为空', 'error');
          return;
        }
    
        // 验证日期
        const regDate = new Date(formData.registrationDate);
        const expDate = new Date(formData.expirationDate);
        
        if (expDate <= regDate) {
          showNotification('到期日期必须晚于注册日期', 'error');
          return;
        }
    
        // 禁用提交按钮
        submitButton.disabled = true;
        submitButton.textContent = '添加中...';
    
        try {
          const response = await fetch('/api/update', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': 'Basic ' + btoa(':' + '${CONFIG.ADMIN_PASSWORD}')
            },
            body: JSON.stringify({
              action: 'add',
              ...formData
            })
          });
    
          const data = await response.json();
    
          if (data.success) {
            showNotification('添加成功');
            form.reset();
            setTimeout(() => location.reload(), 1000);
          } else {
            throw new Error(data.message || '添加失败');
          }
        } catch (error) {
          console.error('Error:', error);
          showNotification(error.message || '添加失败', 'error');
        } finally {
          submitButton.disabled = false;
          submitButton.textContent = '添加';
        }
      });
    
      // 添加通知函数
      function showNotification(message, type = 'success') {
        const notification = document.createElement('div');
        notification.className = \`notification \${type}\`;
        notification.textContent = message;
        
        // 添加样式
        notification.style.cssText = \`
          position: fixed;
          top: 20px;
          right: 20px;
          padding: 15px 25px;
          border-radius: 4px;
          color: white;
          background-color: \${type === 'success' ? '#4CAF50' : '#f44336'};
          z-index: 1000;
          animation: fadeIn 0.3s ease-in;
        \`;
    
        document.body.appendChild(notification);
    
        // 自动移除通知
        setTimeout(() => {
          notification.style.animation = 'fadeOut 0.5s ease-out';
          setTimeout(() => notification.remove(), 500);
        }, 3000);
      }
    
      // 添加必要的样式
      const style = document.createElement('style');
      style.textContent = \`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(-20px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes fadeOut {
          from { opacity: 1; transform: translateY(0); }
          to { opacity: 0; transform: translateY(-20px); }
        }
        #addCustomDomainForm input {
          margin: 5px;
          padding: 8px;
          border: 1px solid #ddd;
          border-radius: 4px;
        }
        #addCustomDomainForm button {
          margin: 5px;
          padding: 8px 16px;
          background-color: #4CAF50;
          color: white;
          border: none;
          border-radius: 4px;
          cursor: pointer;
        }
        #addCustomDomainForm button:disabled {
          background-color: #cccccc;
          cursor: not-allowed;
        }
      \`;
      document.head.appendChild(style);
    ` : ''}
    </script>
    ${footerHTML}
    </body>
  </html>
  `;
}


// Update the status helper functions to use CONFIG.STATUS instead:
function getStatusColor(daysRemaining) {
  if (isNaN(daysRemaining)) return CONFIG.STATUS.UNKNOWN.color;
  if (daysRemaining <= CONFIG.STATUS.URGENT.days) return CONFIG.STATUS.URGENT.color;
  if (daysRemaining <= CONFIG.STATUS.WARNING.days) return CONFIG.STATUS.WARNING.color;
  if (daysRemaining <= CONFIG.STATUS.NOTICE.days) return CONFIG.STATUS.NOTICE.color;
  return CONFIG.STATUS.NORMAL.color;
}

function getStatusTitle(daysRemaining) {
  if (isNaN(daysRemaining)) return CONFIG.STATUS.UNKNOWN.title;
  if (daysRemaining <= CONFIG.STATUS.URGENT.days) return CONFIG.STATUS.URGENT.title;
  if (daysRemaining <= CONFIG.STATUS.WARNING.days) return CONFIG.STATUS.WARNING.title;
  if (daysRemaining <= CONFIG.STATUS.NOTICE.days) return CONFIG.STATUS.NOTICE.title;
  return CONFIG.STATUS.NORMAL.title;
}

function categorizeDomains(domains) {
  if (!domains || !Array.isArray(domains)) {
    console.error('Invalid domains input:', domains);
    return { cfTopLevel: [], cfSecondLevelAndCustom: [] };
  }

  return domains.reduce((acc, domain) => {
    if (domain.system === 'Cloudflare' && domain.domain.split('.').length === 2) {
      acc.cfTopLevel.push(domain);
    } else {
      acc.cfSecondLevelAndCustom.push(domain);
    }
    return acc;
  }, { cfTopLevel: [], cfSecondLevelAndCustom: [] });
}
