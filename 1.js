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
  CF_API_KEY: "A0yVNlSDEPe4vjt6FbfKPAAaTd11sO_ZIxdEuZqH",
  WHOIS_PROXY_URL: "https://whois.lbyan.us.kg",

  // 安全配置
  ACCESS_PASSWORD: "", // 可为空
  ADMIN_PASSWORD: "lbyan", // 不可为空

  // 存储配置
  KV_NAMESPACE: DOMAIN_INFO,

  // 状态配置
  STATUS: {
    UNKNOWN: { color: '#808080', title: '未知状态' },
    URGENT: { color: '#ff0000', title: '紧急', days: 7 },
    WARNING: { color: '#ffa500', title: '警告', days: 30 },
    NOTICE: { color: '#ffff00', title: '注意', days: 90 },
    NORMAL: { color: '#00ff00', title: '正常' }
  },

  // HTTP响应头
  HEADERS: {
    JSON: { 'Content-Type': 'application/json' },
    HTML: { 'Content-Type': 'text/html' },
    PLAIN: { 'Content-Type': 'text/plain' }
  },

  // 缓存配置
  CACHE: {
    WHOIS_TTL: 3600, // WHOIS缓存时间（秒）
    KV_TTL: 315576000 // KV存储过期时间（10年）
  },

  // API请求配置
  API: {
    TIMEOUT: 10000, // 请求超时时间（毫秒）
    MAX_RETRIES: 3 // 最大重试次数
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
// 通用响应处理函数
function createResponse(data, status = 200, headers = CONFIG.HEADERS.JSON) {
  return new Response(
    typeof data === 'string' ? data : JSON.stringify(data),
    { status, headers }
  );
}

// 错误响应处理函数
function createErrorResponse(message, status = 500) {
  console.error(`Error: ${message}`);
  return createResponse(
    { success: false, error: message },
    status,
    CONFIG.HEADERS.JSON
  );
}

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
    return createResponse("Not Found", 404, CONFIG.HEADERS.PLAIN);
  } catch (error) {
    return createErrorResponse(error.message);
  }
}
async function cleanupKV() {
  try {
    const list = await KV_NAMESPACE.list();
    for (const key of list.keys) {
      try {
        const value = await KV_NAMESPACE.get(key.name);
        if (value) {
          const { data } = JSON.parse(value);
          // 只有当数据完全无效时才删除
          if (!data || Object.keys(data).length === 0) {
            await KV_NAMESPACE.delete(key.name);
            console.log(`Cleaned up invalid data for key: ${key.name}`);
          }
        }
      } catch (error) {
        console.error(`Error processing KV key ${key.name}:`, error);
      }
    }
  } catch (error) {
    console.error('Error during KV cleanup:', error);
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
// 通用认证检查函数
function checkAuth(request, isAdmin = false) {
  const cookie = request.headers.get("Cookie");
  const requiredPassword = isAdmin ? CONFIG.ADMIN_PASSWORD : CONFIG.ACCESS_PASSWORD;
  const tokenName = isAdmin ? 'admin_token' : 'access_token';
  
  return cookie && cookie.includes(`${tokenName}=${requiredPassword}`);
}

// 通用登录处理函数
async function handleLogin(request, isAdmin = false) {
  const loginType = isAdmin ? "后台登录" : "前台登录";
  const loginPath = isAdmin ? "/admin-login" : "/login";
  const redirectPath = isAdmin ? "/admin" : "/";
  const password = isAdmin ? CONFIG.ADMIN_PASSWORD : CONFIG.ACCESS_PASSWORD;
  const tokenName = isAdmin ? 'admin_token' : 'access_token';

  try {
    if (request.method === "POST") {
      const formData = await request.formData();
      const inputPassword = formData.get("password");

      if (inputPassword === password) {
        return createResponse("Login successful", 302, {
          "Location": redirectPath,
          "Set-Cookie": `${tokenName}=${password}; HttpOnly; Path=/; SameSite=Strict; Max-Age=86400`,
          ...CONFIG.HEADERS.HTML
        });
      } else {
        return createResponse(
          generateLoginHTML(loginType, loginPath, "密码错误，请重试。"),
          401,
          CONFIG.HEADERS.HTML
        );
      }
    }

    return createResponse(
      generateLoginHTML(loginType, loginPath),
      200,
      CONFIG.HEADERS.HTML
    );
  } catch (error) {
    console.error(`${loginType}处理错误:`, error);
    return createErrorResponse(`${loginType}错误: ${error.message}`);
  }
}

// 前台登录处理
async function handleFrontendLogin(request) {
  return handleLogin(request, false);
}

// 后台登录处理
async function handleAdminLogin(request) {
  return handleLogin(request, true);
}



/**
 * 处理API更新请求
 * @param {Request} request - 请求对象
 * @returns {Promise<Response>} - 响应对象
 */
// API请求验证函数
function validateApiRequest(request, requiredFields = []) {
  // 验证请求方法
  if (request.method !== "POST") {
    throw new Error("Method Not Allowed");
  }

  // 验证身份认证
  const auth = request.headers.get("Authorization");
  if (!auth || auth !== `Basic ${btoa(`:${CONFIG.ADMIN_PASSWORD}`)}`) {
    throw new Error("Unauthorized");
  }

  return true;
}

// 域名操作处理函数
const DomainOperations = {
  async delete(domain) {
    const domainInfo = await getCachedWhoisInfo(domain);
    if (domainInfo && domainInfo.isCustom) {
      await KV_NAMESPACE.delete(`whois_${domain}`);
      console.log(`Deleted custom domain: ${domain}`);
      return true;
    }
    console.log(`Attempted to delete non-custom domain: ${domain}`);
    return false;
  },

  async updateWhois(domain) {
    const whoisInfo = await fetchWhoisInfo(domain);
    await cacheWhoisInfo(domain, whoisInfo);
    return true;
  },

  async add(data) {
    const { domain, system, registrar, registrationDate, expirationDate } = data;
    if (!system || !registrar || !registrationDate || !expirationDate) {
      throw new Error("Missing required fields for domain addition");
    }

    const newDomainInfo = {
      domain,
      system,
      registrar,
      registrationDate,
      expirationDate,
      isCustom: true
    };
    await cacheWhoisInfo(domain, newDomainInfo);
    return true;
  },

  async update(data) {
    const { domain, registrar, registrationDate, expirationDate } = data;
    let domainInfo = await getCachedWhoisInfo(domain) || {};
    const isCustom = domainInfo.isCustom || false;

    domainInfo = {
      ...domainInfo,
      registrar: registrar || domainInfo.registrar,
      registrationDate: registrationDate || domainInfo.registrationDate,
      expirationDate: expirationDate || domainInfo.expirationDate,
      isCustom
    };
    await cacheWhoisInfo(domain, domainInfo);
    return true;
  }
};

async function handleApiUpdate(request) {
  try {
    validateApiRequest(request);
    const data = await request.json();
    const { action, domain } = data;

    if (!domain) {
      return createErrorResponse("Domain is required", 400);
    }

    let success = false;
    switch (action) {
      case 'delete':
        success = await DomainOperations.delete(domain);
        break;
      case 'update-whois':
        success = await DomainOperations.updateWhois(domain);
        break;
      case 'add':
        success = await DomainOperations.add(data);
        break;
      default:
        success = await DomainOperations.update(data);
    }

    return createResponse({ success });
  } catch (error) {
    console.error('Error in handleApiUpdate:', error);
    return createErrorResponse(error.message, 
      error.message === "Unauthorized" ? 401 :
      error.message === "Method Not Allowed" ? 405 : 500
    );
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
// 通用WHOIS请求处理函数
async function handleWhoisRequest(domain) {
  try {
    if (!domain) {
      return createErrorResponse('Domain parameter is required', 400);
    }

    console.log(`Handling WHOIS request for domain: ${domain}`);

    const whoisData = await fetchWhoisDataWithTimeout(domain);
    
    return createResponse({
      error: false,
      rawData: whoisData.rawData
    }, 200, {
      ...CONFIG.HEADERS.JSON,
      'Cache-Control': `public, max-age=${CONFIG.CACHE.WHOIS_TTL}`
    });
  } catch (error) {
    console.error(`Error fetching WHOIS data for ${domain}:`, error);
    return createResponse({
      error: true,
      message: `Failed to fetch WHOIS data for ${domain}. Error: ${error.message}`
    }, 200, CONFIG.HEADERS.JSON);
  }
}

// WHOIS数据获取函数
async function fetchWhoisDataWithTimeout(domain) {
  const whoisUrl = `${CONFIG.WHOIS_PROXY_URL}/whois/${domain}`;
  console.log(`Fetching WHOIS data from: ${whoisUrl}`);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), CONFIG.API.TIMEOUT);

  try {
    const response = await fetch(whoisUrl, {
      signal: controller.signal,
      cf: {
        cacheTtl: CONFIG.CACHE.WHOIS_TTL,
        cacheEverything: true
      }
    });

    if (!response.ok) {
      throw new Error(`WHOIS API responded with status: ${response.status} ${response.statusText}`);
    }

    return await response.json();
  } finally {
    clearTimeout(timeoutId);
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
  if (!dateString) return null;

  try {
    // 尝试创建日期对象
    const date = new Date(dateString);

    // 检查日期是否有效
    if (isNaN(date.getTime())) {
      return dateString;
    }

    // 考虑时区偏移，确保显示正确的日期
    const userTimezoneOffset = date.getTimezoneOffset() * 60000;
    const localDate = new Date(date.getTime() + userTimezoneOffset);

    // 返回 YYYY-MM-DD 格式
    return localDate.toISOString().split('T')[0];
  } catch (error) {
    console.error('Error formatting date:', error);
    return dateString;
  }
}


async function getCachedWhoisInfo(domain) {
  const cacheKey = `whois_${domain}`;
  try {
    const cachedData = await KV_NAMESPACE.get(cacheKey);
    if (cachedData) {
      const { data } = JSON.parse(cachedData);

      // 移除错误数据检查，保留数据
      if (data && Object.keys(data).length > 0) {
        return data;
      }
    }
  } catch (error) {
    console.error(`Error getting cached data for ${domain}:`, error);
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
  try {
    // 移除时间戳，直接存储数据
    await KV_NAMESPACE.put(cacheKey, JSON.stringify({
      data: whoisInfo
    }), {
      // 可选：设置极长的过期时间（比如10年）
      expirationTtl: 315576000 // 10年的秒数
    });
    console.log(`WHOIS info cached for domain ${domain}`);
  } catch (error) {
    console.error(`Error caching WHOIS info for ${domain}:`, error);
  }
}


function generateLoginHTML(title, action, errorMessage = "") {
  return `
  <!DOCTYPE html>
  <html lang="zh-CN">
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
        overflow: hidden;
        opacity: 0.8;
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
        padding: 3rem;
        border-radius: 24px;
        box-shadow: var(--box-shadow);
        width: 100%;
        max-width: 420px;
        margin: 1rem;
        position: relative;
        z-index: 2;
        backdrop-filter: blur(15px);
        border: 1px solid rgba(255, 255, 255, 0.25);
        transform: translateZ(0);
        will-change: transform, opacity;
        animation: fadeIn 0.6s ease-out;
        transition: var(--transition);
        overflow: hidden;
      }
      

      


      /* 标题 */
      h1 {
        text-align: center;
        color: var(--text-color);
        margin-bottom: 2rem;
        font-size: 2rem;
        font-weight: 700;
        transition: var(--transition);
        letter-spacing: 0.5px;
        position: relative;
        padding-bottom: 1rem;
      }

      h1::after {
        content: '';
        position: absolute;
        bottom: 0;
        left: 50%;
        transform: translateX(-50%);
        width: 60px;
        height: 4px;
        background: var(--primary-color);
        border-radius: 2px;
      }

      /* 表单 */
      form {
        display: flex;
        flex-direction: column;
        gap: 1.2rem;
      }

      /* 输入框 - 增强可访问性 */
      input {
        padding: 1.2rem;
        border: none;
        border-radius: 16px;
        font-size: 1.1rem;
        transition: var(--transition);
        background: var(--input-bg);
        color: var(--text-color);
        width: 100%;
        box-sizing: border-box;
        letter-spacing: 0.5px;
      }

      input:focus {
        outline: none;
        border: 1px solid var(--border-color);
        transform: translateY(-2px);
      }
      
      /* 键盘焦点样式 */
      input:focus-visible {
        outline: none;
      }

      /* 提交按钮 - 增强视觉反馈 */
      input[type="submit"] {
        background: linear-gradient(135deg, var(--button-bg), var(--button-hover-bg));
        color: var(--button-text);
        border: none;
        padding: 1.2rem;
        font-weight: 600;
        font-size: 1.1rem;
        cursor: pointer;
        transition: var(--transition);
        border-radius: 16px;
        position: relative;
        overflow: hidden;
        will-change: transform;
        letter-spacing: 1px;
        text-transform: uppercase;
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
        padding: 1.2rem;
        border-radius: 16px;
        text-align: center;
        margin-bottom: 1.5rem;
        border: 1px solid rgba(var(--error-color-rgb), 0.2);
        backdrop-filter: blur(8px);
        animation: shake 0.5s cubic-bezier(0.36, 0.07, 0.19, 0.97) both;
        transform: translateZ(0);
        font-weight: 500;
        box-shadow: 0 4px 12px rgba(var(--error-color-rgb), 0.1);
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
    

  </body>
  </html>
  `;
}


// 域名状态计算工具函数
const DomainUtils = {
  // 计算日期差异（天数）
  calculateDateDiff(date1, date2) {
    if (!date1 || !date2) return null;
    const d1 = new Date(date1);
    const d2 = new Date(date2);
    d1.setHours(0, 0, 0, 0);
    d2.setHours(0, 0, 0, 0);
    return Math.floor((d2 - d1) / (1000 * 60 * 60 * 24));
  },

  // 计算域名状态信息
  calculateDomainStatus(info) {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const status = {
      daysRemaining: 'N/A',
      totalDays: 'N/A',
      progressPercentage: 0
    };

    if (info.expirationDate !== 'Unknown') {
      status.daysRemaining = this.calculateDateDiff(today, info.expirationDate);

      if (info.registrationDate !== 'Unknown') {
        status.totalDays = this.calculateDateDiff(
          new Date(info.registrationDate),
          new Date(info.expirationDate)
        );

        if (status.totalDays > 0) {
          const elapsedDays = this.calculateDateDiff(
            new Date(info.registrationDate),
            today
          );
          status.progressPercentage = (elapsedDays / status.totalDays) * 100;
          status.progressPercentage = Math.max(0, Math.min(100, status.progressPercentage));
        }
      }
    }

    return status;
  }
};

function generateHTML(domains, isAdmin) {
  const categorizedDomains = categorizeDomains(domains);

  console.log("Categorized domains:", categorizedDomains);
  const generateTable = (domainList, isCFTopLevel) => {
    if (!domainList || !Array.isArray(domainList)) {
      console.error('Invalid domainList:', domainList);
      return '';
    }
    return domainList.map(info => {
      const status = DomainUtils.calculateDomainStatus(info);
      const { daysRemaining, totalDays, progressPercentage } = status;
      const whoisErrorMessage = info.whoisError
        ? `<br><span style="color: red;">WHOIS错误: ${info.whoisError}</span><br><span style="color: blue;">建议：请检查域名状态或API配置</span>`
        : '';

      let operationButtons = '';
      if (isAdmin) {
        // 在 generateTable 函数中修改操作按钮的 HTML 代码
        if (isCFTopLevel) {
          operationButtons = `
    <button class="edit-btn" onclick="editDomain('${info.domain}', this)"><i class="fas fa-edit"></i> 编辑</button>
    <button class="update-btn" data-action="update-whois" data-domain="${info.domain}"><i class="fas fa-sync-alt"></i> 更新WHOIS</button>
    <button class="query-btn" data-action="query-whois" data-domain="${info.domain}"><i class="fas fa-search"></i> 查询WHOIS</button>
  `;
        } else {
          operationButtons = `
    <button class="edit-btn" onclick="editDomain('${info.domain}', this)"><i class="fas fa-edit"></i> 编辑</button>
    <button class="delete-btn" onclick="deleteDomain('${info.domain}')"><i class="fas fa-trash-alt"></i> 删除</button>
  `;
        }
      }

      return `
        <tr data-domain="${info.domain}" role="row" aria-label="域名信息: ${info.domain}">
          <td class="status-column" role="cell" aria-label="状态"><span class="status-dot" style="background-color: ${getStatusColor(daysRemaining)};" title="${getStatusTitle(daysRemaining)}" role="img" aria-label="${getStatusTitle(daysRemaining)}"></span></td>
          <td class="domain-column" role="cell" aria-label="域名" title="${info.domain}">${info.domain}</td>
          <td class="system-column" role="cell" aria-label="系统" title="${info.system}">${info.system}</td>
          <td class="registrar-column editable" role="cell" aria-label="注册商" title="${info.registrar}${whoisErrorMessage}">${info.registrar}${whoisErrorMessage}</td>
          <td class="date-column editable" role="cell" aria-label="注册日期" title="${info.registrationDate}">${info.registrationDate}</td>
          <td class="date-column editable" role="cell" aria-label="到期日期" title="${info.expirationDate}">${info.expirationDate}</td>
          <td class="days-column" role="cell" aria-label="剩余天数" title="${daysRemaining}">${daysRemaining}</td>
          <td class="progress-column" role="cell" aria-label="进度">
            <div class="progress-bar" role="progressbar" aria-valuenow="${progressPercentage}" aria-valuemin="0" aria-valuemax="100">
              <div class="progress" style="width: ${progressPercentage}%;" title="${progressPercentage.toFixed(2)}%"></div>
            </div>
          </td>
          ${isAdmin ? `<td class="operation-column" role="cell" aria-label="操作">${operationButtons}</td>` : ''}
        </tr>
      `;
    }).join('');
  };

  const cfTopLevelTable = generateTable(categorizedDomains.cfTopLevel, true);
  const cfSecondLevelAndCustomTable = generateTable(categorizedDomains.cfSecondLevelAndCustom, false);

  const adminLink = isAdmin
    ? '<a href="/">返回前台</a>'
    : '<a href="/admin">进入后台管理</a>';

  return `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${CONFIG.CUSTOM_TITLE}${isAdmin ? ' - 后台管理' : ''}</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    /* 动态主题切换按钮 */
.theme-switch {
  position: fixed;
  top: 25px;
  right: 25px;
  width: 50px;
  height: 50px;
  border-radius: 50%;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  border: 2px solid rgba(255,255,255,0.2);
  cursor: pointer;
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  box-shadow: 0 4px 20px rgba(118, 75, 162, 0.3);
  transform-style: preserve-3d;
}

.theme-switch:hover {
  transform: rotate(15deg) scale(1.1);
  box-shadow: 0 8px 30px rgba(118, 75, 162, 0.5);
}

.theme-switch i {
  color: white;
  font-size: 1.6rem;
  transition: transform 0.3s ease;
}

@keyframes pulse-glow {
  0% { opacity: 0.8; }
  50% { opacity: 0.4; transform: scale(1.2); }
  100% { opacity: 0.8; }
}

.theme-switch:hover {
  transform: rotate(180deg);
  box-shadow: 0 6px 16px rgba(0, 0, 0, 0.2);
}

/* 主题切换动画 */
.theme-transition {
  transition: background-color 0.5s ease;
}

.rotate-icon {
  animation: rotate 0.5s ease-in-out;
}

@keyframes rotate {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

/* 通知组件样式 */
.notification {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px;
  border-radius: 12px;
  color: white;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  backdrop-filter: blur(8px);
  max-width: 450px;
  margin: 10px;
}

.notification-icon {
  width: 24px;
  height: 24px;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.2);
  display: flex;
  align-items: center;
  justify-content: center;
}

.notification-content {
  flex: 1;
  position: relative;
}

.notification-message {
  margin-bottom: 8px;
  font-weight: 500;
}

.notification-close {
  background: none;
  border: none;
  color: white;
  cursor: pointer;
  opacity: 0.8;
  transition: opacity 0.3s;
  padding: 0;
  font-size: 20px;
}

.notification-close:hover {
  opacity: 1;
}

.notification.success {
  background: linear-gradient(135deg, #43a047, #66bb6a);
}

.notification.error {
  background: linear-gradient(135deg, #e53935, #ef5350);
}

/* 页面标题样式 */
h1 {
  font-size: 2rem;
  font-weight: 600;
  margin-bottom: 1.5rem;
  background: var(--primary-gradient);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-align: center;
}

/* 管理链接样式 */
.admin-link {
  text-align: center;
  margin-bottom: 2rem;
}

.admin-link a {
  color: var(--primary-color);
  text-decoration: none;
  font-weight: 500;
  transition: var(--transition);
}

.admin-link a:hover {
  opacity: 0.8;
  text-decoration: underline;
}

    /* 统一的颜色变量 */
    :root {
      --primary-color: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
      --neon-effect: 0 0 15px rgba(99, 102, 241, 0.5);
      --glass-bg: rgba(255, 255, 255, 0.08);
      --text-color: #333;
      --table-bg: #fff;
      --table-border: #e0e0e0;
      --header-bg: #f5f5f5;
      --hover-bg: rgba(76, 175, 80, 0.05);
      --progress-bg: #e8f5e9;
      --button-bg: var(--primary-gradient);
      --button-text: #fff;
      --input-bg: #fff;
      --input-text: #333;
      --box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
      --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .table {
      backdrop-filter: blur(16px) saturate(180%);
      background: var(--glass-bg);
      border: 1px solid rgba(99, 102, 241, 0.3);
      box-shadow: var(--neon-effect);
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .table:hover {
      box-shadow: 0 0 25px rgba(99, 102, 241, 0.8);
    }

    .status-dot {
      box-shadow: var(--neon-effect);
      animation: pulse 2s infinite;
    }

    .progress {
      background: linear-gradient(90deg, #6366f1 0%, #8b5cf6 100%);
      box-shadow: inset 0 0 8px rgba(99, 102, 241, 0.3);
    }

    @keyframes pulse {
      0% { opacity: 0.8; }
      50% { opacity: 0.4; transform: scale(1.2); }
      100% { opacity: 0.8; }
    }

    tr {
      transition: transform 0.3s ease;
    }

    tr:hover {
      transform: perspective(500px) rotateX(5deg);
      background: linear-gradient(145deg, rgba(99, 102, 241, 0.1) 0%, rgba(139, 92, 246, 0.05) 100%);
    }

    /* 暗黑模式样式 */
    [data-theme="dark"] {
      --bg-color: #121212;
      --text-color: #e0e0e0;
      --table-bg: #1e1e1e;
      --table-border: #333;
      --header-bg: #252525;
      --hover-bg: rgba(76, 175, 80, 0.1);
      --progress-bg: #2e2e2e;
      --button-bg: var(--primary-gradient);
      --button-text: #fff;
      --input-bg: #252525;
      --input-text: #e0e0e0;
      --box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    }

    /* 按钮样式 */
    .edit-btn, .delete-btn, .update-btn, .query-btn {
      padding: 6px 12px;
      border: none;
      border-radius: 6px;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.3s ease;
      margin: 0 4px;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      color: white;
      background: var(--primary-gradient);
    }

    .edit-btn.save-mode {
      background: linear-gradient(135deg, #22c55e, #16a34a);
      transform: scale(1.05);
    }

    .edit-btn:hover {
      transform: translateY(-2px);
      box-shadow: var(--neon-effect);
    }

    .edit-btn.save-mode:hover {
      transform: translateY(-2px) scale(1.05);
      box-shadow: 0 0 15px rgba(34, 197, 94, 0.5);
    }

    /* 页面通用样式 */
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      line-height: 1.6;
      background-color: var(--bg-color);
      color: var(--text-color);
      transition: var(--transition);
      background: linear-gradient(135deg, #1a2980 0%, #26d0ce 100%);
      background-attachment: fixed;
      min-height: 100vh;
      margin: 0;
      padding: 0;
    }

    /* 容器 */
    .container {
      max-width: 1400px;
      margin: 0 auto;
      padding: 20px;
      background-color: var(--table-bg);
      border-radius: 12px;
      box-shadow: var(--box-shadow);
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

    /* 表格基础样式 */
    table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      margin-bottom: 1rem;
      background: var(--table-bg);
      border-radius: 8px;
      overflow: hidden;
      transition: var(--transition);
    }

    /* 表格行样式 */
    tr {
      transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      transform-origin: center;
      animation: tableFloat 3s ease-in-out infinite;
    }

    @keyframes tableFloat {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-5px); }
    }

    /* 表格行悬停效果 */
    tr:hover {
      background-color: var(--hover-bg);
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
      z-index: 1;
    }

    /* 表格单元格样式 */
    td, th {
      padding: 1rem;
      text-align: left;
      border-bottom: 1px solid var(--table-border);
      transition: var(--transition);
    }

    /* 表头样式 */
    thead tr {
      background-color: var(--header-bg);
      font-weight: 600;
    }

    /* 表格最后一行去除底部边框 */
    tr:last-child td {
      border-bottom: none;
    }

    /* 表格标题 */
    h2.table-title {
      font-size: 1.5em;
      margin-top: 30px;
      margin-bottom: 15px;
      padding-bottom: 10px;
      border-bottom: 2px solid var(--table-border);
    }

    /* 分割线 */
    .table-separator {
      height: 2px;
      background-color: var(--table-border);
      margin: 30px 0;
    }

    /* 表格 */
    table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      margin-bottom: 20px;
      border-radius: 8px;
      overflow: hidden;
      box-shadow: var(--box-shadow);
    }

    /* 表格头部和单元格 */
    th, td {
      padding: 12px 16px;
      text-align: left;
      border-bottom: 1px solid var(--table-border);
    }

    /* 表格头部 */
    th {
      background: var(--header-bg);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.85rem;
      letter-spacing: 0.5px;
    }

    /* 表格行悬停效果 */
    tr:hover {
      background-color: var(--hover-bg);
      transition: var(--transition);
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
      border-radius: 7px;
      overflow: hidden;
    }

    /* 进度条内部 */
    .progress {
      height: 20px;
      background-color: #4CAF50;
      transition: width 0.5s ease-in-out;
    }

    /* 按钮基础样式 */
    button {
      padding: 8px 16px;
      margin: 4px;
      cursor: pointer;
      color: var(--button-text);
      border: none;
      border-radius: 6px;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-weight: 500;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }

    button i {
      font-size: 0.9em;
      transition: transform 0.3s ease;
    }

    button:hover i {
      transform: scale(1.1);
    }

    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
    }

    button:active {
      transform: translateY(0);
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
    }

    /* 编辑按钮 */
    button.edit-btn {
      background: linear-gradient(135deg, #3b82f6, #60a5fa);
    }

    /* 更新按钮 */
    button.update-btn {
      background: linear-gradient(135deg, #10b981, #34d399);
    }

    /* 查询按钮 */
    button.query-btn {
      background: linear-gradient(135deg, #8b5cf6, #a78bfa);
    }

    /* 删除按钮 */
    button.delete-btn {
      background: linear-gradient(135deg, #ef4444, #f87171);
    }

    /* 按钮光效动画 */
    @keyframes shine {
      0% { transform: translateX(-100%) rotate(45deg); }
      100% { transform: translateX(100%) rotate(45deg); }
    }

    button::before {
      content: '';
      position: absolute;
      top: -50%;
      left: -50%;
      width: 200%;
      height: 200%;
      background: linear-gradient(45deg, transparent, rgba(255,255,255,0.3), transparent);
      transform: rotate(45deg);
      animation: shine 2s infinite cubic-bezier(0.4, 0, 0.2, 1);
      pointer-events: none;
    }

    /* 添加域名表单样式 */
    .add-domain-section {
      background: var(--glass-bg);
      border-radius: 16px;
      padding: 2rem;
      margin-bottom: 2rem;
      box-shadow: var(--box-shadow);
      border: 1px solid rgba(var(--primary-color-rgb), 0.1);
      transition: var(--transition);
    }

    .add-domain-section:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(var(--primary-color-rgb), 0.15);
    }

    .add-domain-section h2 {
      color: var(--text-color);
      font-size: 1.5rem;
      margin-bottom: 1.5rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }

    .form-group {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }

    .form-group label {
      color: var(--text-color);
      font-weight: 500;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .form-group input {
      background: var(--input-bg);
      border: 1px solid var(--table-border);
      border-radius: 8px;
      padding: 0.75rem 1rem;
      color: var(--input-text);
      font-size: 0.95rem;
      transition: var(--transition);
    }

    .form-group input:focus {
      border-color: var(--primary-color);
      box-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.1);
      outline: none;
    }

    .add-btn {
      background: var(--primary-gradient);
      color: white;
      border: none;
      border-radius: 8px;
      padding: 1rem 2rem;
      font-size: 1rem;
      font-weight: 500;
      cursor: pointer;
      transition: var(--transition);
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      width: 100%;
      max-width: 200px;
      margin: 0 auto;
    }

    .add-btn:hover {
      transform: translateY(-2px);
      box-shadow: var(--neon-effect);
    }

    .add-btn:active {
      transform: translateY(0);
    }

    .add-btn:disabled {
      background: #ccc;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }

    @media (max-width: 768px) {
      .add-domain-section {
        padding: 1.5rem;
      }

      .form-grid {
        grid-template-columns: 1fr;
      }

      .add-btn {
        width: 100%;
        max-width: none;
      }
    }
   

    /* 分区头部 */
    .section-header {
      font-weight: bold;
    }

    /* 分区头部单元格 */
    .section-header td {
      padding: 10px;
    }

    /* 响应式布局优化 */
    @media (max-width: 1024px) {
      .container { padding: 10px; }
      table { font-size: 14px; }
      th, td { padding: 8px; }
      .operation-column { width: 120px; }
      button { padding: 4px 8px; }
    }

    @media (max-width: 768px) {
      table { font-size: 13px; }
      .operation-column { width: 100px; }
      button { font-size: 12px; }
    }

    @media (max-width: 480px) {
      table { font-size: 12px; }
      th, td { padding: 6px; }
      .operation-column { width: auto; }
      button { padding: 3px 6px; }
      .progress-bar { height: 15px; }
      .add-domain-form input {
        font-size: 16px;
        padding: 8px 12px;
        margin: 5px 0;
        width: 100%;
        border: 1px solid #ccc;
        border-radius: 4px;
        background-color: var(--bg-color);
        color: var(--text-color);
      }
      .add-domain-form input::placeholder {
        color: var(--text-color-secondary);
        opacity: 0.7;
      }
      .add-domain-form .form-group {
        display: flex;
        flex-direction: column;
        gap: 10px;
      }
      .add-domain-form .add-btn {
        font-size: 16px;
        padding: 10px;
        margin-top: 10px;
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

        ${isAdmin ? `
        <div class="add-domain-section">
          <h2><i class="fas fa-plus-circle"></i> 添加CF二级域名or自定义域名</h2>
          <form id="addCustomDomainForm" class="add-domain-form">
            <div class="form-grid">
              <div class="form-group">
                <label for="newDomain">
                  <i class="fas fa-globe"></i> 域名
                </label>
                <input type="text" id="newDomain" placeholder="example.com" required>
              </div>
              <div class="form-group">
                <label for="newSystem">
                  <i class="fas fa-server"></i> 系统
                </label>
                <input type="text" id="newSystem" placeholder="例如: Cloudflare" required>
              </div>
              <div class="form-group">
                <label for="newRegistrar">
                  <i class="fas fa-building"></i> 注册商
                </label>
                <input type="text" id="newRegistrar" placeholder="例如: Cloudflare" required>
              </div>
              <div class="form-group">
                <label for="newRegistrationDate">
                  <i class="fas fa-calendar-plus"></i> 注册日期
                </label>
                <input type="date" id="newRegistrationDate" required>
              </div>
              <div class="form-group">
                <label for="newExpirationDate">
                  <i class="fas fa-calendar-times"></i> 到期日期
                </label>
                <input type="date" id="newExpirationDate" required>
              </div>
            </div>
            <button type="submit" class="add-btn">
              <i class="fas fa-plus"></i> 添加域名
            </button>
          </form>
        </div>
        ` : ''}
  
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
      themeSwitch.innerHTML = theme === 'dark' ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
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
      
      if (button.innerHTML.includes('编辑')) {
        button.innerHTML = '<i class="fas fa-save"></i> 保存';
        button.classList.add('save-mode');
        cells.forEach(cell => {
          const input = document.createElement('input');
          input.value = cell.textContent;
          cell.textContent = '';
          cell.appendChild(input);
        });
      } else {
        button.innerHTML = '<i class="fas fa-edit"></i> 编辑';
        button.classList.remove('save-mode');
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
        notification.innerHTML = \`
          <div class="notification-icon">
            \${type === 'success' ? '✓' : '✕'}
          </div>
          <div class="notification-content">
            <div class="notification-message">\${message}</div>
            <div class="notification-progress"></div>
          </div>
          <button class="notification-close">×</button>
        \`;
        
        // 添加样式
        notification.style.cssText = \`
          position: fixed;
          top: 20px;
          right: 20px;
          padding: 12px;
          border-radius: 8px;
          color: white;
          background-color: \${type === 'success' ? '#4CAF50' : '#f44336'};
          box-shadow: 0 4px 12px rgba(0,0,0,0.15);
          z-index: 1000;
          display: flex;
          align-items: center;
          gap: 12px;
          min-width: 300px;
          max-width: 450px;
          animation: slideIn 0.3s ease-out;
          backdrop-filter: blur(8px);
        \`;
    
        // 添加关闭按钮事件
        const closeBtn = notification.querySelector('.notification-close');
        if (closeBtn) {
          closeBtn.addEventListener('click', () => {
            notification.style.animation = 'slideOut 0.3s ease-out';
            setTimeout(() => notification.remove(), 300);
          });
        }

        // 添加进度条动画
        const progress = notification.querySelector('.notification-progress');
        if (progress) {
          progress.style.cssText = \`
            width: 100%;
            height: 3px;
            background: rgba(255,255,255,0.3);
            position: absolute;
            bottom: 0;
            left: 0;
            border-radius: 0 0 8px 8px;
          \`;

          // 创建进度条动画
          const progressBar = document.createElement('div');
          progressBar.style.cssText = \`
            height: 100%;
            background: rgba(255,255,255,0.8);
            width: 100%;
            border-radius: inherit;
            animation: progress 3s linear;
          \`;
          progress.appendChild(progressBar);
        }
    
        document.body.appendChild(notification);
    
        // 自动移除通知
        setTimeout(() => {
          notification.style.animation = 'slideOut 0.3s ease-out';
          setTimeout(() => notification.remove(), 300);
        }, 3000);
      }
    
      // 添加必要的样式
      const style = document.createElement('style');
      style.textContent = \`
        @keyframes slideIn {
          from { 
            opacity: 0;
            transform: translateX(100%);
          }
          to {
            opacity: 1;
            transform: translateX(0);
          }
        }

        @keyframes slideOut {
          from {
            opacity: 1;
            transform: translateX(0);
          }
          to {
            opacity: 0;
            transform: translateX(100%);
          }
        }

        @keyframes progress {
          from { width: 100%; }
          to { width: 0%; }
        }

        .notification {
          transition: all 0.3s ease;
        }

        .notification:hover {
          transform: translateY(-3px);
          box-shadow: 0 6px 16px rgba(0,0,0,0.2);
        }

        .notification-icon {
          display: flex;
          align-items: center;
          justify-content: center;
          width: 24px;
          height: 24px;
          border-radius: 50%;
          background: rgba(255,255,255,0.2);
          font-size: 14px;
        }

        .notification-content {
          flex: 1;
          position: relative;
        }

        .notification-message {
          margin-bottom: 6px;
          font-size: 14px;
          line-height: 1.4;
        }

        .notification-close {
          background: none;
          border: none;
          color: white;
          font-size: 18px;
          cursor: pointer;
          opacity: 0.7;
          transition: opacity 0.2s;
          padding: 0 4px;
        }

        .notification-close:hover {
          opacity: 1;
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
          transition: all 0.3s ease;
        }

        #addCustomDomainForm button:hover {
          background-color: #45a049;
          transform: translateY(-1px);
        }

        #addCustomDomainForm button:disabled {
          background-color: #cccccc;
          cursor: not-allowed;
          transform: none;
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