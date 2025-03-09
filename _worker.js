// @ts-nocheck
// 在文件顶部添加版本信息后台密码（不可为空）
const VERSION = "2.0";

// 自定义标题
const CUSTOM_TITLE = "域名管理";

// 在这里设置你的 Cloudflare API Token
const CF_API_KEY = "A0yVNlSDEPe4vjt6FbfKPAAaTd11sO_ZIxdEuZqH";

// 自建 WHOIS 代理服务地址
const WHOIS_PROXY_URL = "https://whois.lbyan.us.kg";


// 访问密码（可为空）
const ACCESS_PASSWORD = "lbyan";

// 后台密码（不可为空）
const ADMIN_PASSWORD = "lbyan";

// KV 命名空间绑定名称
const KV_NAMESPACE = DOMAIN_INFO;

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
    Powered by DomainKeeper v${VERSION} <span style="margin: 0 10px;">|</span> © 2025 bacon159. All rights reserved.
  </footer>
`;

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
});

async function handleRequest(request) {
  // 清理KV中的错误内容
  await cleanupKV();
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/api/manual-query") {
    return handleManualQuery(request);
  }

  if (path === "/") {
    return handleFrontend(request);
  } else if (path === "/admin") {
    return handleAdmin(request);
  } else if (path === "/api/update") {
    return handleApiUpdate(request);
  } else if (path === "/login") {
    return handleLogin(request);
  } else if (path === "/admin-login") {
    return handleAdminLogin(request);
  } else if (path.startsWith("/whois/")) {
    const domain = path.split("/")[2];
    return handleWhoisRequest(domain);
  } else {
    return new Response("Not Found", { status: 404 });
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

async function handleFrontend(request) {
  const cookie = request.headers.get("Cookie");
  if (ACCESS_PASSWORD && (!cookie || !cookie.includes(`access_token=${ACCESS_PASSWORD}`))) {
    return Response.redirect(`${new URL(request.url).origin}/login`, 302);
  }

  console.log("Fetching Cloudflare domains info...");
  const domains = await fetchCloudflareDomainsInfo();
  console.log("Cloudflare domains:", domains);

  console.log("Fetching domain info...");
  const domainsWithInfo = await fetchDomainInfo(domains);
  console.log("Domains with info:", domainsWithInfo);

  return new Response(generateHTML(domainsWithInfo, false), {
    headers: { 'Content-Type': 'text/html' },
  });
}


async function handleAdmin(request) {
  const cookie = request.headers.get("Cookie");
  if (!cookie || !cookie.includes(`admin_token=${ADMIN_PASSWORD}`)) {
    return Response.redirect(`${new URL(request.url).origin}/admin-login`, 302);
  }

  const domains = await fetchCloudflareDomainsInfo();
  const domainsWithInfo = await fetchDomainInfo(domains);
  return new Response(generateHTML(domainsWithInfo, true), {
    headers: { 'Content-Type': 'text/html' },
  });
}

async function handleLogin(request) {
  if (request.method === "POST") {
    const formData = await request.formData();
    const password = formData.get("password");

    console.log("Entered password:", password);
    console.log("Expected password:", ACCESS_PASSWORD);

    if (password === ACCESS_PASSWORD) {
      return new Response("Login successful", {
        status: 302,
        headers: {
          "Location": "/",
          "Set-Cookie": `access_token=${ACCESS_PASSWORD}; HttpOnly; Path=/; SameSite=Strict`
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
}


async function handleAdminLogin(request) {
  console.log("Handling admin login request");
  console.log("Request method:", request.method);

  if (request.method === "POST") {
    console.log("Processing POST request for admin login");
    const formData = await request.formData();
    console.log("Form data:", formData);
    const password = formData.get("password");
    console.log("Entered admin password:", password);
    console.log("Expected admin password:", ADMIN_PASSWORD);

    if (password === ADMIN_PASSWORD) {
      return new Response("Admin login successful", {
        status: 302,
        headers: {
          "Location": "/admin",
          "Set-Cookie": `admin_token=${ADMIN_PASSWORD}; HttpOnly; Path=/; SameSite=Strict`
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
}



async function handleApiUpdate(request) {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const auth = request.headers.get("Authorization");
  if (!auth || auth !== `Basic ${btoa(`:${ADMIN_PASSWORD}`)}`) {
    return new Response("Unauthorized", { status: 401 });
  }

  try {
    const data = await request.json();
    const { action, domain, system, registrar, registrationDate, expirationDate } = data;

    if (action === 'delete') {
      // 删除自定义域名
      await KV_NAMESPACE.delete(`whois_${domain}`);
    } else if (action === 'update-whois') {
      // 更新 WHOIS 信息
      const whoisInfo = await fetchWhoisInfo(domain);
      await cacheWhoisInfo(domain, whoisInfo);
    } else if (action === 'add') {
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
    } else {
      // 更新域名信息
      let domainInfo = await getCachedWhoisInfo(domain) || {};
      domainInfo = {
        ...domainInfo,
        registrar,
        registrationDate,
        expirationDate
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


async function fetchCloudflareDomainsInfo() {
  const response = await fetch('https://api.cloudflare.com/client/v4/zones', {
    headers: {
      'Authorization': `Bearer ${CF_API_KEY}`,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch domains from Cloudflare');
  }

  const data = await response.json();
  if (!data.success) {
    throw new Error('Cloudflare API request failed');
  }

  return data.result.map(zone => ({
    domain: zone.name,
    registrationDate: new Date(zone.created_on).toISOString().split('T')[0],
    system: 'Cloudflare',
  }));
}


async function fetchDomainInfo(domains) {
  const result = [];

  // 获取所有域名信息，包括自定义域名
  const allDomainKeys = await KV_NAMESPACE.list({ prefix: 'whois_' });
  const allDomains = await Promise.all(allDomainKeys.keys.map(async (key) => {
    const value = await KV_NAMESPACE.get(key.name);
    if (value) {
      try {
        const parsedValue = JSON.parse(value);
        return parsedValue.data;
      } catch (error) {
        console.error(`Error parsing data for ${key.name}:`, error);
        return null;
      }
    }
    return null;
  }));

  // 过滤掉无效的域名数据
  const validAllDomains = allDomains.filter(d => d && d.isCustom);

  // 合并 Cloudflare 域名和自定义域名
  const mergedDomains = [...domains, ...validAllDomains];

  for (const domain of mergedDomains) {
    if (!domain) continue; // 跳过无效的域名数据

    let domainInfo = { ...domain };

    const cachedInfo = await getCachedWhoisInfo(domain.domain || domain);
    if (cachedInfo) {
      domainInfo = { ...domainInfo, ...cachedInfo };
    } else if (!domainInfo.isCustom && domainInfo.domain && domainInfo.domain.split('.').length === 2 && WHOIS_PROXY_URL) {
      try {
        const whoisInfo = await fetchWhoisInfo(domainInfo.domain);
        domainInfo = { ...domainInfo, ...whoisInfo };
        if (!whoisInfo.whoisError) {
          await cacheWhoisInfo(domainInfo.domain, whoisInfo);
        }
      } catch (error) {
        console.error(`Error fetching WHOIS info for ${domainInfo.domain}:`, error);
        domainInfo.whoisError = error.message;
      }
    }

    result.push(domainInfo);
  }
  return result;
}


async function handleWhoisRequest(domain) {
  console.log(`Handling WHOIS request for domain: ${domain}`);

  try {
    console.log(`Fetching WHOIS data from: ${WHOIS_PROXY_URL}/whois/${domain}`);
    const response = await fetch(`${WHOIS_PROXY_URL}/whois/${domain}`);

    if (!response.ok) {
      throw new Error(`WHOIS API responded with status: ${response.status}`);
    }

    const whoisData = await response.json();
    console.log(`Received WHOIS data:`, whoisData);

    return new Response(JSON.stringify({
      error: false,
      rawData: whoisData.rawData
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error(`Error fetching WHOIS data for ${domain}:`, error);
    return new Response(JSON.stringify({
      error: true,
      message: `Failed to fetch WHOIS data for ${domain}. Error: ${error.message}`
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function fetchWhoisInfo(domain) {
  try {
    const response = await fetch(`${WHOIS_PROXY_URL}/whois/${domain}`);
    const whoisData = await response.json();

    console.log('Raw WHOIS proxy response:', JSON.stringify(whoisData, null, 2));

    if (whoisData) {
      return {
        registrar: whoisData.registrar || 'Unknown',
        registrationDate: formatDate(whoisData.creationDate) || 'Unknown',
        expirationDate: formatDate(whoisData.expirationDate) || 'Unknown'
      };
    } else {
      console.warn(`Incomplete WHOIS data for ${domain}`);
      return {
        registrar: 'Unknown',
        registrationDate: 'Unknown',
        expirationDate: 'Unknown',
        whoisError: 'Incomplete WHOIS data'
      };
    }
  } catch (error) {
    console.error('Error fetching WHOIS info:', error);
    return {
      registrar: 'Unknown',
      registrationDate: 'Unknown',
      expirationDate: 'Unknown',
      whoisError: error.message
    };
  }
}

function formatDate(dateString) {
  if (!dateString) return null;
  const date = new Date(dateString);
  return isNaN(date.getTime()) ? dateString : date.toISOString().split('T')[0];
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
    // 这里可以添加缓存过期检查，如果需要的话
    return data;
  }
  return null;
}


async function cacheWhoisInfo(domain, whoisInfo) {
  const cacheKey = `whois_${domain}`;
  await KV_NAMESPACE.put(cacheKey, JSON.stringify({
    data: whoisInfo,
    timestamp: Date.now()
  }));
}


function generateLoginHTML(title, action, errorMessage = "") {
  return `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title} - ${CUSTOM_TITLE}</title>
     <style>
      /* 统一的颜色变量 */
      :root {
        --primary-color: #4CAF50;
        --error-color: #f44336;
        --card-bg: rgba(255, 255, 255, 0.95);
        --text-color: #333333;
        --border-color: #dddddd;
        --input-bg: #f9f9f9;
        --input-border: #cccccc;
        --button-bg: var(--primary-color);
        --button-text: white;
        --button-hover-bg: #43a047;
      }

      /* 暗黑模式下的颜色变量 */
      @media (prefers-color-scheme: dark) {
        :root {
          --card-bg: rgba(45, 45, 45, 0.95);
          --text-color: #ffffff;
          --border-color: #404040;
          --input-bg: rgba(255, 255, 255, 0.1);
          --input-border: #404040;
          --button-bg: #333333;
          --button-text: #ffffff;
          --button-hover-bg: #555555;
        }
      }

      /* 动画效果 */
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
      }

      /* 动画背景形状 */
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

      /* 登录容器 */
      .login-container {
        background: var(--card-bg);
        padding: 2.5rem;
        border-radius: 20px;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        width: 100%;
        max-width: 400px;
        margin: 1rem;
        position: relative;
        z-index: 2;
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.2);
        transform: translateZ(0);
      }

      /* 标题 */
      h1 {
        text-align: center;
        color: var(--text-color);
        margin-bottom: 1.5rem;
        font-size: 1.8rem;
        font-weight: 600;
      }

      /* 表单 */
      form {
        display: flex;
        flex-direction: column;
        gap: 1.2rem;
      }

      /* 输入框 */
      input {
        padding: 1rem;
        border: 2px solid var(--input-border);
        border-radius: 12px;
        font-size: 1rem;
        transition: all 0.3s ease;
        background: var(--input-bg);
        color: var(--text-color);
      }

      input:focus {
        outline: none;
        border-color: var(--primary-color);
        box-shadow: 0 0 0 3px rgba(76, 175, 80, 0.2);
        transform: translateY(-2px);
      }

      /* 提交按钮 */
      input[type="submit"] {
        background: var(--button-bg);
        color: var(--button-text);
        border: none;
        padding: 1rem;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
      }

      input[type="submit"]:hover {
        background: var(--button-hover-bg);
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
      }

      input[type="submit"]:active {
        transform: translateY(0);
      }

      /* 错误消息 */
      .error-message {
        color: var(--error-color);
        background: rgba(244, 67, 54, 0.1);
        padding: 1rem;
        border-radius: 12px;
        text-align: center;
        margin-bottom: 1rem;
        border: 1px solid rgba(244, 67, 54, 0.2);
        backdrop-filter: blur(5px);
      }

      /* 响应式布局 */
      @media (max-width: 480px) {
        .login-container {
          margin: 1rem;
          padding: 1.5rem;
        }

        h1 {
          font-size: 1.5rem;
        }
      }

      /* 页脚 */
      footer {
        position: relative;
        z-index: 2;
        background: transparent !important;
        color: white !important;
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
      ${errorMessage ? `<div class="error-message">${errorMessage}</div>` : ''}
      <form method="POST" action="${action}">
        <input type="password" name="password" placeholder="请输入密码" required>
        <input type="submit" value="登录">
      </form>
    </div>
    ${footerHTML}
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
  <title>${CUSTOM_TITLE}${isAdmin ? ' - 后台管理' : ''}</title>
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
        <h1>${CUSTOM_TITLE}${isAdmin ? ' - 后台管理' : ''}</h1>
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
              'Authorization': 'Basic ' + btoa(':${ADMIN_PASSWORD}')
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
              'Authorization': 'Basic ' + btoa(':${ADMIN_PASSWORD}')
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
            'Authorization': 'Basic ' + btoa(':${ADMIN_PASSWORD}')
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
              'Authorization': 'Basic ' + btoa(':' + '${ADMIN_PASSWORD}')
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


const STATUS_COLORS = {
  UNKNOWN: '#808080',
  URGENT: '#ff0000',
  WARNING: '#ffa500',
  NOTICE: '#ffff00',
  NORMAL: '#00ff00'
};

const STATUS_TITLES = {
  UNKNOWN: '未知状态',
  URGENT: '紧急',
  WARNING: '警告',
  NOTICE: '注意',
  NORMAL: '正常'
};

function getStatusColor(daysRemaining) {
  if (isNaN(daysRemaining)) return STATUS_COLORS.UNKNOWN;
  if (daysRemaining <= 7) return STATUS_COLORS.URGENT;
  if (daysRemaining <= 30) return STATUS_COLORS.WARNING;
  if (daysRemaining <= 90) return STATUS_COLORS.NOTICE;
  return STATUS_COLORS.NORMAL;
}

function getStatusTitle(daysRemaining) {
  if (isNaN(daysRemaining)) return STATUS_TITLES.UNKNOWN;
  if (daysRemaining <= 7) return STATUS_TITLES.URGENT;
  if (daysRemaining <= 30) return STATUS_TITLES.WARNING;
  if (daysRemaining <= 90) return STATUS_TITLES.NOTICE;
  return STATUS_TITLES.NORMAL;
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
