# DomainKeeper - 域名可视化管理面板

## 项目简介

DomainKeeper 是一个基于 Cloudflare Workers 构建的高效域名管理面板。它为用户提供了一个直观的界面，用于集中管理和监控域名资产，包括域名状态、注册信息、到期时间等关键数据的可视化展示。

### 适用场景

- 个人或企业需要集中管理多个域名
- 需要实时监控域名到期状态
- 希望通过可视化界面快速了解域名资产状况
- 使用 Cloudflare 管理域名的用户

## 功能特性

### 基础版
- 域名基础信息展示（状态、注册商、注册/到期日期）
- 域名使用时长可视化进度条
- 自动计算剩余有效期
- 支持手动添加自定义域名
- 响应式设计，支持多端访问
- 轻量级实现，加载迅速

### 高级版（推荐）
- 包含基础版全部功能
- 全新 UI 设计，视觉体验升级
- 前后端分离架构，支持密码保护
- Cloudflare API 集成，自动获取域名列表
- 自建 WHOIS 代理服务，自动获取域名详细信息
- 支持二级域名信息管理
- 数据本地持久化存储

## 部署指南

### 环境要求
- Cloudflare 账号
- 域名（可选，用于绑定 Workers）

### 基础版部署
1. 登录 Cloudflare 控制台
2. 创建新的 Worker
3. 复制 `index.js` 内容到 Worker 编辑器
4. 配置域名信息：
   ```javascript
   const DOMAINS = [
     {
       domain: "example.com",
       registrationDate: "2022-01-01",
       expirationDate: "2027-01-01",
       system: "Cloudflare"
     }
   ];
   ```
5. 保存并部署

### 高级版部署
1. 登录 Cloudflare 控制台
2. 创建新的 Worker
3. 复制 `_worker.js` 内容到编辑器
4. 配置必要参数：
   ```javascript
   const CF_API_KEY = "your_cloudflare_api_key";
   const WHOIS_PROXY_URL = "your_whois_proxy_url";
   const ACCESS_PASSWORD = "your_frontend_password";
   const ADMIN_PASSWORD = "your_backend_password";
   ```

#### 参数获取说明
- **CF_API_KEY**: 
  1. 访问 https://dash.cloudflare.com/profile
  2. 点击「API 令牌」→「创建令牌」
  3. 选择「使用模板」→「读取所有资源」
  4. 创建并保存令牌（注意：仅显示一次）

- **WHOIS_PROXY_URL**:
  1. 部署 [whois-proxy](https://github.com/ypq123456789/whois-proxy) 服务
  2. 必须使用域名访问（不支持 IP）
  3. 格式：`https://your-domain.com`（不需要包含 /whois）

5. 创建并绑定 KV 命名空间：
   - 创建名为 `DOMAIN_INFO` 的 KV 命名空间
   - 绑定到 Worker，变量名设为 `DOMAIN_INFO`

## 常见问题

### Q: 如何更新域名信息？
**A**: 高级版支持通过后台管理界面更新域名信息。基础版需要修改 Worker 代码中的 DOMAINS 数组。

### Q: WHOIS 信息获取失败怎么办？
**A**: 
1. 检查 WHOIS_PROXY_URL 配置是否正确
2. 确认代理服务是否正常运行
3. 检查域名是否支持 WHOIS 查询

### Q: 如何自定义界面样式？
**A**: 可以修改 Worker 代码中的 CSS 样式定义，或通过配置变量修改主题色等。

## 项目维护

### 参与贡献
欢迎通过以下方式参与项目：
- 提交 Issue 报告问题或建议
- 提交 Pull Request 改进代码
- 完善文档内容

### 开源协议
本项目采用 [MIT 许可证](https://choosealicense.com/licenses/mit/)，详见 LICENSE 文件。

## 更新日志

### v1.0.0
- 初始版本发布
- 基础域名管理功能
- 可视化界面实现

### v2.0.0
- 新增高级版功能
- API 集成优化
- UI 界面升级
- 数据持久化支持
