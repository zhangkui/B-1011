# Memory QR (记忆二维码)

**Memory QR** 是一个注重隐私与情感连接的 Web 应用原型。它不仅仅是生成二维码，而是将二维码作为通往私密记忆的“加密钥匙”。用户可以上传文字、图片或视频，并自定义二维码的外观（颜色、背景图），使其具有独特的个人情感色彩。

## 核心理念
二维码不仅仅是冷冰冰的链接，它是封存记忆的容器。通过双重加密逻辑，只有拥有权限的用户（或通过特定解码器）才能解析并查看其中的内容。

## 核心功能

1.  **用户系统 (Security Core)**
    *   完整的注册与登录流程。
    *   **双重加密逻辑**：只有登录状态下才能使用“存储”和“解码”功能。
    *   未登录用户无法解析或查看私密内容，且无法访问解码器页面。
    *   **安全增强**：注册时支持密码二次确认，防止输入错误。

2.  **记忆存储 & 个性化设计 (Memory Storage & Design)**
    *   **内容上传**：支持文本、图片、视频等多种格式。
    *   **大文件支持**：支持最大 **64MB** 的媒体文件上传。
    *   **二维码设计器**：用户可以像设计艺术品一样定制二维码——修改前景色、背景色，甚至嵌入背景图片或 Logo。
    *   **持久化保存**：所有记忆和生成的二维码都会安全存储。

3.  **解码栏目 (The Decoder)**
    *   内置网页版二维码扫描/解码器。
    *   支持上传二维码图片进行解析。
    *   智能识别系统内生成的“记忆二维码”并展示对应内容。

4.  **微服务架构**
    *   **前端**：基于 Nginx 运行的静态页面，使用 Tailwind CSS 构建现代 UI。
    *   **后端**：基于 Flask (Python) 的 RESTful API 服务。
    *   **容器化**：完全 Docker 化，前端与后端分离，通过 Docker Compose 一键编排。

## 技术栈

*   **后端**: Python 3.11, Flask, SQLAlchemy (SQLite), Segno (二维码生成), OpenCV (解码)
*   **前端**: HTML5, JavaScript (ES6+), Tailwind CSS
*   **服务器**: Nginx (反向代理 & 静态资源服务)
*   **容器化**: Docker, Docker Compose

## 快速开始

### 前置要求
*   Docker Desktop (或 Docker Engine + Docker Compose)

### 运行项目

1.  **克隆/下载代码** 到本地。
2.  在项目根目录下打开终端。
3.  运行以下命令启动服务：

```bash
docker-compose up -d
```

4.  等待镜像构建及容器启动完成。

### 访问应用

打开浏览器访问：**[http://localhost:8080](http://localhost:8080)**

*   **前端页面**: `http://localhost:8080`
*   **后端 API**: `http://localhost:8080/api/` (通过 Nginx 代理)

### 测试账号

为方便演示，系统初始化时会自动创建一个管理员账号：

*   **用户名**: `admin`
*   **密码**: `password`

*(请手动输入以上凭据进行登录)*

## 项目结构

```
.
├── backend/                # 后端服务 (Flask)
│   ├── app.py              # 主应用逻辑
│   ├── Dockerfile          # 后端镜像构建文件
│   ├── requirements.txt    # Python 依赖
│   └── static/             # 静态资源存储 (uploads, qrcodes) - 挂载卷
├── frontend/               # 前端服务 (Nginx + Static Files)
│   ├── src/                # 源代码 (HTML, JS, CSS)
│   ├── nginx.conf          # Nginx 配置文件
│   └── Dockerfile          # 前端镜像构建文件
├── docker-compose.yml      # 容器编排配置
└── README.md               # 项目文档
```

## 注意事项

*   **数据持久化**: 数据库文件 (`memory_qr.db`) 存储在 Docker Volume `db_data` 中，确保数据重启不丢失。
*   **文件上传限制**: 默认配置支持最大 **64MB** 的文件上传（已在 Nginx 和 Flask 中配置）。
*   **本地开发**: 如果需要本地调试 Python 代码，请参考 `backend/requirements.txt` 安装依赖，并确保安装了系统级依赖 `libgl1` (用于 OpenCV)。

## 许可证
MIT License
