let isUserAuthenticated = false;

document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
});

async function checkAuth() {
    const navLinks = document.getElementById('nav-links');
    if (!navLinks) return;

    try {
        const res = await fetch('/api/auth/status');
        const data = await res.json();
        isUserAuthenticated = data.authenticated;

        let html = `
            <a href="/" class="hover:text-cyber-light px-3 py-2 rounded-md text-sm font-medium">首页</a>
            <a href="/capsule.html" class="hover:text-cyber-light px-3 py-2 rounded-md text-sm font-medium">时光胶囊</a>
            <a href="/store.html" class="hover:text-cyber-light px-3 py-2 rounded-md text-sm font-medium">商城</a>
        `;

        if (data.authenticated) {
            html += `
                <a href="/decode.html" class="hover:text-cyber-light px-3 py-2 rounded-md text-sm font-medium">解码</a>
                <a href="/dashboard.html" class="hover:text-cyber-light px-3 py-2 rounded-md text-sm font-medium">我的记忆</a>
                <a href="/create.html" class="hover:text-cyber-light px-3 py-2 rounded-md text-sm font-medium">创建</a>
                <a href="/join.html" class="hover:text-cyber-light px-3 py-2 rounded-md text-sm font-medium">加入协作</a>
                <span class="text-gray-500 px-3 text-sm">|</span>
                <span class="text-cyber-neon font-bold px-3 text-sm">${data.username}</span>
                <a href="#" onclick="logout(event)" class="text-gray-400 hover:text-white px-3 py-2 rounded-md text-sm font-medium">退出</a>
            `;
        } else {
            html += `
                <a href="/login.html" class="hover:text-cyber-light px-3 py-2 rounded-md text-sm font-medium">登录 / 注册</a>
            `;
        }
        
        navLinks.innerHTML = html;
    } catch (err) {
        console.error('Auth check failed', err);
    }
}

async function logout(e) {
    e.preventDefault();
    await fetch('/api/auth/logout', { method: 'POST' });
    window.location.href = '/';
}

function handleCreateClick(e) {
    e.preventDefault();
    if (isUserAuthenticated) {
        window.location.href = '/create.html';
    } else {
        const redirect = encodeURIComponent('/create.html');
        window.location.href = `/login.html?redirect=${redirect}`;
    }
}
