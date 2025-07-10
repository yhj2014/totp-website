// script.js
document.addEventListener('DOMContentLoaded', function() {
    // 切换标签页
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.getAttribute('data-tab');
            
            // 移除所有active类
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            // 添加active类到当前标签
            btn.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        });
    });
    
    // 下载功能
    const setupDownload = (buttonId, filename) => {
        const btn = document.getElementById(buttonId);
        if (btn) {
            btn.addEventListener('click', async function() {
                try {
                    const originalText = btn.textContent;
                    btn.textContent = '下载中...';
                    btn.disabled = true;
                    
                    const rawUrl = `https://raw.githubusercontent.com/yhj2014/totp-website/main/download/${filename}`;
                    
                    const response = await fetch(rawUrl);
                    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                    const fileContent = await response.text();
                    
                    const blob = new Blob([fileContent], { type: 'text/plain' });
                    const url = URL.createObjectURL(blob);
                    
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                    
                    btn.textContent = originalText;
                    btn.disabled = false;
                    
                    alert(`${filename} 下载成功！`);
                } catch (error) {
                    console.error('下载失败:', error);
                    alert('下载失败，请稍后重试或手动下载。');
                    
                    const btn = document.getElementById(buttonId);
                    if (btn) {
                        btn.textContent = `下载 ${filename}`;
                        btn.disabled = false;
                    }
                }
            });
        }
    };
    
    // 设置三个下载按钮
    setupDownload('download-src', 'totp.py');
    setupDownload('download-exe-script', 'build_exe.ps1');
    setupDownload('download-apk-script', 'build_apk.ps1');
    
    // 平滑滚动
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                window.scrollTo({
                    top: targetElement.offsetTop - 80,
                    behavior: 'smooth'
                });
            }
        });
    });
});
