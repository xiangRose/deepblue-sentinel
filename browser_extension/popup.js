document.addEventListener('DOMContentLoaded', async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const statusContainer = document.getElementById('statusContainer');
  const currentUrlEl = document.getElementById('currentUrl');
  
  if (tab && tab.url) {
    currentUrlEl.textContent = tab.url.substring(0, 50) + '...';
    
    // 调用后端检测
    try {
      const response = await fetch('http://127.0.0.1:5000/api/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: tab.url })
      });
      const result = await response.json();
      
      if (result.verdict === '钓鱼网站') {
        statusContainer.innerHTML = `
          <div class="status-card status-danger">
            <div class="status-title">🔴 钓鱼网站警告</div>
            <div class="status-msg">${result.message}</div>
          </div>
        `;
      } else {
        statusContainer.innerHTML = `
          <div class="status-card status-safe">
            <div class="status-title">🟢 当前页面安全</div>
            <div class="status-msg">${result.message}</div>
          </div>
        `;
      }
    } catch (e) {
      statusContainer.innerHTML = `
        <div class="status-card" style="background: rgba(255,193,7,0.1); border:1px solid #ffc107;">
          <div class="status-title">⚠️ 检测失败</div>
          <div class="status-msg">请确保后端正在运行</div>
        </div>
      `;
    }
  }

  // 按钮事件
  document.getElementById('openWebBtn').addEventListener('click', () => {
    chrome.tabs.create({ url: 'http://127.0.0.1:5000' });
  });
  
  document.getElementById('recheckBtn').addEventListener('click', () => {
    chrome.tabs.reload(tab.id);
    window.close();
  });
});