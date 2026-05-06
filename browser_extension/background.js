// 后端API地址（和你现在运行的后端一致）
const API_URL = "http://127.0.0.1:5000/api/detect";

// 监听标签页更新（用户访问新网址时自动检测）
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // 只有页面完全加载完成后才检测
  if (changeInfo.status !== "complete" || !tab.url) return;

  // 跳过非HTTP/HTTPS页面（如浏览器设置页、扩展页）
  if (!tab.url.startsWith("http://") && !tab.url.startsWith("https://")) {
    setIcon(tabId, "default");
    return;
  }

  try {
    // 调用后端检测API
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url }),
    });

    if (!response.ok) throw new Error("后端未响应");
    const result = await response.json();

    // 根据检测结果更新图标和标题
    if (result.verdict === "钓鱼网站") {
      setIcon(tabId, "danger");
      // 弹出危险通知
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/danger.png",
        title: "⚠️ 智捕钓域警告",
        message: `检测到当前网站为钓鱼网站！\n${result.message}`,
        priority: 2
      });
    } else if (result.verdict === "可疑网站") {
      setIcon(tabId, "warning");
      chrome.notifications.create({
  type: "basic",
  iconUrl: "icons/danger.png",
  title: "⚠️ 智捕钓域警告",
  message: `检测到当前网站为钓鱼网站！\n存在品牌仿冒风险，请勿输入账号密码`,
  priority: 2
});
    } else {
      setIcon(tabId, "safe");
    }

  } catch (err) {
    console.error("检测失败:", err);
    setIcon(tabId, "default");
    chrome.action.setTitle({ tabId: tabId, title: "智捕钓域 - 检测失败，请确保后端正在运行" });
  }
});

// 辅助函数：更新插件图标和标题
function setIcon(tabId, status) {
  const iconPath = `icons/${status}.png`;
  chrome.action.setIcon({ tabId: tabId, path: iconPath });
  
  const statusText = {
    "default": "检测中",
    "safe": "安全可信",
    "danger": "钓鱼网站",
    "warning": "可疑网站"
  };
  chrome.action.setTitle({ tabId: tabId, title: `智捕钓域 - ${statusText[status]}` });
}

// 点击插件图标时，重新检测当前页面
chrome.action.onClicked.addListener(async (tab) => {
  if (!tab.url) return;
  chrome.tabs.reload(tabId);
});