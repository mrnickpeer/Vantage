// background.js - Vantage Extension Background Worker
if (typeof browser === 'undefined') {
  var browser = globalThis.browser || globalThis.chrome;
}

browser.action.onClicked.addListener(async () => {
  const url = browser.runtime.getURL("dashboard.html");
  const tabs = await browser.tabs.query({ url });
  
  if (tabs.length > 0) {
    await browser.tabs.update(tabs[0].id, { active: true });
  } else {
    await browser.tabs.create({ url });
  }
});

function setupContextMenus() {
  if (!browser || !browser.contextMenus) return;
  const createMenus = () => {
    browser.contextMenus.create({
      id: "vt-add-link",
      title: "Send Link to Vantage Audit Log",
      contexts: ["link"]
    });

    browser.contextMenus.create({
      id: "vt-add-page",
      title: "Send Current Page to Vantage Audit Log",
      contexts: ["page"]
    });

    browser.contextMenus.create({
      id: "vt-open-dash",
      title: "Open Vantage Dashboard",
      contexts: ["page", "link"]
    });
  };

  try {
    const p = browser.contextMenus.removeAll();
    if (p && typeof p.then === 'function') {
      p.then(createMenus).catch(createMenus);
    } else {
      createMenus();
    }
  } catch (_) {
    createMenus();
  }
}

browser.runtime.onInstalled.addListener(setupContextMenus);
browser.runtime.onStartup.addListener(setupContextMenus);

browser.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "vt-open-dash" || info.menuItemId === "qs-open-dash") {
    const url = browser.runtime.getURL("dashboard.html");
    const tabs = await browser.tabs.query({ url });
    if (tabs.length > 0) {
      await browser.tabs.update(tabs[0].id, { active: true });
    } else {
      await browser.tabs.create({ url });
    }
    return;
  }

  if (info.menuItemId === "vt-add-link" || info.menuItemId === "vt-add-page" || info.menuItemId === "qs-add-link" || info.menuItemId === "qs-add-page") {
    const targetUrl = info.linkUrl || info.pageUrl || (tab && tab.url);
    if (!targetUrl || targetUrl.startsWith("about:") || targetUrl.startsWith("moz-extension://")) return;

    try {
      const data = await browser.storage.local.get(["auditLogs"]);
      const logs = data.auditLogs || [];

      // Deduplicate by URL
      if (!logs.some(l => l.url === targetUrl)) {
        logs.push({
          id: Date.now().toString(),
          url: targetUrl,
          status: "investigating",
          notes: `Discovered via browser context menu from "${(tab && tab.title) || 'webpage'}".`,
          query: "Context Menu Link Capture",
          engine: "browser",
          timestamp: new Date().toISOString()
        });
        await browser.storage.local.set({ auditLogs: logs });

        // Provide temporary badge confirmation
        if (browser.action.setBadgeText) {
          browser.action.setBadgeText({ text: "+1" });
          browser.action.setBadgeBackgroundColor({ color: "#22c55e" });
          setTimeout(() => {
            browser.action.setBadgeText({ text: "" });
          }, 2000);
        }
      }
    } catch (err) {
      console.error("Failed to log finding from context menu:", err);
    }
  }
});