"use strict";
const reloadNotice = document.getElementById("account-reload");
if (reloadNotice) {
  let attempts = 0;
  async function checkReload() {
    let applied = false;
    try {
      const response = await fetch(reloadNotice.dataset.statusUrl, {credentials: "same-origin", cache: "no-store"});
      if (!response.ok || !response.headers.get("content-type")?.includes("application/json")) return;
      const status = await response.json();
      reloadNotice.textContent = status.message;
      if (status.disconnected) reloadNotice.textContent += ` ${status.disconnected} session(s) disconnected.`;
      reloadNotice.classList.toggle("error", status.status === "error");
      applied = status.status === "applied" || status.status === "none";
    } catch {
      reloadNotice.textContent = "Account changes saved. Waiting for the VPN gateway to apply them.";
    }
    if (!applied && ++attempts < 120) setTimeout(() => { void checkReload(); }, 1000);
  }
  await checkReload();
}
