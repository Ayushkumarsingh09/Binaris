/* Updated by deploy scripts with hosted Vercel / Fly URLs */
(function () {
  const links = {
    web: null, // e.g. "https://binaris.vercel.app"
    api: null, // e.g. "https://binaris-api.fly.dev"
  };
  const webEl = document.getElementById("live-web");
  const apiEl = document.getElementById("live-api");
  const workspace = document.getElementById("workspace-link");
  if (links.web && webEl) {
    webEl.href = links.web;
    webEl.textContent = links.web.replace(/^https?:\/\//, "");
    if (workspace) workspace.href = links.web;
  }
  if (links.api && apiEl) {
    apiEl.href = links.api + "/healthz";
    apiEl.textContent = links.api.replace(/^https?:\/\//, "") + "/healthz";
  }
})();
