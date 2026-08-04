/* Updated by deploy scripts with hosted Vercel / Fly URLs */
(function () {
  const links = {
    web: "https://binaris-nine.vercel.app",
    api: null, // Fly.io deploy requires billing; run API via Docker locally
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
