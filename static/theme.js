// Runs before first paint (loaded in <head>) so the saved theme is applied without a flash.
// It lives in its own file because the Content-Security-Policy forbids inline scripts.
(function () {
  var t = null;
  try { t = localStorage.getItem("zw-theme"); } catch (e) { /* private mode */ }
  if (!t) t = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  document.documentElement.dataset.theme = t;
})();
