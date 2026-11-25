import "./pwa.css";
import { MobilePwaApp } from "./pwaApp";

const root = document.getElementById("pwa-app");
if (root) {
  const app = new MobilePwaApp(root);
  void app.start();
  if ("serviceWorker" in navigator && (location.protocol === "https:" || location.hostname === "localhost" || location.hostname === "127.0.0.1")) {
    window.addEventListener("load", () => {
      void navigator.serviceWorker
        .register("/sw.js")
        .then((reg) => {
          if (reg.waiting) app.setPendingSwUpdate(reg.waiting);
          reg.addEventListener("updatefound", () => {
            const installing = reg.installing;
            if (!installing) return;
            installing.addEventListener("statechange", () => {
              if (installing.state === "installed" && navigator.serviceWorker.controller) {
                app.setPendingSwUpdate(installing);
              }
            });
          });
        })
        .catch(() => {
          // non-fatal if SW unavailable
        });
    });
  }
}
