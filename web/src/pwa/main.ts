import "./pwa.css";
import { MobilePwaApp } from "./pwaApp";

const root = document.getElementById("pwa-app");
if (root) {
  const app = new MobilePwaApp(root);
  void app.start();
  if ("serviceWorker" in navigator && (location.protocol === "https:" || location.hostname === "localhost" || location.hostname === "127.0.0.1")) {
    window.addEventListener("load", () => {
      void navigator.serviceWorker.register("/sw.js").catch(() => {
        // non-fatal if SW unavailable
      });
    });
  }
}
