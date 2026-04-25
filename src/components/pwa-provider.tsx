"use client";

import { useEffect, useState } from "react";

export function PWAProvider({ children }: { children: React.ReactNode }) {
  const [isOffline, setIsOffline] = useState(false);
  const [syncMessage, setSyncMessage] = useState("");

  useEffect(() => {
    // Register service worker
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.register("/sw.js").catch(() => {});

      // Listen for sync messages
      navigator.serviceWorker.addEventListener("message", (event) => {
        if (event.data?.type === "sync-complete") {
          const { synced, remaining } = event.data;
          if (synced > 0) {
            setSyncMessage(`Synced ${synced} offline changes`);
            setTimeout(() => setSyncMessage(""), 3000);
          }
          if (remaining > 0) {
            setSyncMessage(`${remaining} changes still pending`);
          }
        }
      });
    }

    // Online/offline detection
    const goOffline = () => setIsOffline(true);
    const goOnline = () => {
      setIsOffline(false);
      // Trigger sync
      if (navigator.serviceWorker?.controller) {
        navigator.serviceWorker.controller.postMessage("sync");
      }
    };

    window.addEventListener("offline", goOffline);
    window.addEventListener("online", goOnline);
    setIsOffline(!navigator.onLine);

    return () => {
      window.removeEventListener("offline", goOffline);
      window.removeEventListener("online", goOnline);
    };
  }, []);

  return (
    <>
      {/* Offline/sync banner */}
      {(isOffline || syncMessage) && (
        <div className={`fixed top-0 left-0 right-0 z-[100] px-4 py-2 text-center text-xs font-medium ${
          isOffline ? "bg-red-500 text-white" : "bg-emerald-500 text-white"
        }`}>
          {isOffline ? "You are offline — changes will sync when connected" : syncMessage}
        </div>
      )}
      {children}
    </>
  );
}
