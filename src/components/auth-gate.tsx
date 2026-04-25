"use client";

import { useEffect, useState, useCallback } from "react";
import { StarField } from "@/components/star-field";

const AUTH_KEY = "mmam-auth-token";
const PIN_KEY = "mmam-pin";
const AUTH_EXPIRY = 30 * 24 * 60 * 60 * 1000; // 30 days

// Cookie helpers — persist across browser restarts, survive localStorage wipes
function setCookie(name: string, value: string, days: number) {
  const expires = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toUTCString();
  document.cookie = `${name}=${encodeURIComponent(value)}; expires=${expires}; path=/; SameSite=Lax`;
}

function getCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

// Read from cookie first, fall back to localStorage
function getStored(key: string): string | null {
  return getCookie(key) || localStorage.getItem(key);
}

// Write to both cookie and localStorage
function setStored(key: string, value: string, days = 365) {
  localStorage.setItem(key, value);
  setCookie(key, value, days);
}

export function AuthGate({ children }: { children: React.ReactNode }) {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [pin, setPin] = useState("");
  const [confirmPin, setConfirmPin] = useState("");
  const [error, setError] = useState("");
  const [isSetup, setIsSetup] = useState(false);
  const [step, setStep] = useState<"enter" | "confirm">("enter");

  useEffect(() => {
    const token = getStored(AUTH_KEY);
    if (token) {
      try {
        const { expiry } = JSON.parse(token);
        if (Date.now() < expiry) {
          // Refresh storage in case one was wiped
          setStored(AUTH_KEY, token, 30);
          setAuthenticated(true);
          return;
        }
      } catch { /* invalid */ }
    }
    const savedPin = getStored(PIN_KEY);
    if (!savedPin) setIsSetup(true);
    setAuthenticated(false);
  }, []);

  const handleDigit = useCallback((digit: string) => {
    setError("");
    if (isSetup && step === "confirm") {
      const next = confirmPin + digit;
      setConfirmPin(next);
      if (next.length === 4) {
        if (next === pin) {
          const tokenValue = JSON.stringify({ expiry: Date.now() + AUTH_EXPIRY });
          setStored(PIN_KEY, pin, 365);
          setStored(AUTH_KEY, tokenValue, 30);
          setAuthenticated(true);
        } else {
          setError("PINs don't match. Try again.");
          setPin("");
          setConfirmPin("");
          setStep("enter");
        }
      }
      return;
    }

    const next = pin + digit;
    setPin(next);
    if (next.length === 4) {
      if (isSetup) {
        setStep("confirm");
      } else {
        const savedPin = getStored(PIN_KEY);
        if (next === savedPin) {
          const tokenValue = JSON.stringify({ expiry: Date.now() + AUTH_EXPIRY });
          setStored(AUTH_KEY, tokenValue, 30);
          setAuthenticated(true);
        } else {
          setError("Wrong PIN");
          setPin("");
        }
      }
    }
  }, [pin, confirmPin, isSetup, step]);

  const handleDelete = () => {
    setError("");
    if (isSetup && step === "confirm") {
      setConfirmPin(confirmPin.slice(0, -1));
    } else {
      setPin(pin.slice(0, -1));
    }
  };

  // Keyboard support
  useEffect(() => {
    if (authenticated) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key >= "0" && e.key <= "9") handleDigit(e.key);
      if (e.key === "Backspace") handleDelete();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  });

  if (authenticated === null) {
    return <div className="flex h-screen items-center justify-center bg-[var(--background)]"><div className="size-8 animate-spin rounded-full border-2 border-accent border-t-transparent" /></div>;
  }

  if (authenticated) return <>{children}</>;

  const currentPin = isSetup && step === "confirm" ? confirmPin : pin;

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[var(--background)] p-4">
      {/* Full-screen star field background */}
      <div className="pointer-events-none absolute inset-0">
        <StarField />
        <div
          className="absolute inset-0"
          style={{
            background: 'radial-gradient(ellipse 60% 40% at 50% 30%, rgba(56, 189, 248, 0.12), rgba(0, 71, 255, 0.04), transparent)',
          }}
        />
      </div>

      <div className="relative z-10 w-full max-w-xs">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex size-16 items-center justify-center rounded-2xl bg-gradient-to-b from-sky-400 to-sky-600 font-mono text-3xl font-bold text-white shadow-lg shadow-sky-500/20">$</div>
          <h1 className="text-2xl font-bold">MMAM</h1>
          <p className="mt-1 text-sm text-muted">
            {isSetup ? (step === "confirm" ? "Confirm your PIN" : "Create a 4-digit PIN") : "Enter your PIN"}
          </p>
        </div>

        {error && (
          <div className="mb-4 rounded-lg bg-red-500/10 p-3 text-center text-sm text-red-400">{error}</div>
        )}

        {/* PIN dots */}
        <div className="mb-8 flex justify-center gap-4">
          {[0, 1, 2, 3].map((i) => (
            <div
              key={i}
              className={`size-4 rounded-full transition-all ${
                i < currentPin.length ? "scale-110 bg-accent shadow-md shadow-accent/30" : "bg-white/10 ring-1 ring-white/15"
              }`}
            />
          ))}
        </div>

        {/* Numeric keypad */}
        <div className="mx-auto grid max-w-[240px] grid-cols-3 gap-3">
          {["1", "2", "3", "4", "5", "6", "7", "8", "9", "", "0", "⌫"].map((key) => (
            key === "" ? <div key="empty" /> : (
              <button
                key={key}
                onClick={() => key === "⌫" ? handleDelete() : handleDigit(key)}
                className={`flex size-16 items-center justify-center rounded-2xl text-xl font-semibold transition-all active:scale-95 ${
                  key === "⌫"
                    ? "text-muted hover:bg-white/5"
                    : "bg-white/5 ring-1 ring-white/10 text-[var(--foreground)] hover:bg-white/10 hover:ring-white/20"
                }`}
              >
                {key}
              </button>
            )
          ))}
        </div>

        <p className="mt-6 text-center text-xs text-muted/60">
          {isSetup ? "You'll stay logged in for 30 days" : "Stays unlocked for 30 days"}
        </p>
      </div>
    </div>
  );
}
