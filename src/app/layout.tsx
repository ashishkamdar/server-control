import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Sidebar } from "@/components/sidebar";
import { ThemeProvider } from "@/components/theme-provider";
import { PWAProvider } from "@/components/pwa-provider";
import { AuthGate } from "@/components/auth-gate";
import { StarField } from "@/components/star-field";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "MMAM — Make Me A Millionaire",
  description: "Personal AI coach for personality development and business strategy",
  manifest: "/manifest.json",
  appleWebApp: {
    capable: true,
    statusBarStyle: "black-translucent",
    title: "MMAM",
  },
};

export const viewport: Viewport = {
  themeColor: "#0a0e17",
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full dark`}
      suppressHydrationWarning
    >
      <head>
        <link rel="apple-touch-icon" href="/icons/icon-192.png" />
      </head>
      <body className="h-full bg-[var(--background)] text-[var(--foreground)] antialiased">
        <ThemeProvider>
          <AuthGate>
            <PWAProvider>
              {/* Fixed background — stars + glow (dark mode) */}
              <div className="pointer-events-none fixed inset-0 z-0 hidden dark:block">
                <div
                  className="absolute inset-0"
                  style={{
                    background: 'radial-gradient(ellipse 80% 50% at 70% -20%, rgba(56, 189, 248, 0.15), rgba(0, 71, 255, 0.05), transparent)',
                  }}
                />
                <StarField />
              </div>
              {/* Light mode glow only */}
              <div
                className="pointer-events-none fixed inset-0 z-0 block dark:hidden"
                style={{
                  background: 'radial-gradient(ellipse 80% 50% at 70% -20%, rgba(2, 132, 199, 0.06), transparent)',
                }}
              />
              <div className="relative z-10 flex h-full">
                <Sidebar />
                <main className="flex-1 overflow-y-auto xl:ml-0">
                  <div className="xl:hidden h-16" />
                  {children}
                </main>
              </div>
            </PWAProvider>
          </AuthGate>
        </ThemeProvider>
      </body>
    </html>
  );
}
