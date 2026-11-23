import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "FinSec Agent — AI SOC & Safe Virtual Patching Workspace",
  description:
    "Autonomous AI SOC Investigation, Indirect Prompt Injection Defense, and Zero-False-Positive Virtual Patching for Fintech Operations.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="vi" className="dark">
      <body className="min-h-screen bg-[#070b14] text-slate-100 antialiased selection:bg-sky-500/30 selection:text-sky-200">
        {children}
      </body>
    </html>
  );
}
