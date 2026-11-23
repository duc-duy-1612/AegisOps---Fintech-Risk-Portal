import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'AegisOps — AI Fintech Fraud, Cyber Defense & Real-Time User Shield Workspace',
  description:
    'MoMo Tech Contest: Imagine the Future Workspace (Human Centered. AI Powered). Compress fraud & cyber investigation from 30 minutes to 10 seconds and protect end-user wallets in real time.',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="vi" className="dark" suppressHydrationWarning>
      <body
        suppressHydrationWarning
        className="min-h-screen bg-aegis-bg text-aegis-text antialiased selection:bg-aegis-violet/30 selection:text-white"
      >
        {children}
      </body>
    </html>
  );
}
