import type {Metadata} from 'next';
import './globals.css'; // Global styles

export const metadata: Metadata = {
  title: 'AI Cyber Threat Detector',
  description: 'An interactive machine learning framework that analyzes network traffic logs to detect anomalies and evaluate security threats in real-time.',
};

export default function RootLayout({children}: {children: React.ReactNode}) {
  return (
    <html lang="en">
      <body suppressHydrationWarning>{children}</body>
    </html>
  );
}
