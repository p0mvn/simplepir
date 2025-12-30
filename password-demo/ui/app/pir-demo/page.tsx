'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

// This page now redirects to the main page since PIR is the primary flow
export default function PirDemo() {
  const router = useRouter();
  
  useEffect(() => {
    router.replace('/');
  }, [router]);

  return (
    <main className="min-h-screen bg-slate-950 flex items-center justify-center">
      <div className="text-center">
        <div className="animate-spin w-8 h-8 border-2 border-violet-500 border-t-transparent rounded-full mx-auto mb-4" />
        <p className="text-slate-400">Redirecting to Password Checker...</p>
      </div>
    </main>
  );
}
