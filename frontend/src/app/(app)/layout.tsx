import { Nav } from "@/components/shared/nav";
import { PageTransition } from "@/components/shared/page-transition";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen">
      <Nav />
      <main className="mx-auto max-w-7xl px-4 pb-20 pt-6 sm:px-6 sm:pb-10 sm:pt-8">
        <PageTransition>{children}</PageTransition>
      </main>
    </div>
  );
}
