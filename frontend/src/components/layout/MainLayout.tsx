import { useLocation, useNavigate, Outlet } from "react-router";
import { Sidebar } from "./Sidebar";
import Topbar from "./Topbar";
import { Toaster } from "sonner";

function MainLayout() {
  const location = useLocation();
  const navigate = useNavigate();

  return (
    <div className="grid grid-cols-1 md:grid-cols-[250px_1fr] min-h-screen bg-black text-zinc-100 font-sans selection:bg-emerald-500/30 selection:text-emerald-500">
			{/* Sidebar */}
      <Sidebar
        currentPath={location.pathname}
        onNavigate={navigate}
        className="sticky top-0 h-screen overflow-y-auto"
      />

			{/* Main Content */}
      <main className="flex flex-col mx-10 dark">
        <Topbar />
        <div className="flex-1 overflow-auto bg-linear-to-b from-black via-zinc-950 to-black my-6">
          <Outlet />
        </div>
      </main>

			{/* Toast */}
      <Toaster
        position="bottom-right"
        theme="dark"
        richColors
        toastOptions={{
          style: {
            background: "#09090b",
            border: "1px solid #064e3b",
            color: "#ecfdf5",
          },
        }}
      />
    </div>
  );
}

export default MainLayout;
