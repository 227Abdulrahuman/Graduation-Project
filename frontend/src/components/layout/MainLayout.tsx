import { useLocation, useNavigate, Outlet } from "react-router";
import { Sidebar } from "./Sidebar";
import Topbar from "./Topbar";

function MainLayout() {
	const location = useLocation();
	const navigate = useNavigate();

	return (
		<div className="min-h-screen bg-black text-zinc-100 font-sans selection:bg-emerald-500/30 selection:text-emerald-500">
			<Sidebar currentPath={location.pathname} onNavigate={navigate} />

			<main className="pl-64 min-h-screen flex flex-col">
				<Topbar />
				<div className="flex-1 overflow-auto bg-linear-to-b from-black via-zinc-950 to-black px-8 py-3">
					<Outlet />
				</div>
			</main>
		</div>
	);
}

export default MainLayout;
