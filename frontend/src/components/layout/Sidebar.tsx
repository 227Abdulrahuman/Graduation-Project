import { LayoutDashboard, Target, Globe2, ShieldAlert, History, Hexagon, Zap } from "lucide-react";
import { cn } from "@/lib/utils";

interface SidebarProps {
	currentPath: string;
	onNavigate: (path: string) => void;
	className?: string;
}

const navItems = [
	{ id: "/", label: "Dashboard", icon: LayoutDashboard },
	{ id: "/targets", label: "Targets", icon: Target },
	{ id: "/subdomains", label: "Subdomains", icon: Globe2 },
	{ id: "/scans", label: "Scans", icon: History },
	{ id: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
];

export function Sidebar({ currentPath, onNavigate, className }: SidebarProps) {
	return (
		<div className={cn("flex flex-col bg-zinc-950 border-r border-emerald-900/30", className)}>
			<div className="p-6 flex items-center gap-3 select-none">
				<div className="relative">
					<Hexagon className="w-8 h-8 text-emerald-500 fill-emerald-500/10" />
					<Zap className="w-4 h-4 text-white absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
				</div>
				<span className="font-bold text-xl tracking-tight text-white uppercase">
					Web<span className="text-emerald-500">Sploit</span>
				</span>
			</div>

			<nav className="flex-1 px-4 py-4 space-y-1">
				{navItems.map((item) => {
					const isActive = currentPath === item.id;
					return (
						<button
							key={item.id}
							onClick={() => onNavigate(item.id)}
							className={cn(
								"w-full flex items-center justify-between px-3 py-2.5 rounded-lg transition-all duration-200 group",
								isActive
									? "bg-emerald-500/10 text-emerald-500 shadow-[inset_0_0_15px_rgba(16,185,129,0.05)] ring-1 ring-inset ring-emerald-500/20"
									: "text-zinc-400 hover:text-white hover:bg-zinc-900",
							)}
						>
							<div className="flex items-center gap-3">
								<item.icon
									className={cn("w-5 h-5", isActive ? "text-emerald-500" : "text-zinc-500 group-hover:text-zinc-300")}
								/>
								<span className="font-medium text-sm">{item.label}</span>
							</div>
							{isActive && <div className="w-1 h-4 bg-emerald-500 rounded-full" />}
						</button>
					);
				})}
			</nav>

			{/* <div className="p-4 mt-auto">
				<div className="bg-emerald-950/20 border border-emerald-900/30 rounded-xl p-4">
					<div className="flex items-center gap-2 mb-2">
						<div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
						<span className="text-xs font-medium text-emerald-400">System Online</span>
					</div>
					<p className="text-[10px] text-zinc-500 leading-tight">
						Scanner engine v2.4.1 active. 12 active tasks in queue.
					</p>
				</div>
			</div> */}
		</div>
	);
}
