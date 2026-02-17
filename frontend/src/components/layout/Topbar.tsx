import { Search } from "lucide-react";

function Topbar() {
	return (
		<header className="h-16 border-b border-emerald-900/10 bg-black/50 backdrop-blur-xl flex items-center justify-between px-8 sticky top-0 z-30">
			<div className="flex items-center gap-4 flex-1">
				<div className="relative w-96 hidden md:block">
					<Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-600" />
					<input
						type="text"
						placeholder="Global command search... (⌘K)"
						className="w-full bg-zinc-900/50 border border-zinc-800/50 rounded-lg py-1.5 pl-10 pr-4 text-sm text-zinc-400 focus:outline-none focus:border-emerald-500/50 focus:bg-zinc-900 transition-all"
					/>
				</div>
			</div>

			{/* <div className="flex items-center gap-6">
				<div className="flex items-center gap-2 px-3 py-1 bg-emerald-950/20 border border-emerald-900/30 rounded-full">
					<div className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_5px_rgba(16,185,129,0.8)]" />
					<span className="text-[10px] font-bold text-emerald-500 uppercase tracking-widest">Node: US-EAST-1</span>
				</div>

				<button className="relative p-2 text-zinc-400 hover:text-white transition-colors">
					<Bell className="w-5 h-5" />
					<span className="absolute top-2 right-2 w-2 h-2 bg-emerald-500 rounded-full border-2 border-black" />
				</button>

				<div className="flex items-center gap-3 pl-6 border-l border-zinc-800">
					<div className="text-right hidden sm:block">
						<p className="text-xs font-bold text-white">Security Admin</p>
						<p className="text-[10px] text-zinc-500 uppercase tracking-tighter">Level 4 Clearance</p>
					</div>
					<div className="w-10 h-10 rounded-xl bg-linear-to-br from-emerald-500 to-emerald-800 flex items-center justify-center text-white shadow-lg shadow-emerald-900/20 ring-2 ring-emerald-900/20">
						<User className="w-6 h-6" />
					</div>
				</div>
			</div> */}
		</header>
	);
}

export default Topbar;
