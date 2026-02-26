import RecentScansTable from "../components/RecentScansTable";
import SeverityChart from "../components/SeverityChart";
import SeverityTrendsChart from "../components/SeverityTrendsChart";
import StatsGrid from "../components/StatsGrid";

function DashboardPage() {
	return (
		<div className="max-w-8xl mx-auto space-y-8">
			{/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight">System Overview</h1>
          <p className="text-zinc-500 mt-1">Real-time security posture and scan intelligence</p>
        </div>
      </div>

      <StatsGrid className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" />
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <SeverityTrendsChart className="lg:col-span-2 p-6 h-[400px] flex flex-col" />
        <SeverityChart className="p-6 h-[400px] flex flex-col" />
      </div>
      
      <RecentScansTable />

		</div>
	)
}

export default DashboardPage;