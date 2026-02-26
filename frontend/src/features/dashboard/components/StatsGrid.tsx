import { Globe, AlertTriangle, Activity, Clock } from "lucide-react";
import StatCard from "./StatCard";

function StatsGrid({ className }: { className?: string }) {
  return (
    <div className={className}>
      <StatCard
        label="Total Targets"
        value="2,482"
        icon={Globe}
        trend="up"
        trendValue="+12%"
      />
      <StatCard
        label="Critical Vulns"
        value="48"
        icon={AlertTriangle}
        trend="down"
        trendValue="-3%"
      />
      <StatCard
        label="Scans Performed"
        value="12,402"
        icon={Activity}
        trend="up"
        trendValue="+18%"
      />
      <StatCard label="Avg. Response Time" value="124ms" icon={Clock} />
    </div>
  );
}

export default StatsGrid;
