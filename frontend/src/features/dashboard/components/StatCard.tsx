import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";

function StatsCard({
  label,
  value,
  icon: Icon,
  trend,
  trendValue,
}: {
  label: string;
  value: string | number;
  icon: any;
  trend?: "up" | "down";
  trendValue?: string;
}) {
  return (
    <Card className="p-5 flex flex-col gap-3 group hover:border-emerald-500/30 transition-all duration-300">
      <div className="flex justify-between items-start">
        <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-500 group-hover:scale-110 transition-transform duration-300">
          <Icon className="w-5 h-5" />
        </div>
        {trend && (
          <span
            className={cn(
              "text-[10px] font-bold px-1.5 py-0.5 rounded flex items-center gap-0.5",
              trend === "up"
                ? "text-emerald-400 bg-emerald-400/10"
                : "text-red-400 bg-red-400/10",
            )}
          >
            {trendValue}
          </span>
        )}
      </div>
      <div>
        <h3 className="text-zinc-500 text-xs font-medium uppercase tracking-wider">
          {label}
        </h3>
        <div className="text-2xl font-bold text-white mt-1 tabular-nums">
          {value}
        </div>
      </div>
    </Card>
  );
}

export default StatsCard;
