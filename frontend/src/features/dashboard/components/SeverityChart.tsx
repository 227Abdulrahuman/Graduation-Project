import { Card } from "@/components/ui/card";
import {
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const severityData = [
  { name: "Critical", value: 12, color: "#ef4444" },
  { name: "High", value: 25, color: "#f97316" },
  { name: "Medium", value: 48, color: "#f59e0b" },
  { name: "Low", value: 64, color: "#3b82f6" },
];

function SeverityChart({ className }: { className: string }) {
  return (
    <Card className={className}>
      <h3 className="font-bold text-zinc-200 mb-6">Severity Distribution</h3>
      <div className="flex-1 min-h-0">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={severityData} layout="vertical">
            <XAxis type="number" hide />
            <YAxis
              dataKey="name"
              type="category"
              stroke="#71717a"
              fontSize={12}
              width={80}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              cursor={{ fill: "#27272a" }}
              contentStyle={{
                backgroundColor: "#18181b",
                borderColor: "#27272a",
              }}
            />
            <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={20}>
              {severityData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-4 pt-4 border-t border-zinc-800 space-y-3">
        {severityData.map((item) => (
          <div
            key={item.name}
            className="flex justify-between items-center text-xs"
          >
            <div className="flex items-center gap-2">
              <div
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: item.color }}
              />
              <span className="text-zinc-400">{item.name}</span>
            </div>
            <span className="text-zinc-200 font-medium">
              {item.value} issues
            </span>
          </div>
        ))}
      </div>
    </Card>
  );
}

export default SeverityChart;
