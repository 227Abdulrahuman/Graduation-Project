import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const scanData = [
  { name: "Mon", vulns: 12 },
  { name: "Tue", vulns: 19 },
  { name: "Wed", vulns: 3 },
  { name: "Thu", vulns: 5 },
  { name: "Fri", vulns: 2 },
  { name: "Sat", vulns: 8 },
  { name: "Sun", vulns: 15 },
];

function SeverityTrendsChart({ className }: { className?: string }) {
  return (
    <Card className={className}>
      <div className="flex items-center justify-between mb-6">
        <h3 className="font-bold text-zinc-200">Vulnerability Trends</h3>
        <div className="flex gap-2">
          <Badge variant="success">Discovery</Badge>
          <Badge>7 Days</Badge>
        </div>
      </div>
      <div className="flex-1 min-h-0">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={scanData}>
            <defs>
              <linearGradient id="colorVulns" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#27272a"
              vertical={false}
            />
            <XAxis
              dataKey="name"
              stroke="#71717a"
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              stroke="#71717a"
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "#18181b",
                borderColor: "#27272a",
                borderRadius: "8px",
              }}
              itemStyle={{ color: "#10b981" }}
            />
            <Area
              type="monotone"
              dataKey="vulns"
              stroke="#10b981"
              strokeWidth={3}
              fillOpacity={1}
              fill="url(#colorVulns)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}

export default SeverityTrendsChart;
