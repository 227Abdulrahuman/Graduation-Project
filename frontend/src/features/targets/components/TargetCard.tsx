import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { type Target } from "../types";
import { ChevronRight, Globe, MoreHorizontal, Building2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import PlatformBadge from "./PlatformBadge";

interface TargetCardProps {
  target: Target;
  onSelectTarget: (id: string) => void;
}

function TargetCard({ target, onSelectTarget }: TargetCardProps) {
  return (
    <Card
      key={target.id}
      className="p-6 group hover:border-emerald-500/30 transition-all cursor-pointer"
      onClick={() => onSelectTarget(target.id)}
    >
      {/* Card Header */}
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-zinc-800 text-zinc-400 group-hover:bg-emerald-500/10 group-hover:text-emerald-500 transition-colors">
            <Building2 className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">{target.name}</h3>
          </div>
        </div>
        <button
          className="p-1 hover:bg-zinc-800 rounded text-zinc-500"
          onClick={(e) => {
            e.stopPropagation();
            // Additional actions
          }}
        >
          <MoreHorizontal className="w-5 h-5" />
        </button>
      </div>

      {/* Card Content */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="space-y-1 flex flex-col items-center">
          <span className="text-[10px] uppercase font-bold text-zinc-500 tracking-wider">
            Domains
          </span>
          <p className="text-xl font-bold text-zinc-200">
            {target.domains.length}
          </p>
        </div>
        <div className="space-y-1 flex flex-col items-center">
          <span className="text-[10px] uppercase font-bold text-zinc-500 tracking-wider">
            Platform
          </span>
          <PlatformBadge
            platform={target.platform}
            className="flex gap-1.5 mt-1"
          />
        </div>
        <div className="space-y-1 flex flex-col items-center">
          <span className="text-[10px] uppercase font-bold text-zinc-500 tracking-wider">
            Type
          </span>
          <Badge
            className="flex gap-1.5 mt-1"
            variant={target.type.toLowerCase() === "vdp" ? "info" : "success"}
          >
            {target.type}
          </Badge>
        </div>
      </div>

      {/* Card Footer */}
      <div className="pt-4 border-t border-zinc-800/50 flex items-center justify-between">
        <div className="flex -space-x-2">
          {[1, 2, 3, 4].map((i) => (
            <div
              key={i}
              className="w-6 h-6 rounded-full border-2 border-zinc-900 bg-zinc-800 flex items-center justify-center text-[8px] font-bold text-zinc-400"
            >
              <Globe className="w-3 h-3" />
            </div>
          ))}
          <div className="w-6 h-6 rounded-full border-2 border-zinc-900 bg-zinc-800 flex items-center justify-center text-[8px] font-bold text-zinc-400">
            +2
          </div>
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="group-hover:text-emerald-400"
          onClick={(e) => {
            e.stopPropagation();
            onSelectTarget(target.id);
          }}
        >
          Explore Domains <ChevronRight className="w-4 h-4 ml-1" />
        </Button>
      </div>
    </Card>
  );
}

export default TargetCard;
