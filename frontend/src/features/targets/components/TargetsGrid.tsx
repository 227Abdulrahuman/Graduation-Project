
import TargetCard from "./TargetCard";
import { type Target } from "../types";

interface TargetsGridProps {
  targets: Target[],
  onSelectTarget: (id: string) => void,
}

function TargetsGrid({ targets, onSelectTarget }: TargetsGridProps) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
      {targets.map((target) => (
        <TargetCard key={target.id} target={target} onSelectTarget={onSelectTarget} />
      ))}
    </div>
  );
}

export default TargetsGrid;
