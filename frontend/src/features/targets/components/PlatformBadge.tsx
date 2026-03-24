import { Badge } from "@/components/ui/badge";
import { type Target } from "../types";

function PlatformBadge({
  platform,
  className,
}: {
  platform: Target["platform"];
  className?: string;
}) {
  return (
    <Badge
      variant={
        platform === "Bugcrowd"
          ? "orange"
          : platform === "Hackerone"
            ? "default"
            : platform === "YesWeHack"
              ? "error"
              : platform === "Intigriti"
                ? "cyan"
                : platform === "Synack"
                  ? "violet"
                  : "neutral"
      }
      className={className}
    >
      {platform}
    </Badge>
  );
}

export default PlatformBadge;
