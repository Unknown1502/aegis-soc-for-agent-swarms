import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

interface PanelProps {
  title?: ReactNode;
  icon?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  /** make the body a scroll container that fills available height */
  scroll?: boolean;
}

/** Flat enterprise panel: thin header rule, no decoration, dense body. */
export function Panel({ title, icon, right, children, className, bodyClassName, scroll }: PanelProps) {
  return (
    <section className={cn("panel flex flex-col min-h-0 min-w-0", className)}>
      {(title || right) && (
        <header className="panel-head">
          <div className="flex items-center gap-2 min-w-0">
            {icon && <span className="text-ink3 shrink-0">{icon}</span>}
            <span className="panel-title truncate">{title}</span>
          </div>
          {right && <div className="flex items-center gap-2 shrink-0">{right}</div>}
        </header>
      )}
      <div className={cn("min-h-0 flex-1", scroll && "overflow-y-auto scroll", bodyClassName)}>
        {children}
      </div>
    </section>
  );
}
