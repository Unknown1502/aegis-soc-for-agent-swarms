import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  /** shown in the fallback so you know which panel crashed */
  name?: string;
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * Catches render errors in a subtree so one crashing panel can't blank the
 * whole view. It also surfaces the real error message on screen (and to the
 * console) instead of silently unmounting — which is what made the topology
 * "disappear" during the Full Demo event storm.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Keep the real stack visible for debugging the storm-time crash.
    console.error(`[ErrorBoundary${this.props.name ? `:${this.props.name}` : ""}]`, error, info);
  }

  render(): ReactNode {
    if (this.state.error) {
      return (
        <div className="flex h-full w-full flex-col items-center justify-center gap-2 p-4 text-center">
          <div className="text-[12px] font-semibold text-critical">
            {this.props.name ?? "Panel"} failed to render
          </div>
          <pre className="max-w-full overflow-auto rounded bg-surface2 p-2 text-left text-[10px] text-ink3">
            {this.state.error.message}
          </pre>
          <button
            onClick={() => this.setState({ error: null })}
            className="rounded border border-line2 px-2 py-1 text-[11px] text-ink2 hover:bg-surface3"
          >
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
