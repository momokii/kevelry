import type { ReactNode } from "react";

type PanelProps = {
  title: string;
  sub?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  className?: string;
  testId?: string;
};

export function Panel({
  title,
  sub,
  actions,
  children,
  footer,
  className = "",
  testId,
}: PanelProps) {
  return (
    <section className={`panel ${className}`.trim()} data-testid={testId}>
      <header className="panel-head">
        <div>
          <h2 className="panel-title">{title}</h2>
          {sub ? <p className="panel-sub">{sub}</p> : null}
        </div>
        {actions ? <div className="chart-actions">{actions}</div> : null}
      </header>
      <div className="panel-body">{children}</div>
      {footer ? <footer className="panel-foot">{footer}</footer> : null}
    </section>
  );
}
