import type { ReactNode } from "react";

type PageHeaderProps = {
  eyebrow: ReactNode;
  title: ReactNode;
  lede?: ReactNode;
  actions?: ReactNode;
};

export function PageHeader({ eyebrow, title, lede, actions }: PageHeaderProps) {
  return (
    <div className="page-head">
      <div>
        <div className="page-eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        {lede ? <p className="page-lede">{lede}</p> : null}
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </div>
  );
}
