export type NoticeState = "default" | "pending" | "applied" | "dismissed";

type UpdateNoticeProps = {
  state: NoticeState;
  testId: string;
};

const COPY: Record<NoticeState, string> = {
  default: "Feed check complete. No new accepted snapshots since 08:00 UTC.",
  pending: "New accepted KEV snapshot available. Rows stay put until you apply it.",
  applied: "Update applied at 09:12 UTC. Evidence strips show the new source revisions.",
  dismissed: "Notice dismissed. The pending snapshot remains available in the source status list.",
};

export function UpdateNotice({ state, testId }: UpdateNoticeProps) {
  return (
    <div className="ledger-notice" role="status" data-testid={testId}>
      <span aria-hidden="true">{state === "pending" ? "[!]" : state === "applied" ? "[=]" : "[i]"}</span>
      <span>{COPY[state]}</span>
      {state === "pending" ? (
        <button className="ledger-notice-action" type="button" data-testid={`${testId}-action`}>
          Apply update
        </button>
      ) : null}
    </div>
  );
}
