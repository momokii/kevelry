// "How this works" — the desk's three sentences, in the reader's words.
//
// The page lede is one sentence: it says where answers come from. The rest of
// the contract is a disclosure, closed until asked, because a reader who wants
// the mechanics looks for them and a reader who wants an answer should not have
// to read past them.
//
// Nothing here is a policy promise the code does not keep: the answer is written
// from tool results (`turn.ts`), an id outside them is reported unverified
// (`unverifiedNote`), and nothing is persisted (`AssistantDesk` keeps the
// transcript in state, and the storage note beside the composer says so). The
// fourth sentence exists only when the operator turned the web fallback on, so a
// deployment that cannot fetch never claims it might.
//
// It takes no state, so it is a server component: the flag comes from the page's
// own environment read, not from a client fetch.

export interface AssistantHowThisWorksProps {
  /** `AI_WEB_FETCH_ENABLED`, as the server read it for this page. */
  webEnabled: boolean;
}

export function AssistantHowThisWorks({ webEnabled }: AssistantHowThisWorksProps) {
  return (
    <details className="assistant-how" data-testid="assistant-how">
      <summary className="assistant-how-summary">How this works</summary>
      <p className="assistant-how-body" data-testid="assistant-how-body">
        Answers come from tool calls over this deployment&rsquo;s own data, not from model memory.
        Numbers come from the records listed beside the answer, and a record the dataset does not
        hold is reported missing rather than guessed. Nothing you type is stored: the transcript
        lives in this tab and a reload starts clean.
        {webEnabled ? (
          <span data-testid="assistant-how-web">
            {" "}
            When the dataset cannot answer, it may read an allow-listed page and cite the URL.
          </span>
        ) : null}
      </p>
    </details>
  );
}
