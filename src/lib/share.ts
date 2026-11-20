/**
 * The one way this product prints a share of a denominator: `count` out of
 * `total`, as a percentage string.
 *
 * The rule, in full, and why each part is there:
 *
 * - **Precision follows the size of the share.** Under 1% the second decimal is
 *   the one that moves, so a small share keeps two (`0.31%`, never `0.3%`); at
 *   1% and above one decimal is enough and reads quieter (`12.2%`).
 * - **A share is never rounded to a whole number beyond that.** The old rule
 *   printed 99.9% as `100%`, which claims a total the data does not support.
 *   An exact `.0` is still dropped — `12%`, not `12.0%` — so a whole share
 *   stays as short as the integer rule was.
 * - **Exact ends are words, not decimals.** No count is `0%`; the whole
 *   denominator is `100%`.
 * - **A small non-zero share is never flattened to zero.** Anything under 0.01%
 *   prints `<0.01%`, because `0%` there would deny data that exists.
 *
 * The boundaries are pinned in `tests/share.test.ts`, which also fails if a
 * `toFixed` glued to a `%` reappears anywhere outside this file. Every share in
 * the product goes through this function: chart tooltips, the donut centre and
 * legend, aria-labels, captions, data tables, and the stat copy in `app/page.tsx`.
 */
export function sharePercent(count: number, total: number): string {
  if (!Number.isFinite(count) || !Number.isFinite(total) || total <= 0 || count <= 0) {
    return "0%";
  }
  if (count === total) return "100%";
  const share = (count / total) * 100;
  if (share < 0.01) return "<0.01%";
  if (share < 1) return `${share.toFixed(2)}%`;
  const oneDecimal = share.toFixed(1);
  return `${oneDecimal.endsWith(".0") ? oneDecimal.slice(0, -2) : oneDecimal}%`;
}
