# Kevelry v4 launch film — v2 plan: recorded interactions

**Target:** `video-maker/projects/kevelry-v4` (HyperFrames 0.9.69, 1920×1080, 30 fps) · **Status:** plan
only — no scene edited, no render made · **Against:** v1 at
`renders/kevelry-v4_20261127-133734.mp4` (56.0 s) · **Live app:** `http://100.124.184.116:3100/assistant`
(4.0.7) · **Predecessor:** `SPEC.md` + `REVIEW.md` in that project.

Three review notes drive this: `s2-problem` is one sentence on an empty canvas; `s9-numbers`
(`1138 unit tests · 165 browser tests` / `~$0.002`) is information nobody asked for; and six of nine
scenes are stills, so the film claims typing, attaching and refusing without ever showing them.

## Part A — probe (Playwright 1.64.1, live app): recorded interactions are feasible

| Question                    | Measured answer                                                                                                                                                                                                                                                                                          |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Does `recordVideo` work?    | Yes. The probe take (`type-and-answer.webm`) — VP9, yuv420p, **1920×1080**, **25 fps CFR**, 689 frames, 27.56 s, 4.71 MB                                                                                                                                                                                 |
| Cursor captured?            | **Yes.** 432 cursor px inside a 60×60 box at the parked point (95.6 % of a 12 px disc); 13 distinct centroids across 34 frames of one glide; the same script with injection off → **0 px**. The arrow variant of the cursor was recorded in the same rig and is visible on the 5.60 s and 5.80 s frames. |
| Does 2× DSF survive?        | **No.** Video size follows the CSS viewport: 1440×900 @ DSF 2 → 1440×900; 1920×1080 @ DSF 1 and @ DSF 2 → both 1920×1080. DSF only changes antialiasing (mean \|Laplacian\| 8.12 → 7.74, −4.7 %). Device pixel ratio is wasted on the clip.                                                              |
| Are trim points measurable? | **Yes.** A 120 ms accent flash as t=0 in the recording: flash frame at 1.84 s, `sendClick` marker at +3.94 s → 5.78 s predicted; frame 5.60 s still shows the draft and the cursor on Send, frame 5.80 s already shows the turn running. Error ≤ 1 source frame (40 ms).                                 |

- `attach` — complete: thumbnail 90 ms after the file is set, "Attached with this question" plus the
  shot in the turn, consent row present, 1 323-char answer citing `CVE-2023-25914`.
- `refusal` — complete in **1.3 s**: "That question is outside what this desk answers." + `AI_REFUSED`.
- `type-and-answer` — **3 of 5 takes completed** (23.5 s, 33.9 s, 41.4 s, 1 321–1 702 chars, 3 tool
  calls, 50 records cited). Two aborted with "The turn ended before it wrote an answer." So a take is
  only usable if it is verified, not because it was recorded.

**Embedding contract** (`hyperframes/references/format.md`, `SKILL.md`): silent footage is
`muted playsinline` (`video_missing_muted`: "A timed `<video>` gets `data-has-audio="true"` or
`muted`"); the video carries its own timing, "Time the `<video>`; its wrapper stays untimed and gives it
no timing"; trim and speed are attributes, "`data-media-start` — Offset into the source media (a trim)",
"`data-playback-rate` — Constant speed, 0.1–10", with a `rate` lane in `data-automation` for a ramp;
paths are "`assets/...` (no leading `/`), in sub-compositions too"; it fills the frame
(`object-fit: contain`, canvas-sized), and the root must cover it — "Raise the root's `data-duration` to
cover the new clip's end". Never `play()`, `pause()` or seek media; a camera move tweens a wrapper
inside the clip, never the media.

## Part B — the film

Root stays `data-duration="56"`; `bed.m4a` (56.0 s) is reused untouched, so the v2 cut needs no audio
work and changes no music, voiceover, caption track or frame rate.

| #   | scene      | slot      | source                                                           |
| --- | ---------- | --------- | ---------------------------------------------------------------- |
| 1   | `title`    | 0.0–4.4   | unchanged (frame 0 carries the wordmark)                         |
| 2   | `problem`  | 4.4–11.4  | reworked, real UI plates flanking the line                       |
| 3   | `progress` | 11.4–18.2 | **clip a, window 1** — type, Send, tool rows fire                |
| 4   | `evidence` | 18.2–25.2 | **clip a, window 2** — answer streams, tools used, cited records |
| 5   | `attach`   | 25.2–32.4 | **clip b** — Attach, thumbnail, shot in the turn, consent row    |
| 6   | `compare`  | 32.4–38.8 | still, kept (the known weakest shot)                             |
| 7   | `web`      | 38.8–44.0 | still, kept (NVD citation; claims an output, not a click)        |
| 8   | `refusal`  | 44.0–50.6 | **clip c** — the request, then the decline                       |
| 9   | `end`      | 50.6–56.0 | unchanged (mark, `Kevelry v4`, `self-hosted · one Docker image`) |

`s9-numbers` is **deleted**; `SPEC.md`'s shot list and timing table lose shot 9 and the four scenes
around it are re-slotted. Order change: `progress` now precedes `evidence`, which is the order the
product actually runs in — v1 showed the answer before the lookup that produced it.

### `problem` — the emptiness, not the sentence

Keep the three wiped lines (68 px, `411k` accent) and the feed index; put the product between them.
Two edge-to-edge plate columns, cropped 1:1 from the live app and veiled so they carry structure, not
information:

- left, 300×860 at (0, 120): a 300 px slice of the `/priority` list — record header, the KEV/EPSS/CVSS
  chips, the "KEV listed / Remediation due / Forecast tracked" strip, from the 1920×1080 capture at
  x 330, y 120;
- right, 340×860 at (1580, 120): the "How this list is ordered" card, which sits at x 1505, y 374 in
  that capture;
- both under a flat `#161513` veil at 0.72 and a 1 px `#2e2c28` edge, revealed by a clip-path wipe from
  the outer edge in 0.5 s `power3.out`, landing 0.15 s before the first line — no drift, no parallax;
- the type block re-insets to x 380 (from 96) and drops to y 420/499/578, and the top and foot rules
  follow it from x 340 to 1620, so the sentence sits between the columns instead of above a void.

Neither plate is meant to be read at 28 % — they hold rows and rules where there was nothing, and no
caption depends on them. `data-layout-ignore` on both: the crop is on purpose.

The v1 figure `411k` is stale (the same day's capture reads `414001 published`); bind it to
`data-var-text="corpusCount"` so a re-capture updates the film without touching the scene.

### The three clips

Each is a scene with one `<video class="clip" muted playsinline data-media-start data-duration>` inside
an untimed `.cam` wrapper; the camera tweens the wrapper (1.00 → 1.04 `power2.inOut`), never the media.
The recording frame is the delivery frame, so 1.00× needs no push:

| clip                | how it is recorded                                                                                         | trim (from the take's marker JSON)                                                                              | film      |
| ------------------- | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | --------- |
| a `type-and-answer` | one full take; typing is real (`keyboard.type`, 32 ms/char)                                                | w1 `[composerHover − 0.26, …]` rate 1.0 → 2.6 at `sendClick+3.2`; w2 `[answerFirstText − 0.60, clipEnd]` at 1.0 | 6.8 + 7.0 |
| b `attach`          | click the visible picker, `setInputFiles` (the OS dialog is not recordable), type, Send, wait for the shot | `[attachClick − 0.35, …]` rate 1.0 → 3.0 at `sendClick+1.2`                                                     | 7.2       |
| c `refusal`         | type the request, Send; the decline lands in 1.3 s                                                         | whole take at 1.0, then hold the card 2.3 s                                                                     | 6.6       |

The wait between typing and the answer is 20–35 s of dead time: it is cut by the rate lane in window 1
and by starting window 2 at the answer, not by playing it fast in one stretch (at 8× the rail chips
flicker). Both windows are cut from the **same** take, so the rail, the chips and the counts agree.

**Page zoom is the legibility mechanism.** At 1.0 the app's own text is 12.5–17.5 px
(`#assistant-question` 16, answer 17.5, stage line 12.5, rail 15) — under any 26 px floor. The recorder
sets `document.documentElement.style.zoom = "1.6"` and scrolls to the beat: the layout keeps its
sidebar, main column and evidence column (measured at 1200 CSS px), and text renders at 26–28 px in
source pixels, so the film gets it crisp at 1:1 instead of upscaling a punch-in. Where a 12.5 px mono
line must read (`progress`'s stage row) the window pushes 1.3× — the only upscale in the film, and the
first snapshot is where it gets judged.

**Cursor.** A DOM arrow injected before every document script, 46 px tall (4.3 % of the frame), ink
fill `#161513`, 2 px white outline, soft shadow — an arrow, not a disc: a disc at this size blots out
the label of the control it clicks. It mirrors `mousemove` / `mousedown` / `mouseup` (so its position
can never disagree with the click the film shows; the press frame is the white-inverted state), enters
from off-screen, and each glide is ≥ 0.45 s and ≤ 600 px/s because the source is 25 fps.

**Recorder.** `projects/kevelry-v4/tools/record-clip.mjs`, run from the app checkout so Playwright
resolves, writing `captures/<beat>.webm` plus `<beat>.json` (markers in ms after the flash, take
verdict). A take is kept only if `complete && answerChars > 400 && ledgerEntries ≥ 2`; otherwise it is
discarded and retaken (2 of 5 probe takes failed this). Encode for the film:
`ffmpeg -i take.webm -c:v libx264 -preset slow -crf 20 -pix_fmt yuv420p -g 25 -an -movflags +faststart`
→ measured 3.58 MB / 1.04 Mbit/s for 27.56 s; `-g 25` = one keyframe a second so the engine's seeking
never smears. Raw `.webm` stays in `captures/`, outside `assets/`; only the `.mp4` is referenced.

## Acceptance

- `hf check --json`: 0 errors, contrast 0 failures. Captions stay on v1's opaque 200 px plate, so no
  caption ever sits on clip pixels; that is the whole reason contrast stays checkable over footage.
- Every clip's primary text ≥ 26 px and the cursor ≥ 43 px at 1080p, **measured on a snapshot frame**;
  the cursor is in every clip, arrives before the control acts, and its click frame shows the pressed
  state — no click ever lands on a frame where the cursor is absent.
- No still stands in for an interaction the film claims: `progress`, `evidence`, `attach`, `refusal`
  are footage; `compare` and `web` are the only stills, and their captions name an output.
- End card intact (mark, wordmark, `self-hosted · one Docker image`, URL held ≥ 2.4 s); root
  `data-duration` 56.0, render 56.0 ± 0.04, `bed.m4a` unchanged and audible.

## Risks

- **Live-data variance:** a probe take answered "no entries falling in the next 30 days" — real, but a
  poor demo. The take rule rejects it; the caption names the action, never a count.
- **25 fps source into a 30 fps film:** 1.2 output frames per source frame. Mitigated by glide speed;
  if review still reads judder, re-record with the page at 1.75 zoom and 1.0× camera instead of 1.6.
- **`compare` and `web` stay stills.** `compare` is the known weakest shot (`REVIEW.md`): a form, not a
  table. A fourth clip (click Compare → table) is one recorder run if the three land early; `web` needs
  a question the corpus cannot answer. Neither is in this plan.
