import { getAcceptedEpssDate } from "../../../../../src/lib/priority";
import { apiPreflight, withApiRoute } from "../../_lib/api-route";
import { ApiError } from "../../_lib/errors";
import { cachedOkResponse } from "../../_lib/http-cache";
import { CVE_ID_RE } from "../../_lib/params";
import { buildProvenance } from "../../_lib/provenance";
import { detailExtras, loadFullRecords, toCveItem } from "../../_lib/records";
import { loadEpssHistory } from "../../_lib/epss-history";
import { resolveCweRefs, cweCatalogEnvelope } from "../../../../../src/lib/cwe-catalog";

export const dynamic = "force-dynamic";

export async function OPTIONS(request: Request): Promise<Response> {
  return apiPreflight(request);
}

export const GET = withApiRoute<[{ params: Promise<{ cveId: string }> }]>(
  async ({ request, db, rate }, context) => {
    const { cveId } = await context.params;
    if (!CVE_ID_RE.test(cveId)) {
      throw new ApiError("BAD_REQUEST", 400, "cveId must look like CVE-YYYY-NNNN+.");
    }
    const records = loadFullRecords(db, [cveId]);
    const record = records[0];
    if (record === undefined || record.state !== "PUBLISHED") {
      throw new ApiError("CVE_NOT_FOUND", 404, `No current PUBLISHED record for ${cveId}.`);
    }
    const extras = detailExtras(record.rawJson, record.descriptionLang);
    const history = loadEpssHistory(db, [cveId]);
    const nowIso = new Date().toISOString();
    return cachedOkResponse(
      request,
      db,
      {
        data: {
          ...toCveItem(record, getAcceptedEpssDate(db), null),
          descriptionLanguages: extras.descriptionLanguages,
          references: extras.references,
          // Detail-only taxonomy labels for `kev.cwes`, same order and deduped.
          // An absent/non-ready catalog still yields one `taxonomy-unavailable`
          // ref per id; lists omit this block deliberately (payload cost).
          cweDetails: resolveCweRefs(db, record.kevCwes),
          // Detail-only: per-date EPSS observations, oldest first, capped.
          // Lists omit it for cost; null means no observations were retained.
          epssHistory: history.get(cveId) ?? null,
        },
        // Additive envelope provenance for the taxonomy block above: the accepted
        // catalog version is what the UI labels mitigation guidance with.
        cweCatalog: cweCatalogEnvelope(db),
        provenance: buildProvenance(db, nowIso),
      },
      rate,
    );
  },
);
