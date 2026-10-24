import { getAcceptedEpssDate } from "../../../../../lib/priority";
import {
  ApiError,
  buildProvenance,
  CVE_ID_RE,
  detailExtras,
  errorResponse,
  getDb,
  loadFullRecords,
  okResponse,
  reserveRateLimit,
  toCveItem,
} from "../../_lib/shared";

export const dynamic = "force-dynamic";

export async function GET(
  request: Request,
  context: { params: Promise<{ cveId: string }> },
): Promise<Response> {
  let db = null;
  try {
    db = getDb();
  } catch {
    return errorResponse(request, "INTERNAL", "Unexpected failure handling the request.", null);
  }
  const rate = reserveRateLimit(request, db);
  if (rate instanceof Response) return rate;
  try {
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
    const nowIso = new Date().toISOString();
    return okResponse(
      request,
      {
        data: {
          ...toCveItem(record, getAcceptedEpssDate(db), null),
          descriptionLanguages: extras.descriptionLanguages,
          references: extras.references,
        },
        provenance: buildProvenance(db, nowIso),
      },
      rate,
    );
  } catch (error) {
    if (error instanceof ApiError) {
      return errorResponse(request, error.code, error.message, db, error.details, rate);
    }
    return errorResponse(request, "INTERNAL", "Unexpected failure handling the request.", db, undefined, rate);
  }
}
