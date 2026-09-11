import { KJUR, X509 } from "jsrsasign";

export interface AuthEnv {
  APP_BUNDLE_ID: string;
  SUBSCRIPTION_PRODUCT_IDS: string;
}

// Apple Root CA - G3 (public cert). Pins the StoreKit JWS x5c chain to Apple.
const APPLE_ROOT_CA_G3_B64 =
  "MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtfTjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySrMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM6BgD56KyKA==";

interface JOSEHeader {
  alg: string;
  x5c?: string[];
}

interface TransactionPayload {
  bundleId?: string;
  productId?: string;
  expiresDate?: number; // ms epoch
  revocationDate?: number;
}

function b64ToPem(b64: string): string {
  const lines = b64.match(/.{1,64}/g)?.join("\n") ?? b64;
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

function decodeSegment<T>(seg: string): T {
  const b64 = seg.replace(/-/g, "+").replace(/_/g, "/");
  const json = decodeURIComponent(
    atob(b64)
      .split("")
      .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
      .join("")
  );
  return JSON.parse(json) as T;
}

// Verify `subjectPem` was signed by `issuerPem`'s public key.
function certSignedBy(subjectPem: string, issuerPem: string): boolean {
  try {
    const subject = new X509();
    subject.readCertPEM(subjectPem);
    const issuer = new X509();
    issuer.readCertPEM(issuerPem);
    return subject.verifySignature(issuer.getPublicKey());
  } catch {
    return false;
  }
}

function certNotExpired(pem: string): boolean {
  try {
    const x = new X509();
    x.readCertPEM(pem);
    const parse = (s: string): Date | null => {
      const long = s.length > 13;
      const m = long
        ? s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/)
        : s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
      if (!m) return null;
      let y = parseInt(m[1], 10);
      if (!long) y += y < 50 ? 2000 : 1900;
      return new Date(Date.UTC(y, +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
    };
    const nb = parse(x.getNotBefore());
    const na = parse(x.getNotAfter());
    if (!nb || !na) return false;
    const now = new Date();
    return now >= nb && now <= na;
  } catch {
    return false;
  }
}

// Validate the x5c chain (leaf -> ... -> top) and anchor to the pinned Apple root.
function verifyChain(x5c: string[]): boolean {
  if (x5c.length < 2) return false;
  const pems = x5c.map(b64ToPem);

  for (let i = 0; i < pems.length - 1; i++) {
    if (!certNotExpired(pems[i])) return false;
    if (!certSignedBy(pems[i], pems[i + 1])) return false;
  }

  const top = pems[pems.length - 1];
  if (!certNotExpired(top)) return false;
  const rootPem = b64ToPem(APPLE_ROOT_CA_G3_B64);
  // Top is either an intermediate signed by Apple's root, or the root itself.
  return certSignedBy(top, rootPem) || certSignedBy(top, top);
}

export async function verifyEntitlement(
  env: AuthEnv,
  request: Request
): Promise<boolean> {
  const jws = request.headers.get("x-storekit-jws");
  if (!jws) return false;

  const parts = jws.split(".");
  if (parts.length !== 3) return false;

  let header: JOSEHeader;
  let payload: TransactionPayload;
  try {
    header = decodeSegment<JOSEHeader>(parts[0]);
    payload = decodeSegment<TransactionPayload>(parts[1]);
  } catch {
    return false;
  }

  if (header.alg !== "ES256" || !header.x5c || header.x5c.length < 2) return false;

  // 1. Chain of trust anchored to Apple Root CA G3.
  if (!verifyChain(header.x5c)) return false;

  // 2. JWS signed by the leaf cert.
  const leafPem = b64ToPem(header.x5c[0]);
  let sigOk = false;
  try {
    sigOk = KJUR.jws.JWS.verify(jws, leafPem, ["ES256"]);
  } catch {
    sigOk = false;
  }
  if (!sigOk) return false;

  // 3. Claims: our app, one of our products, not expired, not revoked.
  if (payload.bundleId !== env.APP_BUNDLE_ID) return false;
  const productIds = env.SUBSCRIPTION_PRODUCT_IDS.split(",").map((s) => s.trim());
  if (!payload.productId || !productIds.includes(payload.productId)) return false;
  if (payload.revocationDate) return false;
  if (typeof payload.expiresDate === "number" && payload.expiresDate <= Date.now())
    return false;

  return true;
}
