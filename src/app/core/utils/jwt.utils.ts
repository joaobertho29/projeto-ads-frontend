export interface JwtPayload {
  iss?: string;
  sub?: string;
  iat?: number;
  exp?: number;
  nome?: string;
  perfil?: string;
  [claim: string]: unknown;
}

export function decodificarJwtPayload(token: string | null | undefined): JwtPayload | null {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const partes = token.split('.');
  if (partes.length !== 3 || !partes[1]) {
    return null;
  }

  try {
    let base64 = partes[1].replace(/-/g, '+').replace(/_/g, '/');
    const resto = base64.length % 4;
    if (resto === 1) {
      return null;
    }
    if (resto > 0) {
      base64 += '='.repeat(4 - resto);
    }

    const binario = atob(base64);
    const bytes = new Uint8Array(binario.length);
    for (let i = 0; i < binario.length; i++) {
      bytes[i] = binario.charCodeAt(i);
    }

    const json = new TextDecoder('utf-8').decode(bytes);
    const parsed = JSON.parse(json);

    if (!parsed || typeof parsed !== 'object') {
      return null;
    }

    return parsed as JwtPayload;
  } catch {
    return null;
  }
}

export function isJwtExpirado(token: string | null | undefined): boolean {
  const payload = decodificarJwtPayload(token);
  if (!payload || typeof payload.exp !== 'number' || Number.isNaN(payload.exp)) {
    return true;
  }
  return Date.now() >= payload.exp * 1000;
}