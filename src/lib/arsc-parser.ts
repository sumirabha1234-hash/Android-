/**
 * Android Binary Resource Table (resources.arsc) Parser
 * Decodes string pools, resource packages, type specs, and key-value mapping (strings.xml, colors.xml)
 */

export interface ArscResourceEntry {
  id: number;
  hexId: string;
  type: string;
  name: string;
  value: string;
}

export interface ArscParsedData {
  packageName: string;
  packageId: number;
  strings: Map<string, string>; // name -> string value
  idToString: Map<number, string>; // resId -> value
  idToName: Map<number, string>; // resId -> resource name e.g. "app_name"
  resourcesByType: Record<string, ArscResourceEntry[]>;
  generatedStringsXml: string;
  generatedColorsXml: string;
  generatedPublicXml: string;
}

const RES_TABLE_TYPE = 0x0002;
const RES_STRING_POOL_TYPE = 0x0001;
const RES_TABLE_PACKAGE_TYPE = 0x0200;
const RES_TABLE_TYPE_SPEC_TYPE = 0x0202;
const RES_TABLE_TYPE_TYPE = 0x0201;

export function parseArsc(buffer: ArrayBuffer | Uint8Array): ArscParsedData {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const result: ArscParsedData = {
    packageName: '',
    packageId: 0x7f,
    strings: new Map(),
    idToString: new Map(),
    idToName: new Map(),
    resourcesByType: {},
    generatedStringsXml: '',
    generatedColorsXml: '',
    generatedPublicXml: '',
  };

  if (bytes.length < 12) return result;

  const type = view.getUint16(0, true);
  if (type !== RES_TABLE_TYPE) return result;

  try {
    let globalStringPool: string[] = [];
    let pos = 12;

    while (pos < bytes.length) {
      if (pos + 8 > bytes.length) break;
      const chunkType = view.getUint16(pos, true);
      const headerSize = view.getUint16(pos + 2, true);
      const chunkSize = view.getUint32(pos + 4, true);

      if (chunkSize <= 0 || pos + chunkSize > bytes.length + 4) break;

      if (chunkType === RES_STRING_POOL_TYPE && globalStringPool.length === 0) {
        globalStringPool = parseStringPool(bytes, pos);
      } else if (chunkType === RES_TABLE_PACKAGE_TYPE) {
        parsePackageChunk(bytes, pos, globalStringPool, result);
      }

      pos += chunkSize;
    }
  } catch {
    // Fallback best effort
  }

  // Generate XML representations
  result.generatedStringsXml = buildStringsXml(result.resourcesByType['string'] || []);
  result.generatedColorsXml = buildColorsXml(result.resourcesByType['color'] || []);
  result.generatedPublicXml = buildPublicXml(result.resourcesByType);

  return result;
}

function parsePackageChunk(
  bytes: Uint8Array,
  startPos: number,
  globalStringPool: string[],
  result: ArscParsedData
) {
  const view = new DataView(bytes.buffer, bytes.byteOffset + startPos);
  const pkgId = view.getUint32(8, true);
  result.packageId = pkgId;

  // Read package name (UTF-16LE, 128 chars = 256 bytes starting at offset 12)
  let pkgName = '';
  for (let i = 0; i < 128; i++) {
    const charCode = view.getUint16(12 + i * 2, true);
    if (charCode === 0) break;
    pkgName += String.fromCharCode(charCode);
  }
  result.packageName = pkgName;

  const typeStringsOff = view.getUint32(268, true);
  const keyStringsOff = view.getUint32(276, true);

  let typeStrings: string[] = [];
  if (typeStringsOff > 0) {
    typeStrings = parseStringPool(bytes, startPos + typeStringsOff);
  }

  let keyStrings: string[] = [];
  if (keyStringsOff > 0) {
    keyStrings = parseStringPool(bytes, startPos + keyStringsOff);
  }

  // Iterate sub-chunks of package
  let pos = startPos + (keyStringsOff > 0 ? keyStringsOff + getChunkSize(bytes, startPos + keyStringsOff) : 288);

  while (pos < startPos + view.getUint32(4, true) && pos + 8 <= bytes.length) {
    const subType = view.getUint16(pos - startPos, true);
    const subChunkSize = view.getUint32(pos - startPos + 4, true);

    if (subChunkSize <= 0 || pos + subChunkSize > bytes.length + 4) break;

    if (subType === RES_TABLE_TYPE_TYPE) {
      parseTypeChunk(bytes, pos, pkgId, typeStrings, keyStrings, globalStringPool, result);
    }

    pos += subChunkSize;
  }
}

function parseTypeChunk(
  bytes: Uint8Array,
  startPos: number,
  pkgId: number,
  typeStrings: string[],
  keyStrings: string[],
  globalStringPool: string[],
  result: ArscParsedData
) {
  const view = new DataView(bytes.buffer, bytes.byteOffset + startPos);
  const typeId = view.getUint8(8);
  const entryCount = view.getUint32(12, true);
  const entriesStart = view.getUint32(16, true);

  const typeName = typeId > 0 && typeId <= typeStrings.length ? typeStrings[typeId - 1] : `type_${typeId}`;

  if (!result.resourcesByType[typeName]) {
    result.resourcesByType[typeName] = [];
  }

  const headerSize = view.getUint16(2, true);

  for (let i = 0; i < Math.min(entryCount, 5000); i++) {
    const entryOffsetVal = view.getInt32(headerSize + i * 4, true);
    if (entryOffsetVal < 0) continue; // NO_ENTRY = 0xFFFFFFFF

    const entryPos = startPos + entriesStart + entryOffsetVal;
    if (entryPos + 8 > bytes.length) break;

    const entryView = new DataView(bytes.buffer, bytes.byteOffset + entryPos);
    const size = entryView.getUint16(0, true);
    const flags = entryView.getUint16(2, true);
    const keyIdx = entryView.getInt32(4, true);

    const resName = keyIdx >= 0 && keyIdx < keyStrings.length ? keyStrings[keyIdx] : `res_${typeId}_${i}`;
    const resId = (pkgId << 24) | (typeId << 16) | i;
    const hexId = `0x${resId.toString(16).padStart(8, '0')}`;

    result.idToName.set(resId, resName);

    // Simple single entry (not a complex map/bag)
    if ((flags & 0x0001) === 0 && entryPos + size + 8 <= bytes.length) {
      const valType = entryView.getUint8(size + 3);
      const valData = entryView.getUint32(size + 4, true);

      let value = '';
      if (valType === 0x03) { // TYPE_STRING
        value = valData < globalStringPool.length ? globalStringPool[valData] : '';
        result.strings.set(resName, value);
        result.idToString.set(resId, value);
      } else if (valType === 0x12) { // TYPE_INT_BOOLEAN
        value = valData !== 0 ? 'true' : 'false';
      } else if (valType >= 0x1c && valType <= 0x1f) { // TYPE_INT_COLOR
        value = `#${valData.toString(16).padStart(8, '0')}`;
      } else if (valType === 0x01) { // TYPE_REFERENCE
        value = `@0x${valData.toString(16)}`;
      } else {
        value = `${valData}`;
      }

      result.resourcesByType[typeName].push({
        id: resId,
        hexId,
        type: typeName,
        name: resName,
        value,
      });
    }
  }
}

function getChunkSize(bytes: Uint8Array, pos: number): number {
  if (pos + 8 > bytes.length) return 8;
  const view = new DataView(bytes.buffer, bytes.byteOffset + pos);
  return view.getUint32(4, true);
}

function parseStringPool(bytes: Uint8Array, startPos: number): string[] {
  if (startPos + 28 > bytes.length) return [];
  const view = new DataView(bytes.buffer, bytes.byteOffset + startPos);
  const stringCount = view.getUint32(8, true);
  const flags = view.getUint32(16, true);
  const stringsStart = view.getUint32(20, true);
  const isUtf8 = (flags & (1 << 8)) !== 0;

  const stringOffsets: number[] = [];
  for (let i = 0; i < Math.min(stringCount, 50000); i++) {
    if (startPos + 28 + i * 4 + 4 > bytes.length) break;
    stringOffsets.push(view.getUint32(28 + i * 4, true));
  }

  const strings: string[] = [];
  const baseOffset = startPos + stringsStart;

  for (let i = 0; i < stringOffsets.length; i++) {
    const offset = baseOffset + stringOffsets[i];
    if (offset >= bytes.length) {
      strings.push('');
      continue;
    }

    if (isUtf8) {
      let cur = offset;
      let len = bytes[cur++];
      if (len & 0x80) len = ((len & 0x7f) << 8) | bytes[cur++];
      let byteLen = bytes[cur++];
      if (byteLen & 0x80) byteLen = ((byteLen & 0x7f) << 8) | bytes[cur++];

      const strBytes = bytes.slice(cur, cur + Math.min(byteLen, 4096));
      strings.push(new TextDecoder('utf-8', { fatal: false }).decode(strBytes));
    } else {
      let cur = offset;
      let charLen = bytes[cur] | (bytes[cur + 1] << 8);
      cur += 2;
      if (charLen & 0x8000) {
        charLen = ((charLen & 0x7fff) << 16) | (bytes[cur] | (bytes[cur + 1] << 8));
        cur += 2;
      }

      const strBytes = bytes.slice(cur, cur + Math.min(charLen * 2, 8192));
      strings.push(new TextDecoder('utf-16le', { fatal: false }).decode(strBytes));
    }
  }

  return strings;
}

function buildStringsXml(entries: ArscResourceEntry[]): string {
  const lines = ['<?xml version="1.0" encoding="utf-8"?>', '<resources>'];
  for (const entry of entries) {
    const safeVal = (entry.value || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
    lines.push(`    <string name="${entry.name}">${safeVal}</string>`);
  }
  lines.push('</resources>');
  return lines.join('\n');
}

function buildColorsXml(entries: ArscResourceEntry[]): string {
  const lines = ['<?xml version="1.0" encoding="utf-8"?>', '<resources>'];
  for (const entry of entries) {
    lines.push(`    <color name="${entry.name}">${entry.value}</color>`);
  }
  lines.push('</resources>');
  return lines.join('\n');
}

function buildPublicXml(resourcesByType: Record<string, ArscResourceEntry[]>): string {
  const lines = ['<?xml version="1.0" encoding="utf-8"?>', '<resources>'];
  for (const [type, list] of Object.entries(resourcesByType)) {
    for (const item of list) {
      lines.push(`    <public type="${type}" name="${item.name}" id="${item.hexId}" />`);
    }
  }
  lines.push('</resources>');
  return lines.join('\n');
}
