/**
 * Android Binary XML (AXML) Decoder
 * High-accuracy decoder for AndroidManifest.xml and all compiled XML layout/res resources
 */

import { ArscParsedData } from './arsc-parser';

// Standard Android Framework Attribute Resource IDs
const ANDROID_ATTR_MAP: Record<number, string> = {
  0x01010000: 'theme',
  0x01010001: 'label',
  0x01010002: 'icon',
  0x01010003: 'name',
  0x01010004: 'authorities',
  0x01010005: 'grantUriPermissions',
  0x01010006: 'permission',
  0x01010007: 'protectionLevel',
  0x01010008: 'permissionGroup',
  0x01010009: 'description',
  0x0101000c: 'configChanges',
  0x0101000e: 'launchMode',
  0x0101000f: 'versionCode',
  0x01010010: 'exported',
  0x01010011: 'process',
  0x01010012: 'taskAffinity',
  0x01010013: 'multiprocess',
  0x01010014: 'finishOnTaskLaunch',
  0x01010015: 'clearTaskOnLaunch',
  0x01010018: 'stateNotNeeded',
  0x01010019: 'excludeFromRecents',
  0x0101001e: 'screenOrientation',
  0x01010020: 'readPermission',
  0x01010021: 'writePermission',
  0x01010024: 'debuggable',
  0x01010025: 'enabled',
  0x01010028: 'hasCode',
  0x01010029: 'persistent',
  0x0101002b: 'host',
  0x0101002c: 'port',
  0x0101002d: 'path',
  0x0101002e: 'scheme',
  0x01010038: 'mimeType',
  0x0101020c: 'minSdkVersion',
  0x0101021b: 'versionName',
  0x01010226: 'anyDensity',
  0x01010269: 'largeHeap',
  0x01010270: 'targetSdkVersion',
  0x01010281: 'extractNativeLibs',
  0x0101028e: 'installLocation',
  0x010102b7: 'allowBackup',
  0x010102bf: 'fullBackupContent',
  0x010102c9: 'hardwareAccelerated',
  0x010102cd: 'supportsRtl',
  0x010103e6: 'protectionLevel',
  0x01010440: 'usesCleartextTraffic',
  0x010104ec: 'usesCleartextTraffic',
  0x010104fc: 'networkSecurityConfig',
  0x01010543: 'preserveLegacyExternalStorage',
  0x0101057e: 'appComponentFactory',
  0x0101058a: 'requestLegacyExternalStorage',
};

export function decodeAxml(
  buffer: ArrayBuffer | Uint8Array,
  arscData?: ArscParsedData
): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);

  // Check if it is already plain text XML
  const textSample = new TextDecoder('utf-8', { fatal: false }).decode(bytes.slice(0, 100));
  if (textSample.trim().startsWith('<?xml') || textSample.trim().startsWith('<manifest') || textSample.trim().startsWith('<resources')) {
    return new TextDecoder('utf-8').decode(bytes);
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  if (bytes.length < 8) {
    return '<!-- Error: Invalid AXML binary (file too short) -->';
  }

  const magic = view.getUint32(0, true);
  if (magic !== 0x00080003) {
    try {
      const decoded = new TextDecoder('utf-8').decode(bytes);
      if (decoded.includes('<manifest') || decoded.includes('package=')) {
        return decoded;
      }
    } catch {
      // ignore
    }
    return `<!-- Notice: Non-standard AXML magic: 0x${magic.toString(16)}. String Stream Extracted -->\n` + extractStringsFromBinary(bytes);
  }

  try {
    let pos = 8;
    let stringPool: string[] = [];
    const resourceMap: number[] = [];
    const xmlLines: string[] = ['<?xml version="1.0" encoding="utf-8"?>'];
    let indent = 0;
    const namespaces: { prefix: string; uri: string }[] = [];

    while (pos < bytes.length) {
      if (pos + 8 > bytes.length) break;
      const chunkType = view.getUint32(pos, true);
      const chunkSize = view.getUint32(pos + 4, true);

      if (chunkSize <= 0 || pos + chunkSize > bytes.length + 4) {
        break;
      }

      switch (chunkType) {
        case 0x001c0001: {
          // String Pool
          stringPool = parseStringPool(bytes, pos);
          break;
        }

        case 0x00080180: {
          // Resource Map
          const resCount = (chunkSize - 8) / 4;
          for (let r = 0; r < resCount; r++) {
            if (pos + 8 + r * 4 + 4 <= bytes.length) {
              resourceMap.push(view.getUint32(pos + 8 + r * 4, true));
            }
          }
          break;
        }

        case 0x00100100: {
          // START_NAMESPACE
          const prefixIdx = view.getInt32(pos + 16, true);
          const uriIdx = view.getInt32(pos + 20, true);
          const prefix = prefixIdx >= 0 && prefixIdx < stringPool.length ? stringPool[prefixIdx] : 'android';
          const uri = uriIdx >= 0 && uriIdx < stringPool.length ? stringPool[uriIdx] : 'http://schemas.android.com/apk/res/android';
          namespaces.push({ prefix, uri });
          break;
        }

        case 0x00100101: {
          // END_NAMESPACE
          namespaces.pop();
          break;
        }

        case 0x00100102: {
          // START_TAG
          const nameIdx = view.getInt32(pos + 20, true);
          const attrCount = view.getUint16(pos + 28, true);

          const tagName = nameIdx >= 0 && nameIdx < stringPool.length ? stringPool[nameIdx] : 'tag';
          let line = `${'    '.repeat(indent)}<${tagName}`;

          // Root Manifest Element namespace injection
          if (indent === 0) {
            line += ' xmlns:android="http://schemas.android.com/apk/res/android"';
            for (const ns of namespaces) {
              if (ns.prefix && ns.prefix !== 'android') {
                line += ` xmlns:${ns.prefix}="${ns.uri}"`;
              }
            }
          }

          let attrOffset = pos + 36;
          for (let i = 0; i < attrCount; i++) {
            if (attrOffset + 20 > bytes.length) break;

            const attrNsIdx = view.getInt32(attrOffset, true);
            const attrNameIdx = view.getInt32(attrOffset + 4, true);
            const attrValIdx = view.getInt32(attrOffset + 8, true);
            const attrType = view.getUint32(attrOffset + 12, true) >> 24;
            const attrData = view.getUint32(attrOffset + 16, true);

            const attrNs = attrNsIdx >= 0 && attrNsIdx < stringPool.length ? stringPool[attrNsIdx] : '';
            let rawAttrName = attrNameIdx >= 0 && attrNameIdx < stringPool.length ? stringPool[attrNameIdx] : '';

            // Resolve from Resource Map if available and missing
            if (!rawAttrName && attrNameIdx >= 0 && attrNameIdx < resourceMap.length) {
              const resId = resourceMap[attrNameIdx];
              if (ANDROID_ATTR_MAP[resId]) {
                rawAttrName = ANDROID_ATTR_MAP[resId];
              }
            }

            // Fallback for mapped Android attribute IDs
            if (attrNameIdx >= 0 && attrNameIdx < resourceMap.length && ANDROID_ATTR_MAP[resourceMap[attrNameIdx]]) {
              rawAttrName = ANDROID_ATTR_MAP[resourceMap[attrNameIdx]];
            }

            if (!rawAttrName) {
              rawAttrName = `attr_${i}`;
            }

            let attrName = rawAttrName;
            if (attrNs.includes('android') || attrNsIdx >= 0 || ANDROID_ATTR_MAP[resourceMap[attrNameIdx] || 0]) {
              if (!attrName.startsWith('android:')) {
                attrName = `android:${attrName}`;
              }
            }

            // Read attribute value
            let attrValue = '';
            if (attrValIdx >= 0 && attrValIdx < stringPool.length && stringPool[attrValIdx]) {
              attrValue = stringPool[attrValIdx];
            } else {
              attrValue = formatAttributeData(attrType, attrData, arscData);
            }

            // Escape XML entities
            const safeVal = String(attrValue)
              .replace(/&/g, '&amp;')
              .replace(/"/g, '&quot;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;');

            line += ` ${attrName}="${safeVal}"`;
            attrOffset += 20;
          }

          line += '>';
          xmlLines.push(line);
          indent++;
          break;
        }

        case 0x00100103: {
          // END_TAG
          const nameIdx = view.getInt32(pos + 20, true);
          const tagName = nameIdx >= 0 && nameIdx < stringPool.length ? stringPool[nameIdx] : 'tag';
          indent = Math.max(0, indent - 1);
          xmlLines.push(`${'    '.repeat(indent)}</${tagName}>`);
          break;
        }

        case 0x00100104: {
          // CDATA / TEXT
          const dataIdx = view.getInt32(pos + 16, true);
          if (dataIdx >= 0 && dataIdx < stringPool.length) {
            xmlLines.push(`${'    '.repeat(indent)}${stringPool[dataIdx]}`);
          }
          break;
        }
      }

      pos += chunkSize;
    }

    return postProcessXml(xmlLines.join('\n'));
  } catch {
    return extractStringsFromBinary(bytes);
  }
}

function parseStringPool(bytes: Uint8Array, startPos: number): string[] {
  if (startPos + 28 > bytes.length) return [];
  const view = new DataView(bytes.buffer, bytes.byteOffset + startPos);
  const stringCount = view.getUint32(8, true);
  const flags = view.getUint32(16, true);
  const stringsStart = view.getUint32(20, true);
  const isUtf8 = (flags & (1 << 8)) !== 0;

  const stringOffsets: number[] = [];
  for (let i = 0; i < Math.min(stringCount, 25000); i++) {
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

function formatAttributeData(type: number, data: number, arscData?: ArscParsedData): string {
  switch (type) {
    case 0x03: // TYPE_STRING
      return `str_${data}`;
    case 0x10: // TYPE_INT_DEC
      return `${data}`;
    case 0x11: // TYPE_INT_HEX
      return `0x${data.toString(16)}`;
    case 0x12: // TYPE_INT_BOOLEAN
      return data !== 0 ? 'true' : 'false';
    case 0x01: { // TYPE_REFERENCE
      if (arscData && arscData.idToName.has(data)) {
        const name = arscData.idToName.get(data)!;
        return `@${name}`;
      }
      return `@0x${data.toString(16).padStart(8, '0')}`;
    }
    case 0x02: // TYPE_ATTRIBUTE
      return `?0x${data.toString(16).padStart(8, '0')}`;
    case 0x1c:
    case 0x1d:
    case 0x1e:
    case 0x1f: // TYPE_INT_COLOR
      return `#${data.toString(16).padStart(8, '0')}`;
    default:
      return `${data}`;
  }
}

function postProcessXml(xml: string): string {
  // Convert empty paired tags to clean self-closing tags (e.g. <uses-permission ...></uses-permission> -> <uses-permission ... />)
  const selfClosingTags = [
    'uses-permission',
    'uses-feature',
    'permission',
    'action',
    'category',
    'data',
    'meta-data',
    'uses-library',
    'uses-sdk',
    'grant-uri-permission',
    'path-permission',
  ];

  let result = xml;
  for (const tag of selfClosingTags) {
    const regex = new RegExp(`(<${tag}[^>]*?)>\\s*<\\/${tag}>`, 'g');
    result = result.replace(regex, '$1 />');
  }

  return result;
}

function extractStringsFromBinary(bytes: Uint8Array): string {
  const strings: string[] = [];
  let current = '';
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte >= 32 && byte <= 126) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= 4) {
        strings.push(current);
      }
      current = '';
    }
  }
  return `<!-- Decompiled String Stream -->\n<manifest>\n` +
    strings.slice(0, 100).map((s) => `    <!-- ${s} -->`).join('\n') +
    '\n</manifest>';
}
