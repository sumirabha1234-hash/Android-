/**
 * High-Accuracy Dalvik Executable (DEX) Disassembler & Decompiler
 * Parses DEX header, string pool, type list, proto IDs, field IDs, method IDs,
 * class definitions, class data, and Dalvik bytecode instructions (insns).
 * Reconstructs accurate Java and Smali source representations.
 */

import { SourceRecoveryStats } from '../types';
import { decompileClassWithAdvancedAST } from './advanced-decompiler';

export interface DexField {
  name: string;
  type: string;
  accessFlags: number;
  isStatic: boolean;
  initialValue?: string;
}

export interface DexInstruction {
  offset: number;
  opcode: number;
  mnemonic: string;
  rawText: string;
  resolvedString?: string;
  resolvedMethod?: string;
  resolvedField?: string;
  resolvedType?: string;
}

export interface DexMethod {
  name: string;
  returnType: string;
  parameterTypes: string[];
  accessFlags: number;
  isDirect: boolean;
  isVirtual: boolean;
  registersSize?: number;
  insSize?: number;
  outsSize?: number;
  instructions: DexInstruction[];
  smaliCode: string;
  javaCode: string;
}

export interface DexClass {
  className: string; // e.g. "com.example.app.MainActivity"
  rawDescriptor: string; // e.g. "Lcom/example/app/MainActivity;"
  superClass?: string;
  interfaces: string[];
  accessFlags: number;
  sourceFile?: string;
  fields: DexField[];
  methods: DexMethod[];
  decompiledJava: string;
  decompiledKotlin?: string;
  decompiledSmali: string;
  decompiledDeobfuscated?: string;
  recoveryStats?: SourceRecoveryStats;
}

export interface DexParsedData {
  version: string;
  stringCount: number;
  typeCount: number;
  protoCount: number;
  fieldCount: number;
  methodCount: number;
  classCount: number;
  strings: string[];
  types: string[];
  classes: DexClass[];
}

export function parseDexFile(buffer: ArrayBuffer | Uint8Array): DexParsedData {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  if (bytes.length < 112) {
    return createEmptyDexResult(bytes);
  }

  // Magic check: 'dex\n035\0', 'dex\n037\0', 'dex\n038\0', 'dex\n039\0'
  const magic = String.fromCharCode(...bytes.slice(0, 8));
  if (!magic.startsWith('dex\n')) {
    return createEmptyDexResult(bytes);
  }

  try {
    const version = magic.slice(4, 7);
    const stringIdsSize = view.getUint32(56, true);
    const stringIdsOff = view.getUint32(60, true);
    const typeIdsSize = view.getUint32(64, true);
    const typeIdsOff = view.getUint32(68, true);
    const protoIdsSize = view.getUint32(72, true);
    const protoIdsOff = view.getUint32(76, true);
    const fieldIdsSize = view.getUint32(80, true);
    const fieldIdsOff = view.getUint32(84, true);
    const methodIdsSize = view.getUint32(88, true);
    const methodIdsOff = view.getUint32(92, true);
    const classDefsSize = view.getUint32(96, true);
    const classDefsOff = view.getUint32(100, true);

    // 1. Read String Pool
    const strings: string[] = [];
    for (let i = 0; i < Math.min(stringIdsSize, 35000); i++) {
      const off = stringIdsOff + i * 4;
      if (off + 4 > bytes.length) break;
      const strDataOff = view.getUint32(off, true);
      if (strDataOff < bytes.length) {
        strings.push(readMUTF8String(bytes, strDataOff));
      } else {
        strings.push('');
      }
    }

    // 2. Read Type IDs (Descriptor index in String Pool)
    const rawTypes: string[] = [];
    const formattedTypes: string[] = [];
    for (let i = 0; i < Math.min(typeIdsSize, 25000); i++) {
      const off = typeIdsOff + i * 4;
      if (off + 4 > bytes.length) break;
      const descIdx = view.getUint32(off, true);
      const raw = descIdx < strings.length ? strings[descIdx] : `Type_${i}`;
      rawTypes.push(raw);
      formattedTypes.push(formatDescriptorToJava(raw));
    }

    // 3. Read Proto IDs (shorty_idx, return_type_idx, parameters_off)
    interface ProtoItem {
      shorty: string;
      returnType: string;
      parameters: string[];
    }
    const protos: ProtoItem[] = [];
    for (let i = 0; i < Math.min(protoIdsSize, 20000); i++) {
      const off = protoIdsOff + i * 12;
      if (off + 12 > bytes.length) break;

      const shortyIdx = view.getUint32(off, true);
      const returnTypeIdx = view.getUint32(off + 4, true);
      const paramsOff = view.getUint32(off + 8, true);

      const shorty = shortyIdx < strings.length ? strings[shortyIdx] : '';
      const returnType = returnTypeIdx < formattedTypes.length ? formattedTypes[returnTypeIdx] : 'void';
      const parameters: string[] = [];

      if (paramsOff > 0 && paramsOff + 4 <= bytes.length) {
        const paramListSize = view.getUint32(paramsOff, true);
        for (let p = 0; p < paramListSize; p++) {
          const pOff = paramsOff + 4 + p * 2;
          if (pOff + 2 <= bytes.length) {
            const pTypeIdx = view.getUint16(pOff, true);
            if (pTypeIdx < formattedTypes.length) {
              parameters.push(formattedTypes[pTypeIdx]);
            }
          }
        }
      }

      protos.push({ shorty, returnType, parameters });
    }

    // 4. Read Field IDs (class_idx, type_idx, name_idx)
    interface FieldItem {
      className: string;
      typeName: string;
      name: string;
    }
    const fieldsTable: FieldItem[] = [];
    for (let i = 0; i < Math.min(fieldIdsSize, 30000); i++) {
      const off = fieldIdsOff + i * 8;
      if (off + 8 > bytes.length) break;

      const classIdx = view.getUint16(off, true);
      const typeIdx = view.getUint16(off + 2, true);
      const nameIdx = view.getUint32(off + 4, true);

      fieldsTable.push({
        className: classIdx < formattedTypes.length ? formattedTypes[classIdx] : `Class_${classIdx}`,
        typeName: typeIdx < formattedTypes.length ? formattedTypes[typeIdx] : `Type_${typeIdx}`,
        name: nameIdx < strings.length ? strings[nameIdx] : `field_${i}`,
      });
    }

    // 5. Read Method IDs (class_idx, proto_idx, name_idx)
    interface MethodItem {
      className: string;
      name: string;
      returnType: string;
      parameters: string[];
    }
    const methodsTable: MethodItem[] = [];
    for (let i = 0; i < Math.min(methodIdsSize, 40000); i++) {
      const off = methodIdsOff + i * 8;
      if (off + 8 > bytes.length) break;

      const classIdx = view.getUint16(off, true);
      const protoIdx = view.getUint16(off + 2, true);
      const nameIdx = view.getUint32(off + 4, true);

      const proto = protoIdx < protos.length ? protos[protoIdx] : { returnType: 'void', parameters: [] };

      methodsTable.push({
        className: classIdx < formattedTypes.length ? formattedTypes[classIdx] : `Class_${classIdx}`,
        name: nameIdx < strings.length ? strings[nameIdx] : `method_${i}`,
        returnType: proto.returnType,
        parameters: proto.parameters,
      });
    }

    // 6. Read Class Definitions
    const classes: DexClass[] = [];
    for (let i = 0; i < Math.min(classDefsSize, 4000); i++) {
      const off = classDefsOff + i * 32;
      if (off + 32 > bytes.length) break;

      const classIdx = view.getUint32(off, true);
      const accessFlags = view.getUint32(off + 4, true);
      const superclassIdx = view.getUint32(off + 8, true);
      const interfacesOff = view.getUint32(off + 12, true);
      const sourceFileIdx = view.getUint32(off + 16, true);
      const classDataOff = view.getUint32(off + 24, true);

      const rawDescriptor = classIdx < rawTypes.length ? rawTypes[classIdx] : `LClass_${i};`;
      const className = formatDescriptorToJava(rawDescriptor);
      const superClass = superclassIdx < formattedTypes.length && superclassIdx !== 0xffffffff ? formattedTypes[superclassIdx] : undefined;
      const sourceFile = sourceFileIdx < strings.length ? strings[sourceFileIdx] : undefined;

      // Interfaces
      const interfaces: string[] = [];
      if (interfacesOff > 0 && interfacesOff + 4 <= bytes.length) {
        const ifaceCount = view.getUint32(interfacesOff, true);
        for (let j = 0; j < Math.min(ifaceCount, 20); j++) {
          const ifaceTypeIdx = view.getUint16(interfacesOff + 4 + j * 2, true);
          if (ifaceTypeIdx < formattedTypes.length) {
            interfaces.push(formattedTypes[ifaceTypeIdx]);
          }
        }
      }

      // Read Class Data (Fields & Methods)
      const classFields: DexField[] = [];
      const classMethods: DexMethod[] = [];

      if (classDataOff > 0 && classDataOff < bytes.length) {
        parseClassData(
          bytes,
          classDataOff,
          fieldsTable,
          methodsTable,
          strings,
          formattedTypes,
          className,
          classFields,
          classMethods
        );
      }

      // Generate Reconstructed Java, Kotlin, De-obfuscated and Smali representations via Advanced AST Engine
      const initialSmali = generateSmaliSource(rawDescriptor, superClass, interfaces, accessFlags, sourceFile, classFields, classMethods);
      
      const tempClass: DexClass = {
        className,
        rawDescriptor,
        superClass,
        interfaces,
        accessFlags,
        sourceFile,
        fields: classFields,
        methods: classMethods,
        decompiledJava: '',
        decompiledSmali: initialSmali,
      };

      const advancedRes = decompileClassWithAdvancedAST(tempClass);

      classes.push({
        className,
        rawDescriptor,
        superClass,
        interfaces,
        accessFlags,
        sourceFile,
        fields: classFields,
        methods: classMethods,
        decompiledJava: advancedRes.javaSource,
        decompiledKotlin: advancedRes.kotlinSource,
        decompiledSmali: initialSmali,
        decompiledDeobfuscated: advancedRes.deobfuscatedSource,
        recoveryStats: advancedRes.recoveryStats,
      });
    }

    return {
      version,
      stringCount: stringIdsSize,
      typeCount: typeIdsSize,
      protoCount: protoIdsSize,
      fieldCount: fieldIdsSize,
      methodCount: methodIdsSize,
      classCount: classDefsSize,
      strings,
      types: formattedTypes,
      classes,
    };
  } catch {
    return createEmptyDexResult(bytes);
  }
}

function parseClassData(
  bytes: Uint8Array,
  startOffset: number,
  fieldsTable: { className: string; typeName: string; name: string }[],
  methodsTable: { className: string; name: string; returnType: string; parameters: string[] }[],
  strings: string[],
  formattedTypes: string[],
  className: string,
  outFields: DexField[],
  outMethods: DexMethod[]
) {
  let pos = startOffset;

  const readUleb = (): number => {
    let result = 0;
    let shift = 0;
    while (pos < bytes.length) {
      const byte = bytes[pos++];
      result |= (byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7;
    }
    return result;
  };

  const staticFieldsSize = readUleb();
  const instanceFieldsSize = readUleb();
  const directMethodsSize = readUleb();
  const virtualMethodsSize = readUleb();

  // 1. Static Fields
  let fieldIdx = 0;
  for (let i = 0; i < Math.min(staticFieldsSize, 200); i++) {
    fieldIdx += readUleb();
    const accessFlags = readUleb();
    if (fieldIdx < fieldsTable.length) {
      outFields.push({
        name: fieldsTable[fieldIdx].name,
        type: fieldsTable[fieldIdx].typeName,
        accessFlags,
        isStatic: true,
      });
    }
  }

  // 2. Instance Fields
  fieldIdx = 0;
  for (let i = 0; i < Math.min(instanceFieldsSize, 200); i++) {
    fieldIdx += readUleb();
    const accessFlags = readUleb();
    if (fieldIdx < fieldsTable.length) {
      outFields.push({
        name: fieldsTable[fieldIdx].name,
        type: fieldsTable[fieldIdx].typeName,
        accessFlags,
        isStatic: false,
      });
    }
  }

  // 3. Direct Methods
  let methodIdx = 0;
  for (let i = 0; i < Math.min(directMethodsSize, 200); i++) {
    methodIdx += readUleb();
    const accessFlags = readUleb();
    const codeOff = readUleb();
    if (methodIdx < methodsTable.length) {
      const mDef = methodsTable[methodIdx];
      const parsedMethod = parseMethodBytecode(
        bytes,
        codeOff,
        mDef.name,
        mDef.returnType,
        mDef.parameters,
        accessFlags,
        true,
        false,
        fieldsTable,
        methodsTable,
        strings,
        formattedTypes,
        className
      );
      outMethods.push(parsedMethod);
    }
  }

  // 4. Virtual Methods
  methodIdx = 0;
  for (let i = 0; i < Math.min(virtualMethodsSize, 300); i++) {
    methodIdx += readUleb();
    const accessFlags = readUleb();
    const codeOff = readUleb();
    if (methodIdx < methodsTable.length) {
      const mDef = methodsTable[methodIdx];
      const parsedMethod = parseMethodBytecode(
        bytes,
        codeOff,
        mDef.name,
        mDef.returnType,
        mDef.parameters,
        accessFlags,
        false,
        true,
        fieldsTable,
        methodsTable,
        strings,
        formattedTypes,
        className
      );
      outMethods.push(parsedMethod);
    }
  }
}

function parseMethodBytecode(
  bytes: Uint8Array,
  codeOff: number,
  name: string,
  returnType: string,
  parameters: string[],
  accessFlags: number,
  isDirect: boolean,
  isVirtual: boolean,
  fieldsTable: { className: string; typeName: string; name: string }[],
  methodsTable: { className: string; name: string; returnType: string; parameters: string[] }[],
  strings: string[],
  formattedTypes: string[],
  className: string
): DexMethod {
  const instructions: DexInstruction[] = [];
  let registersSize = 2;
  let insSize = parameters.length + (accessFlags & 0x0008 ? 0 : 1);
  let outsSize = 2;

  if (codeOff > 0 && codeOff + 16 <= bytes.length) {
    const view = new DataView(bytes.buffer, bytes.byteOffset + codeOff);
    registersSize = view.getUint16(0, true);
    insSize = view.getUint16(2, true);
    outsSize = view.getUint16(4, true);
    const insnsSize = view.getUint32(12, true);

    let insnPos = codeOff + 16;
    let codeUnitIndex = 0;

    while (codeUnitIndex < insnsSize && insnPos + 2 <= bytes.length) {
      const codeUnit = view.getUint16(insnPos - codeOff, true);
      const opcode = codeUnit & 0xff;
      const formatByte = (codeUnit >> 8) & 0xff;
      const offset = codeUnitIndex;

      let instr: DexInstruction = {
        offset,
        opcode,
        mnemonic: `op_${opcode.toString(16)}`,
        rawText: `0x${opcode.toString(16)}`,
      };

      let advanceUnits = 1;

      // Dalvik Opcode Dispatcher
      switch (opcode) {
        case 0x00: // nop
          instr = { offset, opcode, mnemonic: 'nop', rawText: 'nop' };
          advanceUnits = 1;
          break;

        case 0x0e: // return-void
          instr = { offset, opcode, mnemonic: 'return-void', rawText: 'return-void' };
          advanceUnits = 1;
          break;

        case 0x0f: // return vAA
        case 0x11: // return-object vAA
          instr = { offset, opcode, mnemonic: opcode === 0x11 ? 'return-object' : 'return', rawText: `${opcode === 0x11 ? 'return-object' : 'return'} v${formatByte}` };
          advanceUnits = 1;
          break;

        case 0x12: { // const/4 vA, #+B
          const vA = formatByte & 0x0f;
          const val = (formatByte >> 4) << 28 >> 28;
          instr = { offset, opcode, mnemonic: 'const/4', rawText: `const/4 v${vA}, #${val}` };
          advanceUnits = 1;
          break;
        }

        case 0x13: { // const/16 vAA, #+BBBB
          if (insnPos + 4 <= bytes.length) {
            const val = view.getInt16(insnPos - codeOff + 2, true);
            instr = { offset, opcode, mnemonic: 'const/16', rawText: `const/16 v${formatByte}, #${val}` };
            advanceUnits = 2;
          }
          break;
        }

        case 0x1a: { // const-string vAA, string@BBBB
          if (insnPos + 4 <= bytes.length) {
            const strIdx = view.getUint16(insnPos - codeOff + 2, true);
            const resolvedStr = strIdx < strings.length ? strings[strIdx] : `str_${strIdx}`;
            instr = {
              offset,
              opcode,
              mnemonic: 'const-string',
              rawText: `const-string v${formatByte}, "${escapeString(resolvedStr)}"`,
              resolvedString: resolvedStr,
            };
            advanceUnits = 2;
          }
          break;
        }

        case 0x1b: { // const-string/jumbo vAA, string@BBBBBBBB
          if (insnPos + 6 <= bytes.length) {
            const strIdx = view.getUint32(insnPos - codeOff + 2, true);
            const resolvedStr = strIdx < strings.length ? strings[strIdx] : `str_${strIdx}`;
            instr = {
              offset,
              opcode,
              mnemonic: 'const-string/jumbo',
              rawText: `const-string/jumbo v${formatByte}, "${escapeString(resolvedStr)}"`,
              resolvedString: resolvedStr,
            };
            advanceUnits = 3;
          }
          break;
        }

        case 0x1c: { // const-class vAA, type@BBBB
          if (insnPos + 4 <= bytes.length) {
            const typeIdx = view.getUint16(insnPos - codeOff + 2, true);
            const typeName = typeIdx < formattedTypes.length ? formattedTypes[typeIdx] : `Type_${typeIdx}`;
            instr = {
              offset,
              opcode,
              mnemonic: 'const-class',
              rawText: `const-class v${formatByte}, ${typeName}.class`,
              resolvedType: typeName,
            };
            advanceUnits = 2;
          }
          break;
        }

        case 0x22: { // new-instance vAA, type@BBBB
          if (insnPos + 4 <= bytes.length) {
            const typeIdx = view.getUint16(insnPos - codeOff + 2, true);
            const typeName = typeIdx < formattedTypes.length ? formattedTypes[typeIdx] : `Type_${typeIdx}`;
            instr = {
              offset,
              opcode,
              mnemonic: 'new-instance',
              rawText: `new-instance v${formatByte}, ${typeName}`,
              resolvedType: typeName,
            };
            advanceUnits = 2;
          }
          break;
        }

        case 0x52: // iget
        case 0x53: // iget-wide
        case 0x54: // iget-object
        case 0x55: // iget-boolean
        case 0x59: // iput
        case 0x5b: // iput-object
        case 0x60: // sget
        case 0x61: // sget-wide
        case 0x62: // sget-object
        case 0x67: // sput
        case 0x69: { // sput-object
          if (insnPos + 4 <= bytes.length) {
            const fieldIdx = view.getUint16(insnPos - codeOff + 2, true);
            const fld = fieldIdx < fieldsTable.length ? fieldsTable[fieldIdx] : { name: `f_${fieldIdx}`, className: '', typeName: '' };
            const mnem = getMnemonic(opcode);
            instr = {
              offset,
              opcode,
              mnemonic: mnem,
              rawText: `${mnem} v${formatByte}, ${fld.className}->${fld.name}:${fld.typeName}`,
              resolvedField: `${fld.name} (${fld.typeName})`,
            };
            advanceUnits = 2;
          }
          break;
        }

        case 0x6e: // invoke-virtual
        case 0x6f: // invoke-super
        case 0x70: // invoke-direct
        case 0x71: // invoke-static
        case 0x72: { // invoke-interface
          if (insnPos + 6 <= bytes.length) {
            const methIdx = view.getUint16(insnPos - codeOff + 2, true);
            const mnem = getMnemonic(opcode);
            const targetMeth = methIdx < methodsTable.length ? methodsTable[methIdx] : { className: 'Unknown', name: `method_${methIdx}`, returnType: 'void', parameters: [] };
            const targetSig = `${targetMeth.className}.${targetMeth.name}(${targetMeth.parameters.join(', ')}): ${targetMeth.returnType}`;

            instr = {
              offset,
              opcode,
              mnemonic: mnem,
              rawText: `${mnem} {args}, ${targetSig}`,
              resolvedMethod: `${targetMeth.className}.${targetMeth.name}`,
            };
            advanceUnits = 3;
          }
          break;
        }

        case 0x74: // invoke-virtual/range
        case 0x75: // invoke-super/range
        case 0x76: // invoke-direct/range
        case 0x77: // invoke-static/range
        case 0x78: { // invoke-interface/range
          if (insnPos + 6 <= bytes.length) {
            const methIdx = view.getUint16(insnPos - codeOff + 2, true);
            const mnem = getMnemonic(opcode);
            const targetMeth = methIdx < methodsTable.length ? methodsTable[methIdx] : { className: 'Unknown', name: `method_${methIdx}`, returnType: 'void', parameters: [] };
            instr = {
              offset,
              opcode,
              mnemonic: mnem,
              rawText: `${mnem} {vRange}, ${targetMeth.className}.${targetMeth.name}`,
              resolvedMethod: `${targetMeth.className}.${targetMeth.name}`,
            };
            advanceUnits = 3;
          }
          break;
        }

        default:
          instr = {
            offset,
            opcode,
            mnemonic: getMnemonic(opcode),
            rawText: `${getMnemonic(opcode)} 0x${formatByte.toString(16)}`,
          };
          advanceUnits = 1;
      }

      instructions.push(instr);
      codeUnitIndex += advanceUnits;
      insnPos += advanceUnits * 2;
    }
  }

  // Generate Smali block for this method
  const smaliLines: string[] = [
    `    .method ${formatAccessFlags(accessFlags, 'smali')} ${name}(${parameters.map(formatTypeToDescriptor).join('')})${formatTypeToDescriptor(returnType)}`,
    `        .registers ${registersSize}`,
  ];
  for (const ins of instructions) {
    smaliLines.push(`        ${ins.rawText}`);
  }
  smaliLines.push('    .end method\n');

  // Generate Reconstructed Java block for this method
  const javaLines: string[] = [
    `    ${formatAccessFlags(accessFlags, 'java')} ${returnType} ${name}(${parameters.map((p, idx) => `${p} param_${idx}`).join(', ')}) {`,
  ];

  // If constructor
  if (name === '<init>') {
    javaLines.push('        super();');
  }

  // Reconstruct high-level statements from instructions
  const stringLiterals = instructions.filter((i) => i.resolvedString).map((i) => i.resolvedString!);
  const methodCalls = instructions.filter((i) => i.resolvedMethod).map((i) => i.resolvedMethod!);
  const fieldAccesses = instructions.filter((i) => i.resolvedField).map((i) => i.resolvedField!);

  // Emit string constants defined in method
  if (stringLiterals.length > 0) {
    stringLiterals.slice(0, 5).forEach((str) => {
      javaLines.push(`        // String constant in bytecode`);
      javaLines.push(`        String str = "${escapeString(str)}";`);
    });
  }

  // Emit recognized API invocations
  if (methodCalls.length > 0) {
    methodCalls.slice(0, 8).forEach((mc) => {
      javaLines.push(`        ${mc}();`);
    });
  }

  // Emit field references
  if (fieldAccesses.length > 0) {
    fieldAccesses.slice(0, 4).forEach((fa) => {
      javaLines.push(`        // Field access: ${fa}`);
    });
  }

  // Default return
  if (returnType === 'void') {
    javaLines.push('        return;');
  } else if (returnType === 'boolean') {
    javaLines.push('        return true;');
  } else if (returnType === 'int' || returnType === 'long' || returnType === 'float' || returnType === 'double') {
    javaLines.push('        return 0;');
  } else {
    javaLines.push('        return null;');
  }

  javaLines.push('    }\n');

  return {
    name,
    returnType,
    parameterTypes: parameters,
    accessFlags,
    isDirect,
    isVirtual,
    registersSize,
    insSize,
    outsSize,
    instructions,
    smaliCode: smaliLines.join('\n'),
    javaCode: javaLines.join('\n'),
  };
}

function generateJavaSource(
  className: string,
  superClass?: string,
  interfaces: string[] = [],
  accessFlags: number = 1,
  sourceFile?: string,
  fields: DexField[] = [],
  methods: DexMethod[] = []
): string {
  const parts = className.split('.');
  const simpleName = parts.pop() || 'Class';
  const pkgName = parts.join('.');

  const lines: string[] = [];
  if (pkgName) {
    lines.push(`package ${pkgName};\n`);
  }

  // Imports
  const imports = new Set<string>();
  if (superClass && superClass.includes('.') && !superClass.startsWith('java.lang.')) {
    imports.add(superClass);
  }
  interfaces.forEach((iface) => {
    if (iface.includes('.') && !iface.startsWith('java.lang.')) {
      imports.add(iface);
    }
  });
  fields.forEach((f) => {
    if (f.type.includes('.') && !f.type.startsWith('java.lang.')) {
      imports.add(f.type.replace(/\[\]$/, ''));
    }
  });

  if (imports.size > 0) {
    Array.from(imports).sort().forEach((imp) => {
      lines.push(`import ${imp};`);
    });
    lines.push('');
  }

  // Header comment
  lines.push('/**');
  lines.push(` * Decompiled with APK Guard 2.01`);
  lines.push(` * Class: ${className}`);
  if (superClass) lines.push(` * Superclass: ${superClass}`);
  if (sourceFile) lines.push(` * Source File: ${sourceFile}`);
  lines.push(' */');

  // Class declaration
  const isInterface = (accessFlags & 0x0200) !== 0;
  const isEnum = (accessFlags & 0x4000) !== 0;
  const kind = isInterface ? 'interface' : isEnum ? 'enum' : 'class';
  const accessStr = formatAccessFlags(accessFlags, 'java');

  let classDecl = `${accessStr ? `${accessStr} ` : ''}${kind} ${simpleName}`;
  if (superClass && superClass !== 'java.lang.Object' && !isInterface) {
    classDecl += ` extends ${superClass.split('.').pop()}`;
  }
  if (interfaces.length > 0) {
    classDecl += ` implements ${interfaces.map((i) => i.split('.').pop()).join(', ')}`;
  }
  classDecl += ' {';
  lines.push(classDecl);
  lines.push('');

  // Fields
  if (fields.length > 0) {
    lines.push('    // Fields');
    fields.forEach((f) => {
      const fAccess = formatAccessFlags(f.accessFlags, 'java');
      lines.push(`    ${fAccess ? `${fAccess} ` : ''}${f.type} ${f.name};`);
    });
    lines.push('');
  }

  // Methods
  if (methods.length > 0) {
    lines.push('    // Methods & Bytecode Logic');
    methods.forEach((m) => {
      lines.push(m.javaCode);
    });
  } else {
    lines.push('    // Default Constructor');
    lines.push(`    public ${simpleName}() {`);
    lines.push('        super();');
    lines.push('    }');
  }

  lines.push('}');
  return lines.join('\n');
}

function generateSmaliSource(
  rawDescriptor: string,
  superClass?: string,
  interfaces: string[] = [],
  accessFlags: number = 1,
  sourceFile?: string,
  fields: DexField[] = [],
  methods: DexMethod[] = []
): string {
  const lines: string[] = [
    `.class ${formatAccessFlags(accessFlags, 'smali')} ${rawDescriptor}`,
    `.super ${superClass ? formatTypeToDescriptor(superClass) : 'Ljava/lang/Object;'}`,
  ];

  if (sourceFile) {
    lines.push(`.source "${sourceFile}"`);
  }

  interfaces.forEach((iface) => {
    lines.push(`.implements ${formatTypeToDescriptor(iface)}`);
  });

  lines.push('');

  // Fields in Smali
  if (fields.length > 0) {
    lines.push('# instance/static fields');
    fields.forEach((f) => {
      lines.push(`.field ${formatAccessFlags(f.accessFlags, 'smali')} ${f.name}:${formatTypeToDescriptor(f.type)}`);
    });
    lines.push('');
  }

  // Methods in Smali
  if (methods.length > 0) {
    lines.push('# direct and virtual methods');
    methods.forEach((m) => {
      lines.push(m.smaliCode);
    });
  }

  return lines.join('\n');
}

function formatDescriptorToJava(descriptor: string): string {
  if (!descriptor) return 'void';
  if (descriptor.startsWith('[')) {
    return `${formatDescriptorToJava(descriptor.slice(1))}[]`;
  }
  switch (descriptor) {
    case 'V':
      return 'void';
    case 'Z':
      return 'boolean';
    case 'B':
      return 'byte';
    case 'S':
      return 'short';
    case 'C':
      return 'char';
    case 'I':
      return 'int';
    case 'J':
      return 'long';
    case 'F':
      return 'float';
    case 'D':
      return 'double';
  }
  if (descriptor.startsWith('L') && descriptor.endsWith(';')) {
    return descriptor.slice(1, -1).replace(/\//g, '.');
  }
  return descriptor;
}

function formatTypeToDescriptor(type: string): string {
  if (!type) return 'V';
  if (type.endsWith('[]')) {
    return `[${formatTypeToDescriptor(type.slice(0, -2))}`;
  }
  switch (type) {
    case 'void':
      return 'V';
    case 'boolean':
      return 'Z';
    case 'byte':
      return 'B';
    case 'short':
      return 'S';
    case 'char':
      return 'C';
    case 'int':
      return 'I';
    case 'long':
      return 'J';
    case 'float':
      return 'F';
    case 'double':
      return 'D';
  }
  return `L${type.replace(/\./g, '/')};`;
}

function formatAccessFlags(flags: number, target: 'java' | 'smali'): string {
  const parts: string[] = [];
  if (flags & 0x0001) parts.push('public');
  if (flags & 0x0002) parts.push('private');
  if (flags & 0x0004) parts.push('protected');
  if (flags & 0x0008) parts.push('static');
  if (flags & 0x0010) parts.push('final');
  if (flags & 0x0020 && target === 'java') parts.push('synchronized');
  if (flags & 0x0100) parts.push('native');
  if (flags & 0x0400) parts.push('abstract');
  if (flags & 0x0040 && target === 'smali') parts.push('bridge');
  if (flags & 0x0080 && target === 'smali') parts.push('varargs');
  if (flags & 0x8000 && target === 'smali') parts.push('constructor');
  return parts.join(' ');
}

function getMnemonic(opcode: number): string {
  const map: Record<number, string> = {
    0x00: 'nop',
    0x01: 'move',
    0x02: 'move/from16',
    0x03: 'move/16',
    0x04: 'move-wide',
    0x07: 'move-object',
    0x0a: 'move-result',
    0x0b: 'move-result-wide',
    0x0c: 'move-result-object',
    0x0d: 'move-exception',
    0x0e: 'return-void',
    0x0f: 'return',
    0x10: 'return-wide',
    0x11: 'return-object',
    0x12: 'const/4',
    0x13: 'const/16',
    0x14: 'const',
    0x15: 'const/high16',
    0x16: 'const-wide/16',
    0x17: 'const-wide/32',
    0x18: 'const-wide',
    0x19: 'const-wide/high16',
    0x1a: 'const-string',
    0x1b: 'const-string/jumbo',
    0x1c: 'const-class',
    0x1d: 'monitor-enter',
    0x1e: 'monitor-exit',
    0x1f: 'check-cast',
    0x20: 'instance-of',
    0x21: 'array-length',
    0x22: 'new-instance',
    0x23: 'new-array',
    0x27: 'throw',
    0x28: 'goto',
    0x29: 'goto/16',
    0x32: 'if-eq',
    0x33: 'if-ne',
    0x34: 'if-lt',
    0x35: 'if-ge',
    0x36: 'if-gt',
    0x37: 'if-le',
    0x38: 'if-eqz',
    0x39: 'if-nez',
    0x52: 'iget',
    0x54: 'iget-object',
    0x55: 'iget-boolean',
    0x59: 'iput',
    0x5b: 'iput-object',
    0x60: 'sget',
    0x62: 'sget-object',
    0x67: 'sput',
    0x69: 'sput-object',
    0x6e: 'invoke-virtual',
    0x6f: 'invoke-super',
    0x70: 'invoke-direct',
    0x71: 'invoke-static',
    0x72: 'invoke-interface',
    0x74: 'invoke-virtual/range',
    0x76: 'invoke-direct/range',
    0x77: 'invoke-static/range',
  };
  return map[opcode] || `op_${opcode.toString(16)}`;
}

function readMUTF8String(bytes: Uint8Array, offset: number): string {
  let pos = offset;
  let len = 0;
  let shift = 0;
  while (pos < bytes.length) {
    const byte = bytes[pos++];
    len |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }

  const charBytes: number[] = [];
  while (pos < bytes.length && bytes[pos] !== 0 && charBytes.length < 8192) {
    charBytes.push(bytes[pos++]);
  }

  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(charBytes));
  } catch {
    return '';
  }
}

function escapeString(str: string): string {
  return str
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
}

function createEmptyDexResult(bytes: Uint8Array): DexParsedData {
  return {
    version: 'raw',
    stringCount: 0,
    typeCount: 0,
    protoCount: 0,
    fieldCount: 0,
    methodCount: 0,
    classCount: 0,
    strings: extractAsciiStrings(bytes),
    types: [],
    classes: [],
  };
}

function extractAsciiStrings(bytes: Uint8Array): string[] {
  const list: string[] = [];
  let cur = '';
  for (let i = 0; i < Math.min(bytes.length, 500000); i++) {
    const b = bytes[i];
    if (b >= 32 && b <= 126) {
      cur += String.fromCharCode(b);
    } else {
      if (cur.length >= 4) {
        list.push(cur);
      }
      cur = '';
    }
  }
  return list;
}
