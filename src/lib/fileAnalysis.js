export const MAX_FILE_SIZE = 10 * 1024 * 1024;

const signatures = [
  { name: 'PDF document', key: 'pdf', bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] },
  {
    name: 'PNG image',
    key: 'png',
    bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
  },
  { name: 'JPEG image', key: 'jpeg', bytes: [0xff, 0xd8, 0xff] },
  { name: 'GIF image', key: 'gif', bytes: [0x47, 0x49, 0x46, 0x38] },
  {
    name: 'ZIP archive / Office document',
    key: 'zip',
    bytes: [0x50, 0x4b, 0x03, 0x04],
  },
  {
    name: 'ZIP archive / Office document',
    key: 'zip',
    bytes: [0x50, 0x4b, 0x05, 0x06],
  },
  { name: 'Windows executable', key: 'pe', bytes: [0x4d, 0x5a] },
  { name: 'ELF executable', key: 'elf', bytes: [0x7f, 0x45, 0x4c, 0x46] },
  {
    name: 'OLE document',
    key: 'ole',
    bytes: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1],
  },
  { name: 'GZIP archive', key: 'gzip', bytes: [0x1f, 0x8b] },
  {
    name: '7-Zip archive',
    key: '7z',
    bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c],
  },
  {
    name: 'RAR archive',
    key: 'rar',
    bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07],
  },
];
const expectedTypes = {
  pdf: ['pdf'],
  png: ['png'],
  jpg: ['jpeg'],
  jpeg: ['jpeg'],
  gif: ['gif'],
  zip: ['zip'],
  docx: ['zip'],
  xlsx: ['zip'],
  pptx: ['zip'],
  docm: ['zip'],
  xlsm: ['zip'],
  pptm: ['zip'],
  doc: ['ole'],
  xls: ['ole'],
  ppt: ['ole'],
  exe: ['pe'],
  dll: ['pe'],
  gz: ['gzip'],
  '7z': ['7z'],
  rar: ['rar'],
};
const executableTypes = new Set([
  'exe',
  'dll',
  'scr',
  'msi',
  'bat',
  'cmd',
  'ps1',
  'vbs',
  'js',
  'jar',
  'sh',
  'app',
  'com',
]);
const macroTypes = new Set(['docm', 'xlsm', 'pptm']);

export function identifySignature(bytes) {
  const found = signatures.find((signature) =>
    signature.bytes.every((byte, index) => bytes[index] === byte),
  );
  if (found) return { name: found.name, key: found.key };
  const sample = bytes.subarray(0, Math.min(bytes.length, 2048));
  let textCharacters = 0;
  for (const byte of sample)
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126))
      textCharacters++;
  if (sample.length && textCharacters / sample.length > 0.95)
    return { name: 'Plain text (heuristic)', key: 'text' };
  return { name: 'Unrecognized signature', key: 'unknown' };
}

export function calculateEntropy(bytes) {
  if (!bytes.length) return 0;
  const frequencies = new Uint32Array(256);
  for (const byte of bytes) frequencies[byte]++;
  let result = 0;
  for (const frequency of frequencies)
    if (frequency) {
      const p = frequency / bytes.length;
      result -= p * Math.log2(p);
    }
  return result;
}

export async function analyzeFile(file) {
  if (!file) throw new Error('Choose a file to inspect.');
  if (file.size > MAX_FILE_SIZE)
    throw new Error('Choose a file of 10 MB or less.');
  if (!globalThis.crypto?.subtle)
    throw new Error(
      'Secure browser cryptography is unavailable. Use HTTPS or localhost.',
    );
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const sha256 = Array.from(
    new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', buffer)),
  )
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
  const signature = identifySignature(bytes);
  const extension = file.name.toLowerCase().split('.').pop() || '';
  const expected = expectedTypes[extension];
  const mismatched = Boolean(
    expected &&
      signature.key !== 'unknown' &&
      !expected.includes(signature.key),
  );
  const doubleExtension =
    /\.(pdf|docx?|xlsx?|png|jpe?g|txt)\.(exe|scr|bat|cmd|js|vbs|ps1|msi)$/i.test(
      file.name,
    );
  const activeType =
    executableTypes.has(extension) ||
    macroTypes.has(extension) ||
    ['pe', 'elf'].includes(signature.key);
  const entropy = calculateEntropy(bytes);
  const checks = [
    {
      id: 'signature',
      label: 'File signature',
      status: signature.key === 'unknown' ? 'info' : 'present',
      title: signature.name,
      description:
        'Identified from a small set of file signatures; this does not inspect file contents for malware.',
    },
    {
      id: 'extension',
      label: 'File extension',
      status:
        mismatched || doubleExtension
          ? 'warning'
          : signature.key === 'unknown'
            ? 'info'
            : 'present',
      title: mismatched
        ? 'Extension and signature differ'
        : doubleExtension
          ? 'Double extension detected'
          : signature.key === 'unknown'
            ? 'Signature could not be verified'
            : 'No obvious mismatch',
      description: mismatched
        ? 'The file extension does not match the recognized signature. This can also happen for legitimate files.'
        : doubleExtension
          ? 'A filename appears to hide an executable extension behind a document or image extension.'
          : signature.key === 'unknown'
            ? 'The file signature was not recognized, so the extension could not be checked.'
            : 'The filename and known signature were compared where possible.',
    },
    {
      id: 'active',
      label: 'Active content',
      status: activeType ? 'warning' : 'info',
      title: activeType
        ? 'Executable or macro-enabled type'
        : 'No executable type identified',
      description: activeType
        ? 'This type may run code or contain macros. Only open it if you trust the source.'
        : 'This is based on extension and basic signatures, not a malware scan.',
    },
    {
      id: 'entropy',
      label: 'Byte entropy',
      status: 'info',
      title: `${entropy.toFixed(2)} / 8.00 bits per byte`,
      description:
        'High entropy can be normal for compressed or encrypted files; it is not evidence of malware.',
    },
  ];
  return {
    name: file.name,
    size: file.size,
    sha256,
    signature,
    checks,
    checkedAt: new Date().toISOString(),
  };
}
