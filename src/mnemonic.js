'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.PREFIXES = void 0;
exports.words = words;
exports.generateMnemonic = generateMnemonic;
exports.mnemonicToSeedSync = mnemonicToSeedSync;
exports.mnemonicToSeed = mnemonicToSeed;
exports.validateMnemonic = validateMnemonic;
const randombytes = require('randombytes');
const createHmac = require('create-hmac');
const pbkdf2 = require('pbkdf2');
const ENGLISH = require('./wordlists/english.json');
const SPANISH = require('./wordlists/es.json');
const PORTUGUESE = require('./wordlists/pt.json');
const CHINESES = require('./wordlists/cns.json');
const JAPANESE = require('./wordlists/jp.json');
const encoding_1 = require('./encoding');
const LANGS = {
  en: ENGLISH,
  es: SPANISH,
  pt: PORTUGUESE,
  cn: CHINESES,
  jp: JAPANESE,
};
function words() {
  return LANGS;
}
const INVALID_MNEMONIC_MESSAGE = 'Invalid Seed Version for mnemonic';
exports.PREFIXES = {
  segwit: '100',
  standard: '01',
  '2fa': '101',
  '2fa-segwit': '102',
};
const DEFAULTGENOPTS = {
  prefix: exports.PREFIXES.standard,
  strength: 132, // 12 words x 2048 wordlist === 132 bits
  rng: randombytes,
  wordlist: ENGLISH,
};
function generateMnemonic(opts) {
  const { prefix, strength, rng, wordlist } = Object.assign(
    {},
    DEFAULTGENOPTS,
    opts,
  );
  validatePrefixFormat(prefix);
  if (prefix.length * 4 > strength / 2)
    throw new Error(
      `strength must be at least 2x of prefix bit count to ` +
        `lower endless loop probability.\nprefix: ${prefix} ` +
        `(${prefix.length * 4} bits)\nstrength: ${strength}`,
    );
  const wordBitLen = (0, encoding_1.bitlen)(wordlist.length);
  const wordCount = Math.ceil(strength / wordBitLen);
  const byteCount = Math.ceil((wordCount * wordBitLen) / 8);
  let result = '';
  do {
    const bytes = rng(byteCount);
    (0, encoding_1.maskBytes)(bytes, strength);
    result = (0, encoding_1.encode)(bytes, wordlist);
  } while (!prefixMatches(result, [prefix])[0]);
  return result;
}
const DEFAULTOPTS = {
  passphrase: '',
  prefix: exports.PREFIXES.standard,
  skipCheck: false,
};
function mnemonicToSeedSync(mnemonic, opts) {
  const { passphrase, prefix, skipCheck } = Object.assign(
    {},
    DEFAULTOPTS,
    opts,
  );
  validatePrefixFormat(prefix);
  if (!skipCheck) checkPrefix(mnemonic, [prefix]);
  return pbkdf2.pbkdf2Sync(
    (0, encoding_1.normalizeText)(mnemonic),
    'electrum' + (0, encoding_1.normalizeText)(passphrase),
    2048,
    64,
    'sha512',
  );
}
async function mnemonicToSeed(mnemonic, opts) {
  const { passphrase, prefix, skipCheck } = Object.assign(
    {},
    DEFAULTOPTS,
    opts,
  );
  validatePrefixFormat(prefix);
  if (!skipCheck) checkPrefix(mnemonic, [prefix]);
  return new Promise((resolve, reject) => {
    pbkdf2.pbkdf2(
      (0, encoding_1.normalizeText)(mnemonic),
      'electrum' + (0, encoding_1.normalizeText)(passphrase),
      2048,
      64,
      'sha512',
      (err, res) => {
        /* istanbul ignore next */
        if (err) return reject(err);
        else return resolve(res);
      },
    );
  });
}
function validateMnemonic(mnemonic, prefix) {
  validatePrefixFormat(prefix);
  try {
    checkPrefix(mnemonic, [prefix]);
    return true;
  } catch (e) {
    /* istanbul ignore else  */
    if (
      e &&
      e.hasOwnProperty('message') &&
      (e === null || e === void 0 ? void 0 : e.message) ===
        INVALID_MNEMONIC_MESSAGE
    ) {
      return false;
    }
    /* istanbul ignore next */
    throw e;
  }
}
function matchesAnyPrefix(mnemonic, validPrefixes) {
  return prefixMatches(mnemonic, validPrefixes).some((v) => v);
}
function validatePrefixFormat(prefix) {
  if (!prefix.match(/^[0-9a-f]+$/) || prefix.length > 128)
    throw new Error('prefix must be a hex string');
}
function checkPrefix(mn, validPrefixes) {
  if (!matchesAnyPrefix(mn, validPrefixes))
    throw new Error(INVALID_MNEMONIC_MESSAGE);
}
function prefixMatches(phrase, prefixes) {
  const hmac = createHmac('sha512', 'Seed version');
  hmac.update((0, encoding_1.normalizeText)(phrase));
  const hx = hmac.digest('hex');
  return prefixes.map((prefix) => hx.startsWith(prefix.toLowerCase()));
}
