/** A random 20-character password without look-alike characters. */
export function generatePassword() {
  const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  // Only bytes below a multiple of the alphabet's length, so every character is equally likely.
  const limit = 256 - (256 % alphabet.length);
  let out = "";
  while (out.length < 20) {
    for (const b of crypto.getRandomValues(new Uint8Array(32))) {
      if (b < limit && out.length < 20) out += alphabet[b % alphabet.length];
    }
  }
  return out;
}
