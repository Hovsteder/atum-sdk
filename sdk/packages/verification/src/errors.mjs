export class VerificationError extends Error {
  constructor(code) { super(code); this.name = 'VerificationError'; this.code = code; }
}
