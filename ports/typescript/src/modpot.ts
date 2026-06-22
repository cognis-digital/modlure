// TypeScript port of the modpot CORE check: decode a Modbus/TCP frame (hex)
// and classify it into a severity. Zero runtime dependencies.

export interface ModpotEvent {
  function_code: number;
  function_name: string;
  category: "read" | "write" | "control" | "unknown";
  severity: "info" | "low" | "medium" | "high";
  address: number | null;
  quantity: number | null;
  reasons: string[];
}

const FUNCTION_NAMES: Record<number, string> = {
  0x01: "read_coils", 0x02: "read_discrete_inputs",
  0x03: "read_holding_registers", 0x04: "read_input_registers",
  0x05: "write_single_coil", 0x06: "write_single_register",
  0x0f: "write_multiple_coils", 0x10: "write_multiple_registers",
  0x16: "mask_write_register", 0x17: "read_write_multiple_registers",
  0x2b: "encapsulated_interface_transport", 0x08: "diagnostics",
  0x11: "report_server_id",
};
const READ_CODES = new Set([0x01, 0x02, 0x03, 0x04]);
const WRITE_CODES = new Set([0x05, 0x06, 0x0f, 0x10, 0x16]);
const SUSPICIOUS_CODES = new Set([0x08, 0x11, 0x2b, 0x16]);

export function cleanHex(s: string): string {
  return (s.match(/[0-9a-fA-F]/g) || []).join("");
}

export function decodeHex(s: string): number[] {
  let h = cleanHex(s);
  if (h.length % 2 !== 0) h = h.slice(0, -1);
  const out: number[] = [];
  for (let i = 0; i < h.length; i += 2) out.push(parseInt(h.slice(i, i + 2), 16));
  return out;
}

export function parseAndClassify(buf: number[]): ModpotEvent {
  if (buf.length < 8) throw new Error("frame too short");
  const pid = (buf[2] << 8) | buf[3];
  if (pid !== 0) throw new Error(`bad protocol id 0x${pid.toString(16)}`);
  const length = (buf[4] << 8) | buf[5];
  if (length < 2) throw new Error(`bad MBAP length ${length}`);
  const fc = buf[7];
  const body = buf.slice(8);
  const name = FUNCTION_NAMES[fc] || `unknown_0x${fc.toString(16).padStart(2, "0")}`;
  let address: number | null = null;
  let quantity: number | null = null;
  if (READ_CODES.has(fc) && body.length >= 4) {
    address = (body[0] << 8) | body[1];
    quantity = (body[2] << 8) | body[3];
  } else if ((fc === 0x05 || fc === 0x06) && body.length >= 4) {
    address = (body[0] << 8) | body[1];
  }

  let category: ModpotEvent["category"];
  if (WRITE_CODES.has(fc)) category = "write";
  else if (READ_CODES.has(fc)) category = "read";
  else if (FUNCTION_NAMES[fc]) category = "control";
  else category = "unknown";

  let severity: ModpotEvent["severity"] = "info";
  const reasons: string[] = [];
  if (category === "read") {
    severity = "low";
    if (quantity !== null && quantity > 125) {
      severity = "medium";
      reasons.push(`oversized read quantity ${quantity} (>125)`);
    }
  }
  if (category === "write") {
    severity = "high";
    reasons.push("register/coil write attempt against control device");
  }
  if (SUSPICIOUS_CODES.has(fc)) {
    severity = "high";
    reasons.push(`suspicious function ${name} (recon/tamper)`);
  }
  if (category === "unknown") {
    severity = "medium";
    reasons.push("unknown function code (scanner/fuzzing)");
  }
  if (reasons.length === 0) reasons.push("benign register read");

  return { function_code: fc, function_name: name, category, severity, address, quantity, reasons };
}
