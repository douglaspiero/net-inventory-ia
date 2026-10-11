import { describe, expect, it } from "vitest";
import { isIgnoredIp, isValidIpPattern } from "./ignored-ips";

describe("isValidIpPattern", () => {
  it("aceita IP, faixa, CIDR e curinga", () => {
    for (const p of ["192.168.0.113", "192.168.0.10-192.168.0.30", "192.168.0.0/28", "192.168.0.*", " 10.* "]) {
      expect(isValidIpPattern(p)).toBe(true);
    }
  });

  it("recusa padrões malformados", () => {
    for (const p of ["", "192.168.0", "192.168.0.300", "192.168.0.1-", "192.168.0.0/33", "192.*.0.1", "abc"]) {
      expect(isValidIpPattern(p)).toBe(false);
    }
  });
});

describe("isIgnoredIp", () => {
  const list = [{ id: "1", pattern: "192.168.0.113" }, { id: "2", pattern: "10.0.0.0/30" }];

  it("casa IP exato e CIDR", () => {
    expect(isIgnoredIp("192.168.0.113", list)).toBe(true);
    expect(isIgnoredIp("10.0.0.3", list)).toBe(true);
  });

  it("não casa IPs fora da lista", () => {
    expect(isIgnoredIp("192.168.0.11", list)).toBe(false);
    expect(isIgnoredIp("10.0.0.4", list)).toBe(false);
  });
});
