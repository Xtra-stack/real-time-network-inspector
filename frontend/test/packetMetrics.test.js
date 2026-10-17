import test from "node:test";
import assert from "node:assert/strict";
import { buildProtocolDistribution, getProtocolDistributionTotal } from "../src/utils/packetMetrics.js";

test("protocol distribution totals exactly the supplied packet collection", () => {
  const packets = [
    { protocol: "TCP" },
    { protocol: "UDP" },
    { protocol: "TCP" },
    { protocol: "UNKNOWN" }
  ];
  const distribution = buildProtocolDistribution(packets);

  assert.equal(getProtocolDistributionTotal(distribution), packets.length);
  assert.deepEqual(distribution, [
    { protocol: "TCP", count: 2 },
    { protocol: "UDP", count: 1 },
    { protocol: "UNKNOWN", count: 1 }
  ]);
});