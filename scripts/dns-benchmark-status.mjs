// DNS response codes that indicate the resolver could not process a valid query.
// NXDOMAIN (3) is a legitimate negative DNS answer, not a resolver outage.
export function isDnsProbeFailure(sample) {
  return Object.hasOwn(sample, 'error') || [1, 2, 4, 5].includes(sample.rcode);
}
