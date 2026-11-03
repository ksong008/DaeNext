# Native UDP direction ownership

The UDP state map records the direction chosen by the first observer of a tuple.
LAN client traffic creates client-owned state. Ordinary traffic sent toward a
LAN client creates reverse-key inbound state. Later observations refresh the
timer without overwriting that direction. A client packet matching inbound
state continues the chain, allowing ordinary replies without proxying them.
After expiry, the next observer can establish a new direction.

## Proxy replies and private topology

On LAN egress, a packet whose nonzero `ingress_ifindex` matches the loaded
object's `dae0_ifindex` PARAM does not establish reverse-key inbound state. This
prevents a delayed proxy reply from taking ownership after the client's state
expires. The next client packet still undergoes routing, including proxy and
block rules. Existing client-owned state is also preserved when an ordinary
reverse packet collides with it.

`dae0_ifindex` is a load-time parameter. Rebuilding an object gives the new
object its own parameter; it does not mutate or revoke an older live object's
parameter. Compatible logical reloads retain their physical owner and parameter.
Addresses and ports alone never authenticate a proxy reply.

The private `dae0` interface and daemon network namespace are managed data-plane
resources, not general-purpose workload forwarding interfaces. Provenance is
the interface metadata, not an inspection of the sending application's identity.
A non-proxy application using that private path is consequently treated the
same way: its outgoing packet does not establish inbound ownership. A following
LAN response undergoes the configured routing and may be proxied or blocked,
rather than returning directly to that application. Deploy ordinary inbound
services outside this private path when they require normal inbound ownership.

## Limits and regression coverage

An ordinary inbound packet that arrives first after expiry can still establish
inbound ownership. This is the existing first-writer contract; the proxy-reply
exception does not solve arbitrary external tuple reuse or authenticate ordinary
incoming services. Changing it requires a separate connection-ownership design.

The native gate runs real kernel tests for expiry followed by a proxy reply,
proxy/block policy, ordinary inbound traffic, load-time provenance, and reverse
traffic colliding with client-owned state. The collision test covers the Ethernet
classifier with IPv4 and IPv6. Raw-IP paths need separate wire validation; a
packet-only test must not imply that an actual raw-IP device was exercised. Root
tests require the explicit gate environment; a local opt-out run is not evidence that the kernel cases ran.

Wire validation additionally needs to check the actual classifier and preserved
`ingress_ifindex` on the topology in use. VLAN metadata, in-band tags, bridges,
raw-IP devices, and internal link modes cannot be inferred from packet-only
test runs. Successful tested topologies do not imply support for every device,
encapsulation, namespace arrangement, or external owner of the private path.
