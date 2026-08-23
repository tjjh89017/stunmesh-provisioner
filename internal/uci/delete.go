package uci

import "github.com/tjjh89017/stunmesh-provisioner/internal/last"

// BuildDelete builds the UCI batch that removes every section
// sections records for one interface. It deletes by the exact
// recorded names only, never by a pattern such as "every section
// whose name starts with <iface>_p_" (PLAN.md 6 "Rules": "The agent
// deletes sections by the exact names that last.json records. It
// never deletes by pattern.").
//
// The order is peer sections, then route sections, then the
// interface section last -- the reverse of the order BuildInterface
// creates them in. UCI sections do not nest, so no order is required
// for correctness; this order is chosen only so the delete batch
// reads as "undo the create batch" and so tests (and a later
// integration test asserting an exact command sequence, PLAN.md
// stage 3 item 12) have one fixed order to check against.
func BuildDelete(sections last.Sections) Batch {
	var b Batch
	for _, peer := range sections.Peers {
		b = append(b, deleteCmd(peer))
	}
	for _, route := range sections.Routes {
		b = append(b, deleteCmd(route))
	}
	if sections.Interface != "" {
		b = append(b, deleteCmd(sections.Interface))
	}
	return b
}
