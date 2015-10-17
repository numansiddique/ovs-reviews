/* Copyright (c) 2015 Red Hat
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "lflow.h"
#include "match.h"
#include "ofctrl.h"
#include "ofp-actions.h"
#include "ofpbuf.h"
#include "ovn-controller.h"

/* Adds the flows in the OFTABLE_CONTROLLER table to
 * forward the packets to the controller to handle
 *
 */
void
ofcontroller_add_flows(struct sbrec_port_binding *binding,
		       struct hmap *flow_table)
{
    struct match match;
    struct ofpbuf ofpacts;
    struct eth_addr mac;
    ovs_be32 ipv4;
    ofpbuf_init(&ofpacts, 0);
    for (size_t i = 0; i < binding->n_mac; i++) {
	if (!ovs_scan(binding->mac[i],
		    ETH_ADDR_SCAN_FMT" "IP_SCAN_FMT,
		    ETH_ADDR_SCAN_ARGS(mac), IP_SCAN_ARGS(&ipv4))) {
	    continue;
	}
	match_init_catchall(&match);
	ofpbuf_clear(&ofpacts);
	match_set_metadata(&match, htonll(binding->datapath->tunnel_key));
	match_set_dl_src(&match, mac);
	match_set_dl_type(&match, htons(ETH_TYPE_IP));
	match_set_nw_proto(&match, IPPROTO_UDP);
	match_set_tp_src(&match, htons(ofp_to_u16(68)));
	match_set_tp_dst(&match, htons(ofp_to_u16(67)));
	ofpact_put_SET_IPV4_SRC(&ofpacts)->ipv4 = ipv4;
	struct ofpact_controller *controller = ofpact_put_CONTROLLER(&ofpacts);
	controller->max_len = UINT16_MAX;
	controller->controller_id = 0;
	controller->reason = OFPR_ACTION;

	ofctrl_add_flow(flow_table, OFTABLE_CONTROLLER, 50,
			&match, &ofpacts);
    }
}

