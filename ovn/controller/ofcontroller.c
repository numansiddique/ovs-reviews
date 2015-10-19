/* Copyright (c) 2015 Nicira, Inc.
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
#include "csum.h"
#include "dp-packet.h"
#include "dhcp.h"
#include "lflow.h"
#include "ofpbuf.h"
#include "ofp-actions.h"
#include "ofp-version-opt.h"
#include "ofp-util.h"
#include "ofp-msgs.h"
#include "ofctrl.h"
#include "socket-util.h"
#include "openflow/openflow.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "ovn-controller.h"
#include "physical.h"
#include "rconn.h"
#include "vswitch-idl.h"
#include "ofcontroller.h"

VLOG_DEFINE_THIS_MODULE(ofcontroller);

struct pvconn * pvconn;

/* Remote connection from the switch */
struct rconn *rconn = NULL;


void
ofcontroller_init(char const *sock_path)
{
    char *proto = xasprintf("punix:%s", sock_path);
    pvconn_open(proto, 0, 0, &pvconn);
    free(proto);
}


static enum ofputil_protocol get_ofp_proto(void) {
    enum ofp_version version;
    version = rconn_get_version(rconn);
    return ofputil_protocol_from_ofp_version(version);
}


static void
get_dhcp_options(char *ret, uint32_t *ret_len, uint8_t dhcp_request_type)
{
    char *start = ret;

    *(uint32_t *)ret = htonl(0x63825363); /*magic cookie*/
    ret += (sizeof(uint32_t));

    /*Dhcp option - type*/
    ret[0] = (uint8_t)53;
    ret[1] = (uint8_t)1;
    if (dhcp_request_type == 0x01) {
        /* DHCP DISCOVER. Set the dhcp message type as DHCP OFFER */
        ret[2] = (uint8_t)0x02;
    }
    else {
        /* DHCP REQUEST, set the message type as DHCP ACK */
        ret[2] = (uint8_t)0x05;
    }
    ret += 3;

    /*Dhcp server id*/
    ret[0] = (uint8_t)54;
    ret[1] = (uint8_t)4;
    *((uint32_t *)&ret[2]) = htonl(0x01010101);
    ret += 6;

    /*Subnet mask*/
    ret[0] = (uint8_t)1;
    ret[1] = (uint8_t)4;
    *((uint32_t *)&ret[2]) = htonl(0xFFFFFF00);
    ret += 6;

    /*Router*/
    ret[0] = (uint8_t)3;
    ret[1] = (uint8_t)4;
    *((uint32_t *)&ret[2]) = htonl(0xC0A80101);
    ret += 6;

    /*Lease*/
    ret[0] = (uint8_t)51;
    ret[1] = (uint8_t)4;
    *((uint32_t *)&ret[2]) = htonl(0x00000e10);
    ret += 6;

    /*Padding*/
    *((uint32_t *)ret) = 0x00000;
    ret += 4;

    /*End*/
    ret[0] = 0xFF;
    ret += 1;

    /*Padding*/
    *((uint32_t *)ret) = 0x00000;
    ret += 4;

    *ret_len = (ret - start);
}


static void
compose_dhcp_response(struct flow *in_flow,
                      struct dhcp_header const *in_dhcp,
                      struct dp_packet *out_packet,
                      uint8_t dhcp_request_type)
{
    struct eth_addr eth_addr = {.ea = {0x9a, 0x56, 0x02, 0x53, 0xc2, 0x40}};
    char options[128];
    uint32_t options_len = 0;
    get_dhcp_options(options, &options_len, dhcp_request_type);

    dp_packet_clear(out_packet);
    dp_packet_prealloc_tailroom(out_packet,
                                ETH_HEADER_LEN + \
                                IP_HEADER_LEN + \
                                UDP_HEADER_LEN + \
                                DHCP_HEADER_LEN + \
                                options_len);
    struct eth_header *eth;
    eth = dp_packet_put_zeros(out_packet, sizeof(*eth));
    eth->eth_dst = in_flow->dl_src;
    eth->eth_src = eth_addr;
    eth->eth_type = in_flow->dl_type;

    struct ip_header *ip;
    ip = dp_packet_put_zeros(out_packet, sizeof(*ip));
    ip->ip_ihl_ver = IP_IHL_VER(5, 4);
    ip->ip_tos = in_flow->nw_tos;
    ip->ip_ttl = in_flow->nw_ttl;
    ip->ip_proto = IPPROTO_UDP;
    put_16aligned_be32(&ip->ip_src, (ovs_be32) 0x0);
    put_16aligned_be32(&ip->ip_dst, in_flow->nw_dst);

    struct udp_header *udp;
    udp = dp_packet_put_zeros(out_packet, sizeof(*udp));
    udp->udp_src = htons(ofp_to_u16(67));
    udp->udp_dst = htons(ofp_to_u16(68));
    struct dhcp_header * dhcp;
    dhcp = dp_packet_put_zeros(out_packet, sizeof(*dhcp));
    memcpy(dhcp, in_dhcp, sizeof(struct dhcp_header));
    dhcp->op = 0x02;
    dhcp->yiaddr = in_flow->nw_src;

    void * opts = dp_packet_put_zeros(out_packet, options_len);
    memcpy(opts, options, options_len);

    int udp_len = sizeof(*dhcp) + options_len + UDP_HEADER_LEN;
    udp->udp_len = htons(ofp_to_u16(udp_len));
    ip->ip_tot_len = htons(ofp_to_u16(IP_HEADER_LEN + udp_len));
    ip->ip_csum = csum(ip, sizeof *ip);
    udp->udp_csum = csum(udp, sizeof(*dhcp) + options_len + UDP_HEADER_LEN);
    udp->udp_csum = 0;
}


static inline bool
is_dhcp_packet(struct flow *flow)
{
  if (flow->dl_type == htons(ETH_TYPE_IP) && \
      flow->nw_proto == IPPROTO_UDP && \
      flow->nw_dst == INADDR_BROADCAST && \
      flow->tp_src == htons(DHCP_CLIENT_PORT) && \
      flow->tp_dst == htons(DHCP_SERVER_PORT)) {
      return true;
  }
  return false;
}


static uint8_t get_dhcp_message_type(struct dhcp_header const *dhcp_data, size_t size) {
    struct dhcp_option_header {
        uint8_t option;
        uint8_t len;
    };
#define OPTION_PAYLOAD(opt) ((char *)opt + sizeof(struct dhcp_option_header))
    char const *footer = (char *)dhcp_data + sizeof(*dhcp_data);
    uint32_t cookie = *(uint32_t *)footer;

    if (cookie != htonl(0x63825363))
        /*Cookie validation failed*/
        return (uint8_t)-1;
    footer += sizeof(uint32_t);

    for (struct dhcp_option_header const *opt = (struct dhcp_option_header *)footer;
         footer < (char *)dhcp_data + size;
         footer += (sizeof(*opt) + opt->len)) {
        if (opt->option == 53) {
            return *(uint8_t *)OPTION_PAYLOAD(opt);
        }
    }
    return (uint8_t)-1;
}


static void
process_packet_in(struct ofp_header* msg)
{
    struct ofputil_packet_in pin;
    if (ofputil_decode_packet_in(&pin, msg) != 0) {
        return;
    }
    if (pin.reason != OFPR_ACTION) {
        return;
    }
    struct dp_packet packet;
    struct flow flow;
    dp_packet_use_const(&packet, pin.packet, pin.packet_len);
    flow_extract(&packet, &flow);
    if (!is_dhcp_packet(&flow)) {
        return;
    }


    struct dhcp_header const *dhcp_data = dp_packet_get_udp_payload(&packet);
    if (dhcp_data->op != 0x01) {
        return;
    }
    /*Send response*/
    struct dp_packet out;
    struct ofputil_packet_out ofpacket_out;
    struct ofpbuf ofpacts, *buf;
    uint8_t dhcp_message_type = get_dhcp_message_type(dhcp_data, dp_packet_l4_size(&packet));
    if (dhcp_message_type != 0x01 && dhcp_message_type != 0x03) {
        return;
    }

    ofpbuf_init(&ofpacts, 0);
    ofpbuf_clear(&ofpacts);
    ofpact_put_OUTPUT(&ofpacts)->port = OFPP_IN_PORT;

    compose_dhcp_response(&flow, dhcp_data, &out, dhcp_message_type);

    ofpacket_out.packet = dp_packet_data(&out);
    ofpacket_out.packet_len = dp_packet_size(&out);
    ofpacket_out.buffer_id = UINT32_MAX;
    ofpacket_out.in_port = pin.flow_metadata.flow.in_port.ofp_port;
    ofpacket_out.ofpacts = ofpacts.data;
    ofpacket_out.ofpacts_len = ofpacts.size;
    buf = ofputil_encode_packet_out(&ofpacket_out, get_ofp_proto());
    rconn_send(rconn, buf, NULL);
    ofpbuf_uninit(&ofpacts);
}


static void
process_packet(struct ofpbuf *msg)
{
    enum ofptype type;
    struct ofpbuf b;

    b = *msg;
    if (ofptype_pull(&type, &b)) {
        return;
    }
    switch (type) {
        case OFPTYPE_HELLO:
        {
            uint32_t allowed_versions;
            ofputil_decode_hello(msg->data, &allowed_versions);
            /*TODO: Negotiate*/
            break;
        }
        case OFPTYPE_ECHO_REQUEST:
        {
            struct ofpbuf *r = make_echo_reply(msg->data);
            rconn_send(rconn, r, NULL);
            break;
        }
        case OFPTYPE_FEATURES_REPLY:
            /*TODO: Finish this*/
            break;
        case OFPTYPE_PACKET_IN:
            process_packet_in(msg->data);
            break;
        case OFPTYPE_FLOW_REMOVED:
        case OFPTYPE_ERROR:
        case OFPTYPE_ECHO_REPLY:
        case OFPTYPE_FEATURES_REQUEST:
        case OFPTYPE_GET_CONFIG_REQUEST:
        case OFPTYPE_GET_CONFIG_REPLY:
        case OFPTYPE_SET_CONFIG:
        case OFPTYPE_PORT_STATUS:
        case OFPTYPE_PACKET_OUT:
        case OFPTYPE_FLOW_MOD:
        case OFPTYPE_GROUP_MOD:
        case OFPTYPE_PORT_MOD:
        case OFPTYPE_TABLE_MOD:
        case OFPTYPE_BARRIER_REQUEST:
        case OFPTYPE_BARRIER_REPLY:
        case OFPTYPE_QUEUE_GET_CONFIG_REQUEST:
        case OFPTYPE_QUEUE_GET_CONFIG_REPLY:
        case OFPTYPE_DESC_STATS_REQUEST:
        case OFPTYPE_DESC_STATS_REPLY:
        case OFPTYPE_FLOW_STATS_REQUEST:
        case OFPTYPE_FLOW_STATS_REPLY:
        case OFPTYPE_AGGREGATE_STATS_REQUEST:
        case OFPTYPE_AGGREGATE_STATS_REPLY:
        case OFPTYPE_TABLE_STATS_REQUEST:
        case OFPTYPE_TABLE_STATS_REPLY:
        case OFPTYPE_PORT_STATS_REQUEST:
        case OFPTYPE_PORT_STATS_REPLY:
        case OFPTYPE_QUEUE_STATS_REQUEST:
        case OFPTYPE_QUEUE_STATS_REPLY:
        case OFPTYPE_PORT_DESC_STATS_REQUEST:
        case OFPTYPE_PORT_DESC_STATS_REPLY:
        case OFPTYPE_ROLE_REQUEST:
        case OFPTYPE_ROLE_REPLY:
        case OFPTYPE_ROLE_STATUS:
        case OFPTYPE_REQUESTFORWARD:
        case OFPTYPE_SET_FLOW_FORMAT:
        case OFPTYPE_FLOW_MOD_TABLE_ID:
        case OFPTYPE_SET_PACKET_IN_FORMAT:
        case OFPTYPE_FLOW_AGE:
        case OFPTYPE_SET_CONTROLLER_ID:
        case OFPTYPE_FLOW_MONITOR_STATS_REQUEST:
        case OFPTYPE_FLOW_MONITOR_STATS_REPLY:
        case OFPTYPE_FLOW_MONITOR_CANCEL:
        case OFPTYPE_FLOW_MONITOR_PAUSED:
        case OFPTYPE_FLOW_MONITOR_RESUMED:
        case OFPTYPE_GET_ASYNC_REQUEST:
        case OFPTYPE_GET_ASYNC_REPLY:
        case OFPTYPE_SET_ASYNC_CONFIG:
        case OFPTYPE_METER_MOD:
        case OFPTYPE_GROUP_STATS_REQUEST:
        case OFPTYPE_GROUP_STATS_REPLY:
        case OFPTYPE_GROUP_DESC_STATS_REQUEST:
        case OFPTYPE_GROUP_DESC_STATS_REPLY:
        case OFPTYPE_GROUP_FEATURES_STATS_REQUEST:
        case OFPTYPE_GROUP_FEATURES_STATS_REPLY:
        case OFPTYPE_METER_STATS_REQUEST:
        case OFPTYPE_METER_STATS_REPLY:
        case OFPTYPE_METER_CONFIG_STATS_REQUEST:
        case OFPTYPE_METER_CONFIG_STATS_REPLY:
        case OFPTYPE_METER_FEATURES_STATS_REQUEST:
        case OFPTYPE_METER_FEATURES_STATS_REPLY:
        case OFPTYPE_TABLE_FEATURES_STATS_REQUEST:
        case OFPTYPE_TABLE_FEATURES_STATS_REPLY:
        case OFPTYPE_TABLE_DESC_REQUEST:
        case OFPTYPE_TABLE_DESC_REPLY:
        case OFPTYPE_BUNDLE_CONTROL:
        case OFPTYPE_BUNDLE_ADD_MESSAGE:
        case OFPTYPE_NXT_GENEVE_TABLE_MOD:
        case OFPTYPE_NXT_GENEVE_TABLE_REQUEST:
        case OFPTYPE_NXT_GENEVE_TABLE_REPLY:
        default:
            break;
    }
}


static void
send_hello_packet(struct rconn *rconn)
{
    struct ofpbuf *ofbuf;

    ofbuf = ofputil_encode_hello(rconn_get_allowed_versions(rconn));
    rconn_send(rconn, ofbuf, NULL);
}


void
ofcontroller_run(const struct ovsrec_bridge *br_int)
{
    struct ofpbuf *msg;
    int retval;
    struct vconn *new_vconn = NULL;

    if (br_int) {
        retval = pvconn_accept(pvconn, &new_vconn);
        if (!retval && new_vconn) {
            rconn = rconn_create(60, 0, DSCP_DEFAULT, get_allowed_ofp_versions());
            rconn_connect_unreliably(rconn, new_vconn, NULL);
            send_hello_packet(rconn);
        }
    }
    if (rconn) {
        rconn_run(rconn);
        if (!rconn_is_connected(rconn)) {
            return;
        }

        while((msg = rconn_recv(rconn)) != NULL) {
            process_packet(msg);
            ofpbuf_delete(msg);
        }
    }
}


void
ofcontroller_wait(void)
{
    if (rconn) {
        rconn_run_wait(rconn);
        rconn_recv_wait(rconn);
    }
    pvconn_wait(pvconn);
}


void
ofcontroller_add_flows(const struct sbrec_port_binding *binding,
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
