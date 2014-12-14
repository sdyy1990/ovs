
#include <config.h>
#include "odp-util.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-msgs.h"
#include "ofp-parse.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "ofp-version-opt.h"
#include "ofpbuf.h"
#include "ofproto/ofproto.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "ofp-ofctllib.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofctlLIB);
struct vconn *
prepare_dump_flows(int argc, char *argv[], bool aggregate, struct ofpbuf **requestp, enum ofputil_protocol allowed_protocols)
{
    enum ofputil_protocol usable_protocols, protocol;
    struct ofputil_flow_stats_request fsr;
    struct vconn *vconn;
    char *error;

    error = parse_ofp_flow_stats_request_str(&fsr, aggregate,
                                             argc > 2 ? argv[2] : "",
                                             &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    protocol = open_vconn(argv[1], &vconn);
    protocol = set_protocol_for_flow_dump(vconn, protocol, usable_protocols, allowed_protocols);
    *requestp = ofputil_encode_flow_stats_request(&fsr, protocol);
    return vconn;
}


enum ofputil_protocol
open_vconn(const char *name, struct vconn **vconnp)
{
    return open_vconn__(name, MGMT, vconnp);
}

enum ofputil_protocol
open_vconn__(const char *name, enum open_target target,
             struct vconn **vconnp)
{
    const char *suffix = target == MGMT ? "mgmt" : "snoop";
    char *datapath_name, *datapath_type, *socket_name;
    enum ofputil_protocol protocol;
    char *bridge_path;
    int ofp_version;
    int error;

    bridge_path = xasprintf("%s/%s.%s", ovs_rundir(), name, suffix);

    ofproto_parse_name(name, &datapath_name, &datapath_type);
    socket_name = xasprintf("%s/%s.%s", ovs_rundir(), datapath_name, suffix);
    free(datapath_name);
    free(datapath_type);

    if (strchr(name, ':')) {
        run(vconn_open(name, get_allowed_ofp_versions(), DSCP_DEFAULT, vconnp),
            "connecting to %s", name);
    } else if (!open_vconn_socket(name, vconnp)) {
        /* Fall Through. */
    } else if (!open_vconn_socket(bridge_path, vconnp)) {
        /* Fall Through. */
    } else if (!open_vconn_socket(socket_name, vconnp)) {
        /* Fall Through. */
    } else {
        ovs_fatal(0, "%s is not a bridge or a socket", name);
    }

    if (target == SNOOP) {
        vconn_set_recv_any_version(*vconnp);
    }

    free(bridge_path);
    free(socket_name);

    VLOG_DBG("connecting to %s", vconn_get_name(*vconnp));
    error = vconn_connect_block(*vconnp);
    if (error) {
        ovs_fatal(0, "%s: failed to connect to socket (%s)", name,
                  ovs_strerror(error));
    }

    ofp_version = vconn_get_version(*vconnp);
    protocol = ofputil_protocol_from_ofp_version(ofp_version);
    if (!protocol) {
        ovs_fatal(0, "%s: unsupported OpenFlow version 0x%02x",
                  name, ofp_version);
    }
    return protocol;
}

enum ofputil_protocol
set_protocol_for_flow_dump(struct vconn *vconn,
                           enum ofputil_protocol cur_protocol,
                           enum ofputil_protocol usable_protocols,
                           enum ofputil_protocol allowed_protocols)
{
    char *usable_s;
    int i;

    for (i = 0; i < ofputil_n_flow_dump_protocols; i++) {
        enum ofputil_protocol f = ofputil_flow_dump_protocols[i];
        if (f & usable_protocols & allowed_protocols
            && try_set_protocol(vconn, f, &cur_protocol)) {
            return f;
        }
    }

    usable_s = ofputil_protocols_to_string(usable_protocols);
    if (usable_protocols & allowed_protocols) {
        ovs_fatal(0, "switch does not support any of the usable flow "
                  "formats (%s)", usable_s);
    } else {
        char *allowed_s = ofputil_protocols_to_string(allowed_protocols);
        ovs_fatal(0, "none of the usable flow formats (%s) is among the "
                  "allowed flow formats (%s)", usable_s, allowed_s);
    }
}

bool
try_set_protocol(struct vconn *vconn, enum ofputil_protocol want,
                 enum ofputil_protocol *cur)
{
    for (;;) {
        struct ofpbuf *request, *reply;
        enum ofputil_protocol next;

        request = ofputil_encode_set_protocol(*cur, want, &next);
        if (!request) {
            return *cur == want;
        }

        run(vconn_transact_noreply(vconn, request, &reply),
            "talking to %s", vconn_get_name(vconn));
        if (reply) {
            char *s = ofp_to_string(ofpbuf_data(reply), ofpbuf_size(reply), 2);
            VLOG_DBG("%s: failed to set protocol, switch replied: %s",
                     vconn_get_name(vconn), s);
            free(s);
            ofpbuf_delete(reply);
            return false;
        }

        *cur = next;
    }
}



void run(int retval, const char *message, ...)
    PRINTF_FORMAT(2, 3);

void
run(int retval, const char *message, ...)
{
    if (retval) {
        va_list args;

        va_start(args, message);
        ovs_fatal_valist(retval, message, args);
    }
}



int
open_vconn_socket(const char *name, struct vconn **vconnp)
{
    char *vconn_name = xasprintf("unix:%s", name);
    int error;

    error = vconn_open(vconn_name, get_allowed_ofp_versions(), DSCP_DEFAULT,
                       vconnp);
    if (error && error != ENOENT) {
        ovs_fatal(0, "%s: failed to open socket (%s)", name,
                  ovs_strerror(error));
    }
    free(vconn_name);

    return error;
}





