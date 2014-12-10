
#include <config.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <net/if.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "byte-order.h"
#include "classifier.h"
#include "command-line.h"
#include "daemon.h"
#include "compiler.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "nx-match.h"
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
#include "packets.h"
#include "pcap-file.h"
#include "poll-loop.h"
#include "random.h"
#include "stream-ssl.h"
#include "socket-util.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "vconn.h"
#include "vlog.h"
#include "meta-flow.h"
#include "sort.h"


VLOG_DEFINE_THIS_MODULE(checkpoint);
int main(int argc , char * argv[]) {
     printf("ovs-checkpoint\n");
     return 0;
}

#if false
static void usage(void) NO_RETURN;

enum open_target { MGMT, SNOOP };

static int open_vconn_socket(const char *name, struct vconn **vconnp);
static enum ofputil_protocol
set_protocol_for_flow_dump(struct vconn *vconn,
                           enum ofputil_protocol cur_protocol,
                           enum ofputil_protocol usable_protocols);
static enum ofputil_protocol open_vconn(const char *name, struct vconn **vconnp);
// get flow table via OFP, and dump the flowtable into a file
static void checkpoint_dump(const char * switch_name, const char *file_name);
// read flow table from a local file, and send the flow table to switch via OFP
static void checkpoint_recover(const char * switch_name, const char *file_name);

// send a OFP request to the switch : checkpoint or recover the flow table inside its private storage space.
static void checkpoint_request(const char * switch_name, const char *file_name,bool ischeckpoint);

static struct vconn * prepare_dump_flows(int argc, char *argv[], bool aggregate, struct ofpbuf **requestp);

static enum ofputil_protocol allowed_protocols = OFPUTIL_P_ANY;

static bool try_set_protocol(struct vconn *vconn, enum ofputil_protocol want, enum ofputil_protocol *cur);
static void dump_stats_transaction(struct vconn *vconn, struct ofpbuf *request, FILE * f);

static void transact_noreply(struct vconn *vconn, struct ofpbuf *request);

static void checkpoint_flow_mod(int argc, char *argv[], uint16_t command,struct vconn *vconn, enum ofputil_protocol protocol);
static enum ofputil_protocol prepare_checkpoint_flow_mod(const char * remote , struct vconn **vconn,enum ofputil_protocol usable_protocols);
static void request_transaction(struct vconn *vconn, struct ofpbuf *request);

int
main(int argc, char *argv[])
{
    if (argc != 4) {
        usage();
        return 0;
    }
    if (strlen(argv[1]) > 0 && strlen(argv[2])>0) {
        if (strcmp(argv[1],"dump") ==0) {
            checkpoint_dump(argv[2],argv[3]);
            return 0;
        }
        else if (strcmp(argv[1],"recover")==0) {
            checkpoint_recover(argv[2],argv[3]);
            return 0;
        }
        else if (strcmp(argv[1],"dumpRequest") ==0 ) {
            checkpoint_request(argv[2],argv[3],true);
            return 0;
        }
        else if (strcmp(argv[1],"recoverRequest") ==0 ) {
            checkpoint_request(argv[2],argv[3],false);
        }
    }
    return 0;
}


static void
usage(void)
{
    printf("ovs-checkpoint : OpenVswitch checkpoint utility\n"
           "usage: \tovs-checkpoint dump switch file\n"
           "\tovs-checkpoint recover switch file\n" 
           "\tovs-checkpoint dumpRequest switch file\n");
}


static void run(int retval, const char *message, ...)
PRINTF_FORMAT(2, 3);

static void
run(int retval, const char *message, ...)
{
    if (retval) {
        va_list args;

        va_start(args, message);
        ovs_fatal_valist(retval, message, args);
    }
}

static void
checkpoint_dump(const char * switch_name, const char *file_name) {
    struct ofpbuf *request;
    struct vconn *vconn;
    char * argv [2];
    FILE *f = fopen(file_name,"w");
    argv[1] = switch_name;
    vconn = prepare_dump_flows(2, argv, false, &request);
    dump_stats_transaction(vconn, request, f);
    vconn_close(vconn);
    fclose(f);
}

static struct vconn *
prepare_checkpoint_request(const char * conname, const char * fname,
                   struct ofpbuf **requestp)
{
    enum ofputil_protocol usable_protocols, protocol;
    struct ofputil_checkpoint_request fsr;
    struct vconn *vconn;
    //char *error;

    //error = parse_ofp_checkpoint_request_str(&fsr, fname, &usable_protocols);
    strcpy(fsr.fname ,fname);
    usable_protocols = OFPUTIL_P_ANY;

    protocol = open_vconn(conname, &vconn);
    protocol = set_protocol_for_flow_dump(vconn, protocol, usable_protocols);
    *requestp = ofputil_encode_checkpoint_request(&fsr, protocol);
    return vconn;
}


static struct vconn *
prepare_recover_request(const char * conname, const char * fname,
                   struct ofpbuf **requestp)
{
    enum ofputil_protocol usable_protocols, protocol;
    struct ofputil_checkpoint_request fsr;
    struct vconn *vconn;
    //char *error;

    //error = parse_ofp_checkpoint_request_str(&fsr, fname, &usable_protocols);
    strcpy(fsr.fname ,fname);
    usable_protocols = OFPUTIL_P_ANY;

    protocol = open_vconn(conname, &vconn);
    protocol = set_protocol_for_flow_dump(vconn, protocol, usable_protocols);
    *requestp = ofputil_encode_recover_request(&fsr, protocol);
    return vconn;
}




static void 
checkpoint_request(const char * switch_name, const char * file_name,bool ischeckpoint) {
    struct ofpbuf *request;
    struct vconn * vconn;
    char * argv[2];
    argv[1] = switch_name;
    if (ischeckpoint)
        vconn = prepare_checkpoint_request(switch_name,file_name,&request);
    else
        vconn = prepare_recover_request(switch_name,file_name,&request);
    printf ("vconn establish\n");
    request_transaction(vconn,request);
    vconn_close(vconn);
}
static void checkpoint_recover(const char * switch_name, const char *file_name) {
    //remove all current flows
    //ofctl_flow_mod(argc, argv, strict ? OFPFC_DELETE_STRICT : OFPFC_DELETE);

    char * argv [3];
    argv[1] = switch_name;

    //get usable protocols
    enum ofputil_protocol protocol;
    struct vconn * vconn;
    enum ofputil_protocol usable_protocols;
    struct ofputil_flow_mod fm;
    char * error;
    error = parse_ofp_flow_mod_str(&fm,  "", OFPFC_DELETE, &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }


    //connect to switch
    protocol = prepare_checkpoint_flow_mod(switch_name,&vconn,usable_protocols);

    checkpoint_flow_mod(2,argv,OFPFC_DELETE,vconn,protocol);
    //add these flows
    //for each item in argv[2];
    char bufline[2048];
    char bufstr[2048];
    char *p;
    argv[2] = bufstr;
    FILE *f = fopen(file_name,"r");
    while (fgets(bufline,2048,f) != NULL) {
        p = bufstr;
        char * p1;
        if ((p1 = strstr(bufline,"table="))==NULL) continue;
        while ( (*p = *p1)!=',') {
            p++;
            p1++;
        }
        p++;
        if ((p1 = strstr(bufline,"priority="))==NULL) continue;
        while ( (*p = *p1)!=' ') {
            p++;
            p1++;
        }
        *p = ',';
        p++;
        if ((p1 = strstr(bufline,"actions="))==NULL) continue;
        while ( (*p = *p1)!='\n') {
            p++;
            p1++;
        }
        *p = '\0';
        //printf("+%s+\n",bufstr);
        checkpoint_flow_mod(3,argv,OFPFC_ADD,vconn,protocol);
    }
    vconn_close(vconn);
}


static enum ofputil_protocol
open_vconn_for_flow_mod(const char *remote, struct vconn **vconnp,
                        enum ofputil_protocol usable_protocols)
{
    enum ofputil_protocol cur_protocol;
    char *usable_s;
    int i;

    if (!(usable_protocols & allowed_protocols)) {
        char *allowed_s = ofputil_protocols_to_string(allowed_protocols);
        usable_s = ofputil_protocols_to_string(usable_protocols);
        ovs_fatal(0, "none of the usable flow formats (%s) is among the "
                  "allowed flow formats (%s)", usable_s, allowed_s);
    }

    /* If the initial flow format is allowed and usable, keep it. */
    cur_protocol = open_vconn(remote, vconnp);
    if (usable_protocols & allowed_protocols & cur_protocol) {
        return cur_protocol;
    }

    /* Otherwise try each flow format in turn. */
    for (i = 0; i < sizeof(enum ofputil_protocol) * CHAR_BIT; i++) {
        enum ofputil_protocol f = 1 << i;

        if (f != cur_protocol
                && f & usable_protocols & allowed_protocols
                && try_set_protocol(*vconnp, f, &cur_protocol)) {
            return f;
        }
    }

    usable_s = ofputil_protocols_to_string(usable_protocols);
    ovs_fatal(0, "switch does not support any of the usable flow "
              "formats (%s)", usable_s);
}


static void
ofctl_flow_mod__( struct ofputil_flow_mod *fms,
                  size_t n_fms, struct vconn *vconn, enum ofputil_protocol protocol)
{
//    enum ofputil_protocol protocol;
//    struct vconn *vconn;
    size_t i;

//    protocol = open_vconn_for_flow_mod(remote, &vconn, usable_protocols);

    for (i = 0; i < n_fms; i++) {
        struct ofputil_flow_mod *fm = &fms[i];
        transact_noreply(vconn, ofputil_encode_flow_mod(fm, protocol));
        free(fm->ofpacts);
    }
//    vconn_close(vconn);
}

static enum ofputil_protocol
prepare_checkpoint_flow_mod(const char * remote , struct vconn **vconn,enum ofputil_protocol usable_protocols)
{
    enum ofputil_protocol protocol;
    protocol = open_vconn_for_flow_mod(remote, vconn, usable_protocols);
    return protocol;
}

static void
checkpoint_flow_mod(int argc, char *argv[], uint16_t command,struct vconn *vconn, enum ofputil_protocol protocol)
{
    // printf("flow_mod:%d._%d_%d__",argc,(command==OFPFC_DELETE),(command==OFPFC_ADD));
    //int i; for (i = 0 ; i < argc; i++) printf("%s.",argv[i]); printf("\n");
    struct ofputil_flow_mod fm;
    char *error;
    enum ofputil_protocol usable_protocols;

    error = parse_ofp_flow_mod_str(&fm, argc > 2 ? argv[2] : "", command,
                                   &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }
    ofctl_flow_mod__( &fm, 1, vconn, protocol);
}





static struct vconn *
prepare_dump_flows(int argc, char *argv[], bool aggregate,
                   struct ofpbuf **requestp)
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
    protocol = set_protocol_for_flow_dump(vconn, protocol, usable_protocols);
    *requestp = ofputil_encode_flow_stats_request(&fsr, protocol);
    return vconn;
}

static void
send_openflow_buffer(struct vconn *vconn, struct ofpbuf *buffer)
{
    ofpmsg_update_length(buffer);
    run(vconn_send_block(vconn, buffer), "failed to send packet to switch");
}

static void
dump_stats_transaction(struct vconn *vconn, struct ofpbuf *request, FILE * f)
{
    const struct ofp_header *request_oh = request->data;
    ovs_be32 send_xid = request_oh->xid;
    enum ofpraw request_raw;
    enum ofpraw reply_raw;
    bool done = false;

    ofpraw_decode_partial(&request_raw, request->data, request->size);
    reply_raw = ofpraw_stats_request_to_reply(request_raw,
                request_oh->version);

    send_openflow_buffer(vconn, request);
    while (!done) {
        ovs_be32 recv_xid;
        struct ofpbuf *reply;

        run(vconn_recv_block(vconn, &reply), "OpenFlow packet receive failed");
        recv_xid = ((struct ofp_header *) reply->data)->xid;
        if (send_xid == recv_xid) {
            enum ofpraw raw;

            ofp_print(f, reply->data, reply->size,  1);

            ofpraw_decode(&raw, reply->data);
            if (ofptype_from_ofpraw(raw) == OFPTYPE_ERROR) {
                done = true;
            } else if (raw == reply_raw) {
                done = !ofpmp_more(reply->data);
            } else {
                ovs_fatal(0, "received bad reply: %s",
                          ofp_to_string(reply->data, reply->size,
                                        1));
            }
        } else {
            VLOG_DBG("received reply with xid %08"PRIx32" "
                     "!= expected %08"PRIx32, recv_xid, send_xid);
        }
        ofpbuf_delete(reply);
    }
}

 void 
request_transaction(struct vconn *vconn, struct ofpbuf *request) {
   const struct ofp_header *request_oh = request -> data; ovs_be32 send_xid = request_oh->xid;
   enum ofpraw request_raw; ofpraw_decode_partial(&request_raw, request->data, request->size);
//   enum ofpraw reply_raw = ofpraw_checkpoint_request_to_reply(request_raw, request_oh->version);
   send_openflow_buffer(vconn, request);
   bool done = false;
   while (!done ) {
        ovs_be32 recv_xid;
        struct ofpbuf *reply;
        run(vconn_recv_block(vconn,&reply), "Openflow packet receive failed");
        recv_xid = ((struct ofp_header *) reply->data)->xid;
        printf("%d %d \n",recv_xid,send_xid);
        if (send_xid == recv_xid) {
           enum ofpraw raw;
           ofpraw_decode(&raw,reply->data);
           if (ofptype_from_ofpraw(raw) == OFPTYPE_ERROR) {
           } else if (true){// (raw == reply_raw){
               //print
               ofp_print(stdout,reply->data,reply->size,1); 
               done = true; !ofpmp_more(reply->data);
           } else {
               ovs_fatal(0,"bad reply :%s", ofp_to_string(reply->data,reply->size,1));
           }
        } else {
            VLOG_DBG("received reply with xid %08"PRIx32" "
                     "!= expected %08"PRIx32, recv_xid, send_xid);
        }
        ofpbuf_delete(reply);
   }
}
static enum ofputil_protocol
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

static enum ofputil_protocol
open_vconn(const char *name, struct vconn **vconnp)
{
    return open_vconn__(name, MGMT, vconnp);
}


static enum ofputil_protocol
set_protocol_for_flow_dump(struct vconn *vconn,
                           enum ofputil_protocol cur_protocol,
                           enum ofputil_protocol usable_protocols)
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

static bool
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
            char *s = ofp_to_string(reply->data, reply->size, 2);
            VLOG_DBG("%s: failed to set protocol, switch replied: %s",
                     vconn_get_name(vconn), s);
            free(s);
            ofpbuf_delete(reply);
            return false;
        }

        *cur = next;
    }
}

static int
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

static void
transact_multiple_noreply(struct vconn *vconn, struct list *requests)
{
    struct ofpbuf *request, *reply;

    LIST_FOR_EACH (request, list_node, requests) {
        ofpmsg_update_length(request);
    }

    run(vconn_transact_multiple_noreply(vconn, requests, &reply),
        "talking to %s", vconn_get_name(vconn));
    if (reply) {
        ofp_print(stderr, reply->data, reply->size,2);
        exit(1);
    }
    ofpbuf_delete(reply);
}

/* Sends 'request', which should be a request that only has a reply if an error
 * occurs, and waits for it to succeed or fail.  If an error does occur, prints
 * it and exits with an error.
 *
 * Destroys 'request'. */
static void
transact_noreply(struct vconn *vconn, struct ofpbuf *request)
{
    struct list requests;

    list_init(&requests);
    list_push_back(&requests, &request->list_node);
    transact_multiple_noreply(vconn, &requests);
}

*/
/*
static void
ofctl_dump_flows__(int argc, char *argv[], bool aggregate)
{
    struct ofpbuf *request;
    struct vconn *vconn;

    vconn = prepare_dump_flows(argc, argv, aggregate, &request);
    dump_stats_transaction(vconn, request);
    vconn_close(vconn);
}




static struct vconn *
prepare_dump_flows(int argc, char *argv[], bool aggregate,
                   struct ofpbuf **requestp)
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
    protocol = set_protocol_for_flow_dump(vconn, protocol, usable_protocols);
    *requestp = ofputil_encode_flow_stats_request(&fsr, protocol);
    return vconn;
}

*/
#endif
