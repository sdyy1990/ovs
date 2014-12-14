#ifndef OFP_OFCTLLIB_H
#define OFP_OFCTLLIB_H 1
#include "vconn.h"
#include "socket-util.h"
#include "dirs.h"


struct vconn *
prepare_dump_flows(int argc, char *argv[], bool aggregate,
                   struct ofpbuf **requestp, enum ofputil_protocol allowed_protocols);
                   
                   
enum open_target { MGMT, SNOOP };
enum ofputil_protocol
open_vconn__(const char *name, enum open_target target,
             struct vconn **vconnp); //, enum ofputil_protocol allowed_protocols);
enum ofputil_protocol
open_vconn(const char *name, struct vconn **vconnp);


enum ofputil_protocol
set_protocol_for_flow_dump(struct vconn *vconn,
                           enum ofputil_protocol cur_protocol,
                           enum ofputil_protocol usable_protocols,
                           enum ofputil_protocol allowed_protocols);
                           
                           

bool
try_set_protocol(struct vconn *vconn, enum ofputil_protocol want,
                 enum ofputil_protocol *cur);
void run(int retval, const char *message, ...);
void run(int retval, const char *message, ...);

int open_vconn_socket(const char *name, struct vconn **vconnp)                 ;
                           
#endif
                   
