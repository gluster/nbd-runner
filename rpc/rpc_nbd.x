/* rpcgen generates code that results in unused-variable warnings */
#ifdef RPC_XDR
%#include "rpc-pragmas.h"
#endif

enum handler_t {
    NBD_HANDLER_GLUSTER     = 0,

    NBD_HANDLER_MAX
};

#define HOST_MAX  255
#define CFGS_MAX  1024
#define PORT_MAX  32

struct nbd_create {
  handler_t     type;
  char          host[HOST_MAX];
  char          cfgstring[CFGS_MAX];
};

struct nbd_delete {
  handler_t     type;
  char          host[HOST_MAX];
  char          cfgstring[CFGS_MAX];
};

struct nbd_map {
  handler_t     type;
  char          host[HOST_MAX];
  char          cfgstring[CFGS_MAX];
  int           threads;
};

struct nbd_response {
  int           exit;
  string        out<>;

  /*
   * The following members will only be
   * used by the map option.
   *
   * host : the server listen ip address
   * port : the server listen tcp port
   * size : the backend file/block size
   * blksize: the backend file/block sector size
   */
  char          host[HOST_MAX];
  char          port[PORT_MAX];
  u_quad_t      size;
  u_quad_t      blksize;

};

#define RPC1_RPC_PROG_NUM 0x3f0a37eb

program RPC_NBD {
  version RPC_NBD_VERS {
    nbd_response NBD_CREATE(nbd_create) = 1;
    nbd_response NBD_DELETE(nbd_delete) = 2;
    nbd_response NBD_MAP(nbd_map) = 3;
  } = 1;
} = RPC1_RPC_PROG_NUM;
