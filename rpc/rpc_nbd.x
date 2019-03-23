/* rpcgen generates code that results in unused-variable warnings */
#ifdef RPC_XDR
%#include "rpc-pragmas.h"
#endif

enum handler_t {
    NBD_BACKSTORE_GLUSTER,
    NBD_BACKSTORE_CEPH,

    NBD_BACKSTORE_MAX
};

#define HOST_MAX  255
#define CFGS_MAX  1024
#define PORT_MAX  32
#define TLEN_MAX  32
#define DLEN_MAX  16

struct nbd_create {
    handler_t     type;
    u_quad_t      size;
    bool          prealloc;
    char          cfgstring[CFGS_MAX];
};

struct nbd_delete {
    handler_t     type;
    char          cfgstring[CFGS_MAX];
};

struct nbd_premap {
    handler_t     type;
    bool          readonly;
    char          cfgstring[CFGS_MAX];
};

struct nbd_postmap {
    handler_t     type;
    char          nbd[DLEN_MAX];
    char          time[TLEN_MAX];
    char          cfgstring[CFGS_MAX];
};

struct nbd_unmap {
    handler_t     type;
    char          nbd[DLEN_MAX];
    char          cfgstring[CFGS_MAX];
};

struct nbd_list {
    handler_t     type;
};

struct nbd_response {
    int           exit;
    /*
     * The following are used for the error info
     * if exit is none zero or it will used for
     * the list command to get the mapping
     * backstore <--> /dev/nbdXX infomation.
     *
     * For the mapping info, for each map it should
     * be "{[/dev/nbdXX][backstore]}" string.
     */
    string        buf<>;

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
        nbd_response NBD_PREMAP(nbd_premap) = 3;
        nbd_response NBD_POSTMAP(nbd_postmap) = 4;
        nbd_response NBD_UNMAP(nbd_unmap) = 5;
        nbd_response NBD_LIST(nbd_list) = 6;
    } = 1;
} = RPC1_RPC_PROG_NUM;
