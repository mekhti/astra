
#include <astra.h>
#include <modules/mpegts/mpegts.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_MSG(_msg) "[sap %s] " _msg, mod->config.name

typedef enum
{
    SAP_GLOBAL,
    SAP_ORG,
    SAP_LOCAL,
    SAP_LINK
} sap_scope_t;

struct module_data_s
{
    MODULE_BASE();

    struct
    {
        const char *name;
        sap_scope_t scope;

        const char *sap_group;
        int sap_port;

        const char *addr;
        int port;
        const char *localaddr;
        int ttl;
        int rtp;
    } config;

    int sock;
    void *sockaddr;

    void *timer;

    char packet[1024];
    uint16_t packet_size;
};

static uint16_t sap_sid = 0;

static const char SAP_V4_GLOBAL[]   = "224.2.127.254";
static const char SAP_V4_ORG[]      = "239.195.255.255";
static const char SAP_V4_LOCAL[]    = "239.255.255.255";
static const char SAP_V4_LINK[]     = "224.0.0.255";

static void send_sap(void *arg)
{
    module_data_t *mod = arg;
    socket_sendto(mod->sock, mod->packet, mod->packet_size, mod->sockaddr);
}

static void module_initialize(module_data_t *mod)
{
    int number_value;
    const char *string_value;

    module_set_string(mod, "name", 1, NULL, &mod->config.name);

    const char *sap_group_def;
    module_set_string(mod, "scope", 0, "global", &string_value);
    if(!strcasecmp(string_value, "global"))
    {
        mod->config.scope = SAP_GLOBAL;
        sap_group_def = SAP_V4_GLOBAL;
    }
    else if(!strcasecmp(string_value, "org"))
    {
        mod->config.scope = SAP_ORG;
        sap_group_def = SAP_V4_ORG;
    }
    else if(!strcasecmp(string_value, "local"))
    {
        mod->config.scope = SAP_LOCAL;
        sap_group_def = SAP_V4_LOCAL;
    }
    else if(!strcasecmp(string_value, "link"))
    {
        mod->config.scope = SAP_LINK;
        sap_group_def = SAP_V4_LINK;
    }
    else
    {
        log_error(LOG_MSG("Illegal SAP scope \"%s\""), string_value);
        abort();
    }

    module_set_string(mod, "sap_group", 0, sap_group_def, &mod->config.sap_group);
    module_set_number(mod, "sap_port", 0, 9875, &mod->config.sap_port);

    module_set_string(mod, "addr", 1, NULL, &mod->config.addr);
    module_set_number(mod, "port", 1, 0, &mod->config.port);
    module_set_string(mod, "localaddr", 0, NULL, &mod->config.localaddr);
    module_set_number(mod, "ttl", 0, 32, &mod->config.ttl);
    module_set_number(mod, "rtp", 0, 0, &mod->config.rtp);

    ++sap_sid;

    /* init socket */
    mod->sock = socket_open(SOCKET_PROTO_UDP | SOCKET_REUSEADDR | SOCKET_BIND, NULL, 0);
    socket_multicast_set_if(mod->sock, mod->config.localaddr);
    socket_multicast_set_ttl(mod->sock, mod->config.ttl);
    socket_multicast_join(mod->sock, mod->config.addr, NULL);
    mod->sockaddr = socket_sockaddr_init(mod->config.sap_group, mod->config.sap_port);

    /* init timer */
    module_set_number(mod, "interval", 0, 10, &number_value);
    mod->timer = timer_attach(number_value * 1000, send_sap, mod);

    /* init packet */
    mod->packet[0] = 0x20; // sap version
    mod->packet[1] = 0;
    mod->packet[2] = sap_sid >> 8;
    mod->packet[3] = sap_sid & 0xFF;

    uint32_t addr = inet_addr(mod->config.addr);
    mod->packet[4] = addr & 0xFF;
    mod->packet[5] = (addr >> 8) & 0xFF;
    mod->packet[6] = (addr >> 16) & 0xFF;
    mod->packet[7] = (addr >> 24) & 0xFF;

    char *ptr = &mod->packet[8];
    ptr += sprintf(ptr, "v=0\r\n");
    /* SDP Origin */
    ptr += sprintf(ptr, "o=- %d %lu IN IP4 %s\r\n", sap_sid, time(NULL), mod->config.addr);

    ptr += sprintf(ptr, "s=%s\r\n", mod->config.name);

    if(module_set_string(mod, "description", 0, NULL, &string_value) && string_value)
        ptr += sprintf(ptr, "i=%s\r\n", string_value);

    if(module_set_string(mod, "uri", 0, NULL, &string_value) && string_value)
        ptr += sprintf(ptr, "u=%s\r\n", string_value);

    if(module_set_string(mod, "email", 0, NULL, &string_value) && string_value)
        ptr += sprintf(ptr, "e=%s\r\n", string_value);

    if(module_set_string(mod, "phone", 0, NULL, &string_value) && string_value)
        ptr += sprintf(ptr, "p=%s\r\n", string_value);

    ptr += sprintf(ptr, "t=0 0\r\n");
    ptr += sprintf(ptr, "a=type:broadcast\r\n");

    if(module_set_string(mod, "attribute", 0, NULL, &string_value) && string_value)
        ptr += sprintf(ptr, "a=%s\r\n", string_value);

    /* SDP Media Announcement */
    const char *mdata_tpl = (mod->config.rtp)
                          ? "m=video %d RTP/AVP 33\r\n"
                          : "m=video %d udp 33\r\n";
    ptr += sprintf(ptr, mdata_tpl, mod->config.port);

    /* SDP Connection Data */
    ptr += sprintf(ptr, "c=IN IP4 %s/%d\r\n", mod->config.addr, mod->config.ttl);

    module_set_string(mod, "playgroup", 0, NULL, &string_value);
    if(string_value)
        ptr += sprintf(ptr, "a=x-plgroup:%s\r\n", string_value);

    mod->packet_size = ptr - mod->packet;
}

static void module_destroy(module_data_t *mod)
{
    timer_detach(mod->timer);

    socket_close(mod->sock);
    socket_sockaddr_destroy(mod->sockaddr);
}

MODULE_METHODS_EMPTY();

MODULE(sdp)
