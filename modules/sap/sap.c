
#include <astra.h>
#include <modules/mpegts/mpegts.h>

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
        int ttl;
        int interval;

        const char *addr;
        int port;
        int rtp;
        const char *playgroup;
        const char *uri;
        const char *description;
        const char *email;
        const char *phone;
        const char *attribute;
    } config;

    int sid;
};

static int sap_sid = 0;

static const char SAP_V4_GLOBAL[]   = "224.2.127.254";
static const char SAP_V4_ORG[]      = "239.195.255.255";
static const char SAP_V4_LOCAL[]    = "239.255.255.255";
static const char SAP_V4_LINK[]     = "224.0.0.255";

static void module_initialize(module_data_t *mod)
{
    const char *tmp;
    module_set_string(mod, "name", 1, NULL, &mod->config.name);

    const char *sap_group;
    module_set_string(mod, "scope", 0, "global", &tmp);
    if(!strcasecmp(tmp, "global"))
    {
        mod->config.scope = SAP_GLOBAL;
        sap_group = SAP_V4_GLOBAL;
    }
    else if(!strcasecmp(tmp, "org"))
    {
        mod->config.scope = SAP_ORG;
        sap_group = SAP_V4_ORG;
    }
    else if(!strcasecmp(tmp, "local"))
    {
        mod->config.scope = SAP_LOCAL;
        sap_group = SAP_V4_LOCAL;
    }
    else if(!strcasecmp(tmp, "link"))
    {
        mod->config.scope = SAP_LINK;
        sap_group = SAP_V4_LINK;
    }
    else
    {
        log_error(LOG_MSG("Illegal SAP scope \"%s\""), tmp);
        abort();
    }

    module_set_string(mod, "sap_group", 0, sap_group, &mod->config.sap_group);
    module_set_number(mod, "sap_port", 0, 9875, &mod->config.sap_port);
    module_set_number(mod, "ttl", 0, 32, &mod->config.ttl);
    module_set_number(mod, "sap_ttl", 0, mod->config.ttl, &mod->config.ttl);
    module_set_number(mod, "interval", 0, 10, &mod->config.interval);

    module_set_string(mod, "addr", 1, NULL, &mod->config.addr);
    module_set_number(mod, "port", 1, 0, &mod->config.port);
    module_set_number(mod, "rtp", 0, 0, &mod->config.rtp);
    module_set_string(mod, "playgroup", 0, NULL, &mod->config.playgroup);
    module_set_string(mod, "uri", 0, NULL, &mod->config.uri);
    module_set_string(mod, "description", 0, NULL, &mod->config.description);
    module_set_string(mod, "email", 0, NULL, &mod->config.email);
    module_set_string(mod, "phone", 0, NULL, &mod->config.phone);
    module_set_string(mod, "attribute", 0, NULL, &mod->config.attribute);

    ++sap_sid;
    mod->sid = sap_sid;

    /* init SDP Connection Data */
    // TODO: ...

    /* init SDP Media Announcement */
    // TODO: ...

    /* init SDP Origin */
    // TODO: ...

    /* init socket */
}

static void module_destroy(module_data_t *mod)
{
}

MODULE_METHODS_EMPTY();

MODULE(sdp)
