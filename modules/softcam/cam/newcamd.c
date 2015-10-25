/*
 * Astra Module: SoftCAM. Newcamd Client
 * http://cesbo.com/astra
 *
 * Copyright (C) 2012-2015, Andrey Dyldin <and@cesbo.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <astra.h>
#include "../module_cam.h"
#include "des.h"

#define NEWCAMD_HEADER_SIZE 12
#define NEWCAMD_MSG_SIZE (NEWCAMD_HEADER_SIZE + EM_MAX_SIZE)
#define MAX_PROV_COUNT 16
#define KEY_SIZE 14

#define MSG(_msg) "[newcamd %s] " _msg, mod->config.name

#define CSA_KEY_SIZE 8
#define ECM_HEADER_SIZE 3
#define ECM_PAYLOAD_SIZE (CSA_KEY_SIZE * 2)

struct module_data_t
{
    MODULE_CAM_DATA();

    struct
    {
        const char *name;

        const char *host;
        int port;
        int timeout;

        const char *user;
        char pass[36];

        uint8_t key[KEY_SIZE];
        uint16_t caid;

        bool disable_emm;
    } config;

    int status;
    asc_socket_t *sock;
    asc_timer_t *timeout;

    uint8_t *prov_buffer;

    struct
    {
        uint8_t key[16];
        des_ctx_t ks1;
        des_ctx_t ks2;
    } triple_des;

    uint16_t msg_id;        // curren message id
    em_packet_t *packet;    // current packet

    uint8_t buffer[NEWCAMD_MSG_SIZE];
    size_t payload_size;    // to send
    size_t buffer_skip;     // to recv

    asc_timer_t *status_timer;
    int idx_callback;

    uint32_t ecm_rate[60];
    uint32_t emm_rate[60];
    size_t rate_skip;
};

typedef enum
{
    NEWCAMD_MSG_ERROR = 0,
    NEWCAMD_MSG_FIRST = 0xDF,
    NEWCAMD_MSG_CLIENT_2_SERVER_LOGIN,
    NEWCAMD_MSG_CLIENT_2_SERVER_LOGIN_ACK,
    NEWCAMD_MSG_CLIENT_2_SERVER_LOGIN_NAK,
    NEWCAMD_MSG_CARD_DATA_REQ,
    NEWCAMD_MSG_CARD_DATA,
    NEWCAMD_MSG_KEEPALIVE = 0xFD,
} newcamd_cmd_t;

static void newcamd_connect(module_data_t *mod);
static void newcamd_reconnect(module_data_t *mod, bool timeout);

static uint8_t xor_sum(const uint8_t *mem, size_t size)
{
    uint8_t cs = 0;
    while(size > 0)
    {
        cs ^= *mem++;
        size--;
    }
    return cs;
}

/*
 *  ____             _        _
 * / ___|  ___   ___| | _____| |_
 * \___ \ / _ \ / __| |/ / _ \ __|
 *  ___) | (_) | (__|   <  __/ |_
 * |____/ \___/ \___|_|\_\___|\__|
 *
 */

static void callback_error(module_data_t *mod, const char *error)
{
    if(!mod->idx_callback)
        return;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, mod->idx_callback);
    lua_newtable(lua);
    lua_pushstring(lua, error);
    lua_setfield(lua, -2, "error");
    lua_pushnumber(lua, 0);
    lua_setfield(lua, -2, "status");
    lua_call(lua, 1, 0);
}

static void on_timeout(void *arg)
{
    module_data_t *mod = arg;

    asc_timer_destroy(mod->timeout);
    mod->timeout = NULL;

    static const char __err_0[] = "connection timeout";
    static const char __err_X[] = "response timeout";

    switch(mod->status)
    {
        case -1:
            newcamd_connect(mod);
            return;
        case 0:
            asc_log_error(MSG("%s"), __err_0);
            callback_error(mod, __err_0);
            break;
        default:
            asc_log_error(MSG("%s"), __err_X);
            callback_error(mod, __err_X);
            break;
    }

    newcamd_reconnect(mod, false);
}

static void on_newcamd_close(void *arg)
{
    module_data_t *mod = arg;

    ASC_FREE(mod->sock, asc_socket_close);
    ASC_FREE(mod->timeout, asc_timer_destroy);

    module_cam_reset(&mod->__cam);

    ASC_FREE(mod->prov_buffer, free);
    ASC_FREE(mod->packet, free);

    static const char __err_0[] = "connection failed";
    static const char __err_1[] = "failed to parse response";
    switch(mod->status)
    {
        case 0:
            asc_log_error(MSG("%s"), __err_0);
            callback_error(mod, __err_0);
            break;
        case 1:
            asc_log_error(MSG("%s"), __err_1);
            callback_error(mod, __err_1);
            break;
    }

    if(mod->status != -1)
    {
        mod->status = -1;
        mod->timeout = asc_timer_init(mod->config.timeout, on_timeout, mod);
    }
    else
        mod->status = 0;

    for(size_t i = 0; i < 60; ++i)
    {
        mod->ecm_rate[i] = 0;
        mod->emm_rate[i] = 0;
    }
    mod->rate_skip = 0;
}

/*
 *  ____                 _
 * / ___|  ___ _ __   __| |
 * \___ \ / _ \ '_ \ / _` |
 *  ___) |  __/ | | | (_| |
 * |____/ \___|_| |_|\__,_|
 *
 */

static void on_newcamd_ready(void *arg)
{
    module_data_t *mod = arg;

    memset(mod->buffer, 0, NEWCAMD_HEADER_SIZE);

    if(mod->packet)
    {
        memcpy(&mod->buffer[NEWCAMD_HEADER_SIZE], mod->packet->buffer, mod->packet->buffer_size);
        mod->payload_size = mod->packet->buffer_size - 3;

        mod->msg_id = (mod->msg_id + 1) & 0xFFFF;
        U16_TO_BUFFER(mod->msg_id, &mod->buffer[2]);

        const uint16_t pnr = mod->packet->decrypt->cas_pnr;
        U16_TO_BUFFER(pnr, &mod->buffer[4]);
    }

    U16_TO_BUFFER(mod->payload_size & 0x0FFF, &mod->buffer[NEWCAMD_HEADER_SIZE + 1]);

    size_t packet_size = NEWCAMD_HEADER_SIZE + 3 + mod->payload_size;
    const uint8_t no_pad_bytes = (8 - ((packet_size - 1) % 8)) % 8;

    if((packet_size + no_pad_bytes + 1) >= (NEWCAMD_MSG_SIZE - 8))
    {
        asc_log_error(MSG("failed to pad message"));
        newcamd_reconnect(mod, true);
        return;
    }

    random_key(&mod->buffer[packet_size], no_pad_bytes);
    packet_size += no_pad_bytes;
    mod->buffer[packet_size] = xor_sum(&mod->buffer[2], packet_size - 2);
    ++packet_size;

    // encrypt
    uint8_t ivec[8];
    random_key(ivec, sizeof(ivec));
    if(packet_size + sizeof(ivec) >= NEWCAMD_MSG_SIZE)
    {
        asc_log_error(MSG("failed to encrypt message"));
        newcamd_reconnect(mod, true);
        return;
    }
    memcpy(&mod->buffer[packet_size], ivec, sizeof(ivec));
    des_encrypt(&mod->buffer[2], &mod->buffer[2], packet_size - 2,
            &mod->triple_des.ks1, &mod->triple_des.ks2, &mod->triple_des.ks1, ivec, 1);
    packet_size += sizeof(ivec);

    U16_TO_BUFFER(packet_size - 2, &mod->buffer[0]);

    if(asc_socket_send(mod->sock, mod->buffer, packet_size) != (ssize_t)packet_size)
    {
        asc_log_error(MSG("failed to send message"));
        newcamd_reconnect(mod, true);
        return;
    }

    asc_socket_set_on_ready(mod->sock, NULL);

    mod->buffer_skip = 0;
    mod->payload_size = 0;

    if(!mod->timeout)
        mod->timeout = asc_timer_init(mod->config.timeout, on_timeout, mod);
}

/*
 *  ____                _
 * |  _ \ ___  __ _  __| |
 * | |_) / _ \/ _` |/ _` |
 * |  _ <  __/ (_| | (_| |
 * |_| \_\___|\__,_|\__,_|
 *
 */

static void on_newcamd_read_packet(void *arg)
{
    module_data_t *mod = arg;

    if(mod->buffer_skip < 2)
    {
        const ssize_t size = asc_socket_recv(mod->sock,
            &mod->buffer[mod->buffer_skip], 2 - mod->buffer_skip);
        if(size <= 0)
        {
            if(asc_socket_errno() == EAGAIN)
                return;

            asc_log_error(MSG("failed to read header [%s]"), asc_socket_error());
            newcamd_reconnect(mod, true);
            return;
        }
        mod->buffer_skip += size;
        if(mod->buffer_skip != 2)
            return;

        mod->payload_size = 2 + ((mod->buffer[0] << 8) | mod->buffer[1]);
        if(mod->payload_size > NEWCAMD_MSG_SIZE)
        {
            asc_log_error(MSG("wrong message size"));
            newcamd_reconnect(mod, true);
            return;
        }

        return;
    }

    const ssize_t size = asc_socket_recv(mod->sock,
        &mod->buffer[mod->buffer_skip], mod->payload_size - mod->buffer_skip);
    if(size <= 0)
    {
        if(asc_socket_errno() == EAGAIN)
            return;

        asc_log_error(MSG("failed to read message [%s]"), asc_socket_error());
        newcamd_reconnect(mod, true);
        return;
    }

    mod->buffer_skip += size;
    if(mod->buffer_skip != mod->payload_size)
        return;

    size_t packet_size = mod->payload_size - 2;
    mod->payload_size = 0;
    mod->buffer_skip = 0;

    // decrypt
    if((packet_size % 8 == 0) && (packet_size > NEWCAMD_HEADER_SIZE + 3))
    {
        uint8_t ivec[8];
        packet_size -= sizeof(ivec);
        memcpy(ivec, &mod->buffer[packet_size + 2], sizeof(ivec));
        des_encrypt(&mod->buffer[2], &mod->buffer[2], packet_size,
            &mod->triple_des.ks1, &mod->triple_des.ks2, &mod->triple_des.ks1,
            ivec, 0);
    }
    if(xor_sum(&mod->buffer[2], packet_size))
    {
        asc_log_error(MSG("bad message checksum"));
        newcamd_reconnect(mod, true);
        return;
    }

    const uint8_t msg_type = mod->buffer[NEWCAMD_HEADER_SIZE];

    uint8_t *buffer = &mod->buffer[NEWCAMD_HEADER_SIZE];
    mod->payload_size = ((buffer[1] & 0x0F) << 8) | buffer[2];

    if(mod->status == 3)
    {
        if(!mod->packet && msg_type == NEWCAMD_MSG_KEEPALIVE)
        {
            buffer[0] = NEWCAMD_MSG_KEEPALIVE;
            buffer[1] = 0;
            buffer[2] = 0;
            mod->payload_size = 0;

            asc_socket_set_on_ready(mod->sock, on_newcamd_ready);
            return;
        }

        if(!mod->packet || msg_type < 0x80 || msg_type > 0x8F)
        {
            asc_log_warning(MSG("unknown packet type [0x%02X]"), msg_type);
            return;
        }

        asc_timer_destroy(mod->timeout);
        mod->timeout = NULL;

        asc_list_for(mod->__cam.decrypt_list)
        {
            if(asc_list_data(mod->__cam.decrypt_list) == mod->packet->decrypt)
                break;
        }
        if(asc_list_eol(mod->__cam.decrypt_list))
        {
            /* the decrypt module was detached */
            free(mod->packet);
            mod->packet = module_cam_queue_pop(&mod->__cam);
            if(mod->packet)
                asc_socket_set_on_ready(mod->sock, on_newcamd_ready);
            return;
        }

        if(mod->payload_size == ECM_PAYLOAD_SIZE)
        {
            memcpy(mod->packet->buffer, buffer, ECM_HEADER_SIZE + ECM_PAYLOAD_SIZE);
            mod->packet->buffer_size = ECM_HEADER_SIZE + ECM_PAYLOAD_SIZE;
        }
        else if(mod->payload_size == 0)
        {
            memcpy(mod->packet->buffer, buffer, ECM_HEADER_SIZE);
            mod->packet->buffer_size = ECM_HEADER_SIZE;
        }
        else
        {
            mod->packet->buffer[2] = 0x00;
            mod->packet->buffer[3] = 0x00;
            mod->packet->buffer_size = ECM_HEADER_SIZE;
        }

        on_cam_response(mod->packet->decrypt->self, mod->packet->arg, mod->packet->buffer);
        free(mod->packet);

        mod->packet = module_cam_queue_pop(&mod->__cam);
        if(mod->packet)
            asc_socket_set_on_ready(mod->sock, on_newcamd_ready);
    }
    else if(mod->status == 1)
    {
        if(msg_type != NEWCAMD_MSG_CLIENT_2_SERVER_LOGIN_ACK)
        {
            asc_log_error(MSG("login failed [0x%02X]"), msg_type);
            newcamd_reconnect(mod, true);
            return;
        }

        mod->status = 2;

        const size_t p_len = 35; /* strlen(mod->config.pass) */

        triple_des_set_key(mod->config.key, mod->config.pass, p_len - 1,
            &mod->triple_des.ks1, &mod->triple_des.ks2);

        buffer[0] = NEWCAMD_MSG_CARD_DATA_REQ;
        buffer[1] = 0;
        buffer[2] = 0;
        mod->payload_size = 0;

        asc_socket_set_on_ready(mod->sock, on_newcamd_ready);
    }
    else if(mod->status == 2)
    {
        if(msg_type != NEWCAMD_MSG_CARD_DATA)
        {
            asc_log_error(MSG("NEWCAMD_MSG_CARD_DATA"));
            newcamd_reconnect(mod, true);
            return;
        }

        mod->status = 3;

        mod->__cam.caid = (mod->config.caid != 0) ? mod->config.caid : BUFFER_TO_U16(&buffer[4]);
        mod->__cam.au = (buffer[3] == 1);
        memcpy(mod->__cam.ua, &buffer[6], 8);

        char hex_str[32];
        asc_log_info(MSG("CaID=0x%04X AU=%s UA=%s"), mod->__cam.caid,
            (mod->__cam.au) ? "YES" : "NO", hex_to_str(hex_str, mod->__cam.ua, 8));

        mod->__cam.disable_emm = (mod->config.disable_emm) ? (true) : (buffer[3] != 1);

        const int prov_count = (buffer[14] <= MAX_PROV_COUNT) ? buffer[14] : MAX_PROV_COUNT;

        static const int info_size = 3 + 8; /* ident + sa */
        if(mod->prov_buffer)
            free(mod->prov_buffer);
        mod->prov_buffer = malloc(prov_count * info_size);

        for(int i = 0; i < prov_count; i++)
        {
            uint8_t *p = &mod->prov_buffer[i * info_size];
            memcpy(&p[0], &buffer[15 + (11 * i)], 3);
            memcpy(&p[3], &buffer[18 + (11 * i)], 8);
            asc_list_insert_tail(mod->__cam.prov_list, p);
            asc_log_info(MSG("Prov:%d ID:%s SA:%s"), i,
                hex_to_str(hex_str, &p[0], 3), hex_to_str(&hex_str[8], &p[3], 8));
        }

        asc_timer_destroy(mod->timeout);
        mod->timeout = NULL;

        module_cam_ready(&mod->__cam);
    }
}

static void on_newcamd_read_init(void *arg)
{
    module_data_t *mod = arg;

    const ssize_t size = asc_socket_recv(mod->sock,
        &mod->buffer[mod->buffer_skip], KEY_SIZE - mod->buffer_skip);
    if(size <= 0)
    {
        if(asc_socket_errno() == EAGAIN)
            return;

        asc_log_error(MSG("failed to read initial response [%s]"), asc_socket_error());
        newcamd_reconnect(mod, true);
        return;
    }
    mod->buffer_skip += size;
    if(mod->buffer_skip != KEY_SIZE)
        return;

    triple_des_set_key(mod->config.key, (const char *)mod->buffer, KEY_SIZE,
        &mod->triple_des.ks1, &mod->triple_des.ks2);

    uint8_t *buffer = &mod->buffer[NEWCAMD_HEADER_SIZE];

    buffer[0] = NEWCAMD_MSG_CLIENT_2_SERVER_LOGIN;
    const size_t u_len = strlen(mod->config.user) + 1;
    memcpy(&buffer[3], mod->config.user, u_len);
    const size_t p_len = 35; /* strlen(mod->config.pass) */
    memcpy(&buffer[3 + u_len], mod->config.pass, p_len);

    mod->payload_size = u_len + p_len;

    asc_socket_set_on_read(mod->sock, on_newcamd_read_packet);
    asc_socket_set_on_ready(mod->sock, on_newcamd_ready);
}

/*
 *   ____                            _
 *  / ___|___  _ __  _ __   ___  ___| |_
 * | |   / _ \| '_ \| '_ \ / _ \/ __| __|
 * | |__| (_) | | | | | | |  __/ (__| |_
 *  \____\___/|_| |_|_| |_|\___|\___|\__|
 *
 */

static void on_newcamd_connect(void *arg)
{
    module_data_t *mod = arg;

    mod->status = 1;

    asc_timer_destroy(mod->timeout);
    mod->timeout = asc_timer_init(mod->config.timeout, on_timeout, mod);

    mod->buffer_skip = 0;

    asc_socket_set_on_read(mod->sock, on_newcamd_read_init);
}

static void newcamd_connect(module_data_t *mod)
{
    if(mod->sock)
        return;

    mod->status = 0;
    mod->payload_size = 0;
    mod->buffer_skip = 0;

    mod->sock = asc_socket_open_tcp4(mod);
    asc_socket_connect(mod->sock,
        mod->config.host, mod->config.port,
        on_newcamd_connect, on_newcamd_close);

    mod->timeout = asc_timer_init(mod->config.timeout, on_timeout, mod);
}

static void newcamd_disconnect(module_data_t *mod)
{
    mod->status = -1;
    on_newcamd_close(mod);
}

static void newcamd_reconnect(module_data_t *mod, bool timeout)
{
    mod->status = -1;
    on_newcamd_close(mod);

    if(timeout)
        mod->timeout = asc_timer_init(mod->config.timeout, on_timeout, mod);
    else
        newcamd_connect(mod);
}

void newcamd_send_em(module_data_t *mod,
    module_decrypt_t *decrypt, void *arg,
    const uint8_t *buffer, uint16_t size)
{
    if(mod->status != 3)
        return;

    const size_t packet_size = NEWCAMD_HEADER_SIZE + size;
    const uint8_t no_pad_bytes = (8 - ((packet_size - 1) % 8)) % 8;
    if(packet_size + no_pad_bytes > NEWCAMD_MSG_SIZE)
    {
        asc_log_error(MSG("wrong packet size (pnr:%d drop:0x%02X size:%d"),
            decrypt->pnr, buffer[0], size);
        return;
    }

    em_packet_t *packet = malloc(sizeof(em_packet_t));
    memcpy(packet->buffer, buffer, size);
    packet->buffer_size = size;
    packet->decrypt = decrypt;
    packet->arg = arg;

    if(IS_ECM(packet->buffer))
    {
        asc_list_for(mod->__cam.packet_queue)
        {
            em_packet_t *queue_item = asc_list_data(mod->__cam.packet_queue);
            if(queue_item->decrypt == decrypt &&
                queue_item->arg == arg &&
                IS_ECM(queue_item->buffer))
            {
                asc_log_warning(MSG("drop old packet (pnr:%d drop:0x%02X set:0x%02X)"),
                    decrypt->pnr, queue_item->buffer[0], packet->buffer[0]);
                asc_list_remove_current(mod->__cam.packet_queue);
                free(queue_item);
                break;
            }
        }

        mod->ecm_rate[mod->rate_skip] += 1;
    }
    else
    {
        mod->emm_rate[mod->rate_skip] += 1;
    }

    if(mod->packet)
    {
        // newcamd is busy
        asc_list_insert_tail(mod->__cam.packet_queue, packet);
        return;
    }

    mod->packet = packet;
    asc_socket_set_on_ready(mod->sock, on_newcamd_ready);
}

/*
 *  __  __           _       _
 * |  \/  | ___   __| |_   _| | ___
 * | |\/| |/ _ \ / _` | | | | |/ _ \
 * | |  | | (_) | (_| | |_| | |  __/
 * |_|  |_|\___/ \__,_|\__,_|_|\___|
 *
 */

static void on_status_timer(void *arg)
{
    module_data_t *mod = (module_data_t *)arg;

    if(mod->status != 3)
        return;

    lua_rawgeti(lua, LUA_REGISTRYINDEX, mod->idx_callback);
    lua_newtable(lua);
    lua_pushnumber(lua, mod->__cam.caid);
    lua_setfield(lua, -2, "caid");
    lua_pushnumber(lua, mod->status);
    lua_setfield(lua, -2, "status");

    uint32_t ecm_rate = 0;
    uint32_t emm_rate = 0;
    for(size_t i = 0; i < 60; ++i)
    {
        ecm_rate += mod->ecm_rate[i];
        emm_rate += mod->emm_rate[i];
    }

    lua_pushnumber(lua, ecm_rate);
    lua_setfield(lua, -2, "ecm_rate");
    lua_pushnumber(lua, emm_rate);
    lua_setfield(lua, -2, "emm_rate");

    lua_call(lua, 1, 0);

    mod->rate_skip = (mod->rate_skip + 1) % 60;
    mod->ecm_rate[mod->rate_skip] = 0;
    mod->emm_rate[mod->rate_skip] = 0;
}

static int method_info(module_data_t *mod)
{
    if(mod->status != 3)
    {
        lua_pushnil(lua);
        return 1;
    }

    lua_newtable(lua);
    lua_pushnumber(lua, mod->__cam.caid);
    lua_setfield(lua, -2, "caid");
    lua_pushboolean(lua, mod->__cam.au);
    lua_setfield(lua, -2, "au");

    char hex_str[32];
    lua_pushlstring(lua, hex_to_str(hex_str, mod->__cam.ua, 8), 16);
    lua_setfield(lua, -2, "ua");

    lua_newtable(lua);
    asc_list_for(mod->__cam.prov_list)
    {
        const int item_count = luaL_len(lua, -1) + 1;
        lua_pushnumber(lua, item_count);

        const uint8_t *p = (const uint8_t *)asc_list_data(mod->__cam.prov_list);
        lua_newtable(lua);
        lua_pushlstring(lua, hex_to_str(hex_str, &p[0], 3), 6);
        lua_setfield(lua, -2, "id");
        lua_pushlstring(lua, hex_to_str(hex_str, &p[3], 8), 16);
        lua_setfield(lua, -2, "sa");

        lua_settable(lua, -3); // append to the "idents" table
    }
    lua_setfield(lua, -2, "idents");

    return 1;
}

static int method_close(module_data_t *mod)
{
    mod->status = -1;
    on_newcamd_close(mod);

    if(mod->idx_callback)
    {
        luaL_unref(lua, LUA_REGISTRYINDEX, mod->idx_callback);
        mod->idx_callback = 0;
    }
    ASC_FREE(mod->status_timer, asc_timer_destroy);

    return 0;
}

static void module_init(module_data_t *mod)
{
    const char *value_str;
    size_t value_length;

    module_option_string("name", &mod->config.name, NULL);
    asc_assert(mod->config.name != NULL, "[newcamd] option 'name' is required");

    module_option_string("host", &mod->config.host, NULL);
    asc_assert(mod->config.host != NULL, MSG("option 'host' is required"));
    module_option_number("port", &mod->config.port);
    asc_assert(mod->config.port != 0, MSG("option 'port' is required"));

    module_option_string("user", &mod->config.user, NULL);
    asc_assert(mod->config.user != NULL, MSG("option 'user' is required"));

    value_str = NULL;
    module_option_string("pass", &value_str, NULL);
    asc_assert(value_str != NULL, MSG("option 'pass' is required"));
    md5_crypt(value_str, "$1$abcdefgh$", mod->config.pass);

    value_str = "0102030405060708091011121314";
    value_length = 28;
    if(module_option_string("key", &value_str, &value_length))
        asc_assert(value_length == 28, MSG("option 'key' must be 28 chars length"));
    str_to_hex(value_str, mod->config.key, sizeof(mod->config.key));

    if(module_option_string("caid", &value_str, &value_length))
    {
        asc_assert(value_length == 4, MSG("option 'caid' must be 4 chars length"));
        uint8_t caid[2];
        str_to_hex(value_str, caid, sizeof(caid));
        mod->config.caid = BUFFER_TO_U16(caid);
    }

    module_option_number("timeout", &mod->config.timeout);
    if(!mod->config.timeout)
        mod->config.timeout = 8;
    mod->config.timeout *= 1000;

    module_option_boolean("disable_emm", &mod->config.disable_emm);

    lua_getfield(lua, MODULE_OPTIONS_IDX, "callback");
    if(lua_isfunction(lua, -1))
    {
        mod->idx_callback = luaL_ref(lua, LUA_REGISTRYINDEX);
        mod->status_timer = asc_timer_init(1000, on_status_timer, mod);
    }
    else
        lua_pop(lua, 1);

    module_cam_init(mod, newcamd_connect, newcamd_disconnect, newcamd_send_em);

    bool force = false;
    module_option_boolean("force", &force);
    if(force)
        newcamd_connect(mod);
}

static void module_destroy(module_data_t *mod)
{
    method_close(mod);
    module_cam_destroy(mod);
}

static const char * module_name(void)
{
    return "softcam/newcamd";
}

MODULE_CAM_METHODS()
MODULE_LUA_METHODS()
{
    { "info", method_info },
    { "close", method_close },
    MODULE_CAM_METHODS_REF()
};
MODULE_LUA_REGISTER(newcamd)
