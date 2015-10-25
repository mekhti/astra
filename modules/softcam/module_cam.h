/*
 * Astra Module: SoftCAM
 * http://cesbo.com/astra
 *
 * Copyright (C) 2013-2015, Andrey Dyldin <and@cesbo.com>
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

#ifndef _MODULE_CAM_H_
#define _MODULE_CAM_H_ 1

#include <astra.h>

#define EM_MAX_SIZE 1024

typedef struct module_decrypt_t module_decrypt_t;
typedef struct module_cam_t module_cam_t;
typedef struct module_cas_t module_cas_t;

typedef struct em_packet_t em_packet_t;

#define IS_ECM(_buffer) (((_buffer)[0] & (~0x01)) == 0x80)

/*
 *  ____            _        _
 * |  _ \ __ _  ___| | _____| |_
 * | |_) / _` |/ __| |/ / _ \ __|
 * |  __/ (_| | (__|   <  __/ |_
 * |_|   \__,_|\___|_|\_\___|\__|
 *
 */

struct em_packet_t
{
    uint8_t buffer[EM_MAX_SIZE];
    uint16_t buffer_size;

    module_decrypt_t *decrypt;
    void *arg;
};

/*
 *   ____    _    __  __
 *  / ___|  / \  |  \/  |
 * | |     / _ \ | |\/| |
 * | |___ / ___ \| |  | |
 *  \____/_/   \_\_|  |_|
 *
 */

struct module_cam_t
{
    module_data_t *self;

    bool is_ready;

    uint16_t caid;
    bool au;
    uint8_t ua[8];
    bool disable_emm;

    asc_list_t *prov_list;
    asc_list_t *decrypt_list;
    asc_list_t *packet_queue;

    void (*connect)(module_data_t *mod);
    void (*disconnect)(module_data_t *mod);
    void (*send_em)(  module_data_t *mod
                    , module_decrypt_t *decrypt, void *arg
                    , const uint8_t *buffer, uint16_t size);
};

#define MODULE_CAM_DATA() module_cam_t __cam

void module_cam_attach_decrypt(module_cam_t *cam, module_decrypt_t *decrypt);
void module_cam_detach_decrypt(module_cam_t *cam, module_decrypt_t *decrypt);

void module_cam_ready(module_cam_t *cam);
void module_cam_reset(module_cam_t *cam);

em_packet_t * module_cam_queue_pop(module_cam_t *cam);
void module_cam_queue_flush(module_cam_t *cam, module_decrypt_t *decrypt);

#define module_cam_init(_mod, _connect, _disconnect, _send_em)                                  \
    {                                                                                           \
        _mod->__cam.self = _mod;                                                                \
        _mod->__cam.decrypt_list = asc_list_init();                                             \
        _mod->__cam.prov_list = asc_list_init();                                                \
        _mod->__cam.packet_queue = asc_list_init();                                             \
        _mod->__cam.connect = _connect;                                                         \
        _mod->__cam.disconnect = _disconnect;                                                   \
        _mod->__cam.send_em = _send_em;                                                         \
    }

#define module_cam_destroy(_mod)                                                                \
    {                                                                                           \
        module_cam_reset(&_mod->__cam);                                                         \
        asc_list_clear(_mod->__cam.decrypt_list);                                               \
        asc_list_destroy(_mod->__cam.decrypt_list);                                             \
        asc_list_destroy(_mod->__cam.prov_list);                                                \
        asc_list_destroy(_mod->__cam.packet_queue);                                             \
    }

#define MODULE_CAM_METHODS()                                                                    \
    static int module_cam_cam(module_data_t *mod)                                               \
    {                                                                                           \
        lua_pushlightuserdata(lua, &mod->__cam);                                                \
        return 1;                                                                               \
    }

#define MODULE_CAM_METHODS_REF()                                                                \
    { "cam", module_cam_cam }

/*
 *   ____    _    ____
 *  / ___|  / \  / ___|
 * | |     / _ \ \___ \
 * | |___ / ___ \ ___) |
 *  \____/_/   \_\____/
 *
 */

struct module_cas_t
{
    module_data_t *self;
    module_decrypt_t *decrypt;

    bool (*check_cat_desc)(module_data_t *cas_data, const uint8_t *desc);
    bool (*check_pmt_desc)(module_data_t *cas_data, const uint8_t *desc);
    bool (*check_em)(module_data_t *cas_data, mpegts_psi_t *em);
    bool (*check_keys)(module_data_t *cas_data, const uint8_t *keys);
};

#define MODULE_CAS_DATA() module_cas_t __cas

#define module_cas_check_cat_desc(_cas, _desc) _cas->check_cat_desc(_cas->self, _desc)
#define module_cas_check_pmt_desc(_cas, _desc) _cas->check_pmt_desc(_cas->self, _desc)
#define module_cas_check_em(_cas, _em) _cas->check_em(_cas->self, _em)
#define module_cas_check_keys(_cas, _keys) _cas->check_keys(_cas->self, _keys)

#define MODULE_CAS(_name)                                                                       \
    module_cas_t * _name##_cas_init(module_decrypt_t *decrypt)                                  \
    {                                                                                           \
        if(!cas_check_caid(decrypt->cam->caid)) return NULL;                                    \
        module_data_t *mod = calloc(1, sizeof(module_data_t));                                  \
        mod->__cas.self = mod;                                                                  \
        mod->__cas.decrypt = decrypt;                                                           \
        mod->__cas.check_cat_desc = cas_check_cat_desc;                                         \
        mod->__cas.check_pmt_desc = cas_check_pmt_desc;                                         \
        mod->__cas.check_em = cas_check_em;                                                     \
        mod->__cas.check_keys = cas_check_keys;                                                 \
        return &mod->__cas;                                                                     \
    }

/*
 *  ____                             _
 * |  _ \  ___  ___ _ __ _   _ _ __ | |_
 * | | | |/ _ \/ __| '__| | | | '_ \| __|
 * | |_| |  __/ (__| |  | |_| | |_) | |_
 * |____/ \___|\___|_|   \__, | .__/ \__|
 *                       |___/|_|
 */

struct module_decrypt_t
{
    module_data_t *self;

    uint16_t pnr;
    uint16_t cas_pnr;
    bool is_cas_data;
    uint8_t cas_data[32];

    module_cam_t *cam;
    module_cas_t *cas;
};

#define MODULE_DECRYPT_DATA() module_decrypt_t __decrypt

void on_cam_ready(module_data_t *mod);
void on_cam_error(module_data_t *mod);
void on_cam_response(module_data_t *mod, void *arg, const uint8_t *data);

#endif /* _MODULE_CAM_H_ */
