/*
 * Astra Module: MPEG-TS (Analyze)
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

/*
 * Module Name:
 *      analyze
 *
 * Module Options:
 *      upstream    - object, stream instance returned by module_instance:stream()
 *      name        - string, analyzer name
 *      rate_stat   - boolean, dump bitrate with 10ms interval
 *      join_pid    - boolean, request all SI tables on the upstream module
 *      callback    - function(data), events callback:
 *                    data.error    - string,
 *                    data.psi      - table, psi information (PAT, PMT, CAT, SDT)
 *                    data.analyze  - table, per pid information: errors, bitrate
 *                    data.on_air   - boolean, comes with data.analyze, stream status
 *                    data.rate     - table, rate_stat array
 */

#include <astra.h>

typedef struct
{
    mpegts_packet_type_t type;

    uint8_t cc;

    uint32_t packets;

    // errors
    uint32_t cc_error;  // Continuity Counter
    uint32_t sc_error;  // Scrambled
    uint32_t pes_error; // PES header
} analyze_item_t;

typedef struct
{
    uint16_t pnr;
    uint32_t crc;
} pmt_checksum_t;

struct module_data_t
{
    MODULE_STREAM_DATA();

    const char *name;
    bool rate_stat;
    int cc_limit;
    int bitrate_limit;
    bool join_pid;

    bool cc_check; // to skip initial cc errors
    bool video_check; // increase bitrate_limit for channel with video stream

    int idx_callback;

    uint16_t tsid;

    asc_timer_t *check_stat;
    analyze_item_t *stream[MAX_PID];

    mpegts_psi_t *pat;
    mpegts_psi_t *cat;
    mpegts_psi_t *pmt;
    mpegts_psi_t *nit;
    mpegts_psi_t *sdt;

    int pmt_ready;
    int pmt_count;
    pmt_checksum_t *pmt_checksum_list;

    uint8_t sdt_max_section_id;
    uint32_t *sdt_checksum_list;

    // rate_stat
    uint64_t last_ts;
    uint32_t ts_count;
    int rate_count;
    int rate[10];
};

#define MSG(_msg) "[analyze %s] " _msg, mod->name

static const char __pid_static[] = "pid";
static const char __crc32_static[] = "crc32";
static const char __pnr_static[] = "pnr";
static const char __tsid_static[] = "tsid";
static const char __desc_static[] = "descriptors";
static const char __psi_static[] = "psi";
static const char __err_static[] = "error";

static void callback(module_data_t *mod)
{
    asc_assert((lua_type(lua, -1) == LUA_TTABLE), "table required");

    lua_rawgeti(lua, LUA_REGISTRYINDEX, mod->idx_callback);
    lua_pushvalue(lua, -2);
    lua_call(lua, 1, 0);

    lua_pop(lua, 1); // data
}

/*
 *  ____   _  _____
 * |  _ \ / \|_   _|
 * | |_) / _ \ | |
 * |  __/ ___ \| |
 * |_| /_/   \_\_|
 *
 */

static void on_pat(void *arg, mpegts_psi_t *psi)
{
    module_data_t *mod = (module_data_t *)arg;

    if(psi->buffer[0] != 0x00)
        return;

    // check changes
    const uint32_t crc32 = PSI_GET_CRC32(psi);
    if(crc32 == psi->crc32)
        return;

    lua_newtable(lua);

    lua_pushnumber(lua, psi->pid);
    lua_setfield(lua, -2, __pid_static);

    // check crc
    if(crc32 != PSI_CALC_CRC32(psi))
    {
        lua_pushstring(lua, "PAT checksum error");
        lua_setfield(lua, -2, __err_static);
        callback(mod);
        return;
    }

    psi->crc32 = crc32;
    mod->tsid = PAT_GET_TSID(psi);

    lua_pushstring(lua, "pat");
    lua_setfield(lua, -2, __psi_static);

    lua_pushnumber(lua, psi->crc32);
    lua_setfield(lua, -2, __crc32_static);

    lua_pushnumber(lua, mod->tsid);
    lua_setfield(lua, -2, __tsid_static);

    mod->pmt_ready = 0;
    mod->pmt_count = 0;

    lua_newtable(lua);
    const uint8_t *pointer;
    PAT_ITEMS_FOREACH(psi, pointer)
    {
        const uint16_t pnr = PAT_ITEM_GET_PNR(psi, pointer);
        const uint16_t pid = PAT_ITEM_GET_PID(psi, pointer);

        if(!pid || pid >= NULL_TS_PID)
            continue;

        const int item_count = luaL_len(lua, -1) + 1;
        lua_pushnumber(lua, item_count);
        lua_newtable(lua);
        lua_pushnumber(lua, pnr);
        lua_setfield(lua, -2, __pnr_static);
        lua_pushnumber(lua, pid);
        lua_setfield(lua, -2, __pid_static);
        lua_settable(lua, -3); // append to the "programs" table

        if(!mod->stream[pid])
            mod->stream[pid] = (analyze_item_t *)calloc(1, sizeof(analyze_item_t));

        if(pnr != 0)
        {
            if(mod->stream[pid]->type && mod->stream[pid]->type != MPEGTS_PACKET_PMT)
                asc_log_warning(MSG("PID:%d duplicated in PAT"), pid);

            mod->stream[pid]->type = MPEGTS_PACKET_PMT;
            if(mod->join_pid)
                module_stream_demux_join_pid(mod, pid);
            ++mod->pmt_count;
        }
        else if(pid != NIT_PID)
        {
            mod->stream[pid]->type = MPEGTS_PACKET_NIT;
            if(mod->join_pid)
                module_stream_demux_join_pid(mod, pid);
        }
    }
    lua_setfield(lua, -2, "programs");

    if(mod->pmt_checksum_list)
    {
        free(mod->pmt_checksum_list);
        mod->pmt_checksum_list = NULL;
    }
    if(mod->pmt_count > 0)
        mod->pmt_checksum_list = (pmt_checksum_t *)calloc(mod->pmt_count, sizeof(pmt_checksum_t));

    callback(mod);
}

/*
 *   ____    _  _____
 *  / ___|  / \|_   _|
 * | |     / _ \ | |
 * | |___ / ___ \| |
 *  \____/_/   \_\_|
 *
 */

static void on_cat(void *arg, mpegts_psi_t *psi)
{
    module_data_t *mod = (module_data_t *)arg;

    const uint8_t *desc_pointer;

    if(psi->buffer[0] != 0x01)
        return;

    // check changes
    const uint32_t crc32 = PSI_GET_CRC32(psi);
    if(crc32 == psi->crc32)
        return;

    lua_newtable(lua);

    lua_pushnumber(lua, psi->pid);
    lua_setfield(lua, -2, __pid_static);

    // check crc
    if(crc32 != PSI_CALC_CRC32(psi))
    {
        lua_pushstring(lua, "CAT checksum error");
        lua_setfield(lua, -2, __err_static);
        callback(mod);
        return;
    }
    psi->crc32 = crc32;

    lua_pushstring(lua, "cat");
    lua_setfield(lua, -2, __psi_static);

    lua_pushnumber(lua, psi->crc32);
    lua_setfield(lua, -2, __crc32_static);

    lua_newtable(lua);
    CAT_DESC_FOREACH(psi, desc_pointer)
    {
        const int desc_count = luaL_len(lua, -1) + 1;
        lua_pushnumber(lua, desc_count);
        mpegts_desc_to_lua(desc_pointer);
        lua_settable(lua, -3); // append to the "descriptors" table
    }
    lua_setfield(lua, -2, __desc_static);

    callback(mod);
}

/*
 *  _   _ ___ _____
 * | \ | |_ _|_   _|
 * |  \| || |  | |
 * | |\  || |  | |
 * |_| \_|___| |_|
 *
 */

#if 0
static void on_nit(void *arg, mpegts_psi_t *psi)
{
    module_data_t *mod = (module_data_t *)arg;
}
#endif

/*
 *  ____  __  __ _____
 * |  _ \|  \/  |_   _|
 * | |_) | |\/| | | |
 * |  __/| |  | | | |
 * |_|   |_|  |_| |_|
 *
 */

static void on_pmt(void *arg, mpegts_psi_t *psi)
{
    module_data_t *mod = (module_data_t *)arg;

    const uint8_t *pointer;
    const uint8_t *desc_pointer;

    if(psi->buffer[0] != 0x02)
        return;

    const uint32_t crc32 = PSI_GET_CRC32(psi);

    // check crc
    if(crc32 != PSI_CALC_CRC32(psi))
    {
        lua_newtable(lua);

        lua_pushnumber(lua, psi->pid);
        lua_setfield(lua, -2, __pid_static);

        lua_pushstring(lua, "PMT checksum error");
        lua_setfield(lua, -2, __err_static);
        callback(mod);
        return;
    }

    const uint16_t pnr = PMT_GET_PNR(psi);

    // check changes
    for(int i = 0; i < mod->pmt_count; ++i)
    {
        if(mod->pmt_checksum_list[i].pnr == pnr)
        {
            if(mod->pmt_checksum_list[i].crc == crc32)
                return;

            --mod->pmt_ready;
            mod->pmt_checksum_list[i].pnr = 0;
            break;
        }
    }

    for(int i = 0; i < mod->pmt_count; ++i)
    {
        if(mod->pmt_checksum_list[i].pnr == 0)
        {
            ++mod->pmt_ready;
            mod->pmt_checksum_list[i].pnr = pnr;
            mod->pmt_checksum_list[i].crc = crc32;
            break;
        }
    }

    mod->video_check = false;

    lua_newtable(lua);

    lua_pushnumber(lua, psi->pid);
    lua_setfield(lua, -2, __pid_static);

    lua_pushstring(lua, "pmt");
    lua_setfield(lua, -2, __psi_static);

    lua_pushnumber(lua, crc32);
    lua_setfield(lua, -2, __crc32_static);

    lua_pushnumber(lua, pnr);
    lua_setfield(lua, -2, __pnr_static);

    lua_newtable(lua);
    PMT_DESC_FOREACH(psi, desc_pointer)
    {
        const int desc_count = luaL_len(lua, -1) + 1;
        lua_pushnumber(lua, desc_count);
        mpegts_desc_to_lua(desc_pointer);
        lua_settable(lua, -3); // append to the "descriptors" table
    }
    lua_setfield(lua, -2, __desc_static);

    lua_pushnumber(lua, PMT_GET_PCR(psi));
    lua_setfield(lua, -2, "pcr");

    lua_newtable(lua);
    PMT_ITEMS_FOREACH(psi, pointer)
    {
        const uint16_t pid = PMT_ITEM_GET_PID(psi, pointer);
        const uint8_t type = PMT_ITEM_GET_TYPE(psi, pointer);

        if(!pid || pid >= NULL_TS_PID)
            continue;

        const int service_count = luaL_len(lua, -1) + 1;
        lua_pushnumber(lua, service_count);
        lua_newtable(lua);

        if(!mod->stream[pid])
            mod->stream[pid] = (analyze_item_t *)calloc(1, sizeof(analyze_item_t));

        mod->stream[pid]->type = mpegts_pes_type(type);

        lua_pushnumber(lua, pid);
        lua_setfield(lua, -2, __pid_static);

        lua_newtable(lua);
        PMT_ITEM_DESC_FOREACH(pointer, desc_pointer)
        {
            const int item_count = luaL_len(lua, -1) + 1;
            lua_pushnumber(lua, item_count);
            mpegts_desc_to_lua(desc_pointer);
            lua_settable(lua, -3); // append to the "streams[X].descriptors" table

            if(type == 0x06)
            {
                switch(desc_pointer[0])
                {
                    case 0x59:
                        mod->stream[pid]->type = MPEGTS_PACKET_SUB;
                        break;
                    case 0x6A:
                        mod->stream[pid]->type = MPEGTS_PACKET_AUDIO;
                        break;
                    default:
                        break;
                }
            }
        }
        lua_setfield(lua, -2, __desc_static);

        lua_pushstring(lua, mpegts_type_name(mod->stream[pid]->type));
        lua_setfield(lua, -2, "type_name");

        lua_pushnumber(lua, type);
        lua_setfield(lua, -2, "type_id");

        lua_settable(lua, -3); // append to the "streams" table

        if(mod->stream[pid]->type == MPEGTS_PACKET_VIDEO)
            mod->video_check = true;
    }
    lua_setfield(lua, -2, "streams");

    callback(mod);
}

/*
 *  ____  ____ _____
 * / ___||  _ \_   _|
 * \___ \| | | || |
 *  ___) | |_| || |
 * |____/|____/ |_|
 *
 */

static void on_sdt(void *arg, mpegts_psi_t *psi)
{
    module_data_t *mod = (module_data_t *)arg;

    const uint8_t *pointer;
    const uint8_t *desc_pointer;

    const uint8_t table_id = psi->buffer[0];
    if(table_id != 0x42)
        return;

    if((psi->buffer[1] & 0x80) != 0x80) // section_syntax_indicator
        return;

    if((psi->buffer[5] & 0x01) != 0x01) // current_next_indicator
        return;

    const uint32_t crc32 = PSI_GET_CRC32(psi);

    // check crc
    if(crc32 != PSI_CALC_CRC32(psi))
    {
        lua_newtable(lua);

        lua_pushnumber(lua, psi->pid);
        lua_setfield(lua, -2, __pid_static);

        lua_pushstring(lua, "SDT checksum error");
        lua_setfield(lua, -2, __err_static);
        callback(mod);
        return;
    }

    // check changes
    if(!mod->sdt_checksum_list)
    {
        const uint8_t max_section_id = SDT_GET_LSECTION_NUMBER(psi);
        mod->sdt_max_section_id = max_section_id;
        mod->sdt_checksum_list = (uint32_t *)calloc(max_section_id + 1, sizeof(uint32_t));
    }
    const uint8_t section_id = SDT_GET_CSECTION_NUMBER(psi);
    if(section_id > mod->sdt_max_section_id)
    {
        asc_log_warning(MSG("SDT: section_number is greater then section_last_number"));
        return;
    }
    if(mod->sdt_checksum_list[section_id] == crc32)
        return;

    if(mod->sdt_checksum_list[section_id] != 0)
    {
        // Reload stream
        free(mod->sdt_checksum_list);
        mod->sdt_checksum_list = NULL;
        return;
    }

    mod->sdt_checksum_list[section_id] = crc32;

    lua_newtable(lua);

    lua_pushnumber(lua, psi->pid);
    lua_setfield(lua, -2, __pid_static);

    lua_pushstring(lua, "sdt");
    lua_setfield(lua, -2, __psi_static);

    lua_pushnumber(lua, crc32);
    lua_setfield(lua, -2, __crc32_static);

    lua_pushnumber(lua, table_id);
    lua_setfield(lua, -2, "table_id");

    lua_pushnumber(lua, mod->tsid);
    lua_setfield(lua, -2, __tsid_static);

    lua_newtable(lua);
    SDT_ITEMS_FOREACH(psi, pointer)
    {
        const uint16_t sid = SDT_ITEM_GET_SID(psi, pointer);

        const int service_count = luaL_len(lua, -1) + 1;
        lua_pushnumber(lua, service_count);

        lua_newtable(lua);
        lua_pushnumber(lua, sid);
        lua_setfield(lua, -2, "sid");

        lua_newtable(lua);
        SDT_ITEM_DESC_FOREACH(pointer, desc_pointer)
        {
            const int desc_count = luaL_len(lua, -1) + 1;
            lua_pushnumber(lua, desc_count);
            mpegts_desc_to_lua(desc_pointer);
            lua_settable(lua, -3);
        }
        lua_setfield(lua, -2, __desc_static);

        lua_settable(lua, -3); // append to the "services[service_count]" table
    }
    lua_setfield(lua, -2, "services");

    callback(mod);
}

/*
 *  _____ ____
 * |_   _/ ___|
 *   | | \___ \
 *   | |  ___) |
 *   |_| |____/
 *
 */

static void append_rate(module_data_t *mod, int rate)
{
    mod->rate[mod->rate_count] = rate;
    ++mod->rate_count;
    if(mod->rate_count >= (int)(sizeof(mod->rate)/sizeof(*mod->rate)))
    {
        lua_newtable(lua);
        lua_newtable(lua);
        for(int i = 0; i < mod->rate_count; ++i)
        {
            lua_pushnumber(lua, i + 1);
            lua_pushnumber(lua, mod->rate[i]);
            lua_settable(lua, -3);
        }
        lua_setfield(lua, -2, "rate");
        callback(mod);
        mod->rate_count = 0;
    }
}

static void on_ts(module_data_t *mod, const uint8_t *ts)
{
    if(mod->rate_stat)
    {
        ++mod->ts_count;

        uint64_t diff_interval = 0;
        const uint64_t cur = asc_utime() / 10000;

        if(cur != mod->last_ts)
        {
            if(mod->last_ts != 0 && cur > mod->last_ts)
                diff_interval = cur - mod->last_ts;

            mod->last_ts = cur;
        }

        if(diff_interval > 0)
        {
            if(diff_interval > 1)
            {
                for(; diff_interval > 0; --diff_interval)
                    append_rate(mod, 0);
            }

            append_rate(mod, mod->ts_count);
            mod->ts_count = 0;
        }
    }

    const uint16_t pid = TS_GET_PID(ts);
    analyze_item_t *item = NULL;
    if(ts[0] == 0x47 && pid < MAX_PID)
        item = mod->stream[pid];
    if(!item)
        item = mod->stream[NULL_TS_PID];

    ++item->packets;

    if(item->type == MPEGTS_PACKET_NULL)
        return;

    if(item->type & (MPEGTS_PACKET_PSI | MPEGTS_PACKET_SI))
    {
        switch(item->type)
        {
            case MPEGTS_PACKET_PAT:
                mpegts_psi_mux(mod->pat, ts, on_pat, mod);
                break;
            case MPEGTS_PACKET_CAT:
                mpegts_psi_mux(mod->cat, ts, on_cat, mod);
                break;
            case MPEGTS_PACKET_PMT:
                mod->pmt->pid = pid;
                mpegts_psi_mux(mod->pmt, ts, on_pmt, mod);
                break;
            case MPEGTS_PACKET_SDT:
                mpegts_psi_mux(mod->sdt, ts, on_sdt, mod);
                break;
#if 0
            case MPEGTS_PACKET_NIT:
                mpegts_psi_mux(mod->nit, ts, on_nit, mod);
                break;
#endif
            default:
                break;
        }
    }

    // Analyze

    // skip packets without payload
    if(!TS_IS_PAYLOAD(ts))
        return;

    const uint8_t cc = TS_GET_CC(ts);
    const uint8_t last_cc = (item->cc + 1) & 0x0F;
    item->cc = cc;

    if(cc != last_cc)
        ++item->cc_error;

    if(TS_IS_SCRAMBLED(ts))
        ++item->sc_error;

    if(!(item->type & MPEGTS_PACKET_PES))
        return;

    if(item->type == MPEGTS_PACKET_VIDEO && TS_IS_PAYLOAD_START(ts))
    {
        const uint8_t *payload = TS_GET_PAYLOAD(ts);
        if(payload && PES_BUFFER_GET_HEADER(payload) != 0x000001)
            ++item->pes_error;
    }
}

/*
 *  ____  _        _
 * / ___|| |_ __ _| |_
 * \___ \| __/ _` | __|
 *  ___) | || (_| | |_
 * |____/ \__\__,_|\__|
 *
 */

static void on_check_stat(void *arg)
{
    module_data_t *mod = (module_data_t *)arg;

    int items_count = 1;
    lua_newtable(lua);

    bool on_air = true;

    uint32_t datarate = 0;
    uint32_t totalrate = 0;
    uint32_t cc_errors = 0;
    uint32_t pes_errors = 0;
    bool scrambled = false;

    const uint32_t bitrate_limit = (mod->bitrate_limit > 0)
                                 ? ((uint32_t)mod->bitrate_limit)
                                 : ((mod->video_check) ? 128 : 16);

    lua_newtable(lua);
    for(int i = 0; i < MAX_PID; ++i)
    {
        analyze_item_t *item = mod->stream[i];

        if(!item)
            continue;

        if(!mod->cc_check)
            item->cc_error = 0;

        lua_pushnumber(lua, items_count++);
        lua_newtable(lua);

        lua_pushnumber(lua, i);
        lua_setfield(lua, -2, __pid_static);

        const uint32_t item_bitrate = (item->packets * TS_PACKET_SIZE * 8) / 1000;
        totalrate += item_bitrate;

        lua_pushnumber(lua, item_bitrate);
        lua_setfield(lua, -2, "bitrate");

        lua_pushnumber(lua, item->cc_error);
        lua_setfield(lua, -2, "cc_error");
        lua_pushnumber(lua, item->sc_error);
        lua_setfield(lua, -2, "sc_error");
        lua_pushnumber(lua, item->pes_error);
        lua_setfield(lua, -2, "pes_error");

        cc_errors += item->cc_error;
        pes_errors += item->pes_error;

        if(item->type == MPEGTS_PACKET_VIDEO || item->type == MPEGTS_PACKET_AUDIO)
        {
            if(item->sc_error)
            {
                scrambled = true;
                on_air = false;
            }
            if(item->pes_error > 2)
                on_air = false;

            datarate += item_bitrate;
        }

        item->packets = 0;
        item->cc_error = 0;
        item->sc_error = 0;
        item->pes_error = 0;

        lua_settable(lua, -3);
    }
    lua_setfield(lua, -2, "analyze");

    lua_newtable(lua);
    {
        lua_pushnumber(lua, totalrate);
        lua_setfield(lua, -2, "bitrate");
        lua_pushnumber(lua, cc_errors);
        lua_setfield(lua, -2, "cc_errors");
        lua_pushnumber(lua, pes_errors);
        lua_setfield(lua, -2, "pes_errors");
        lua_pushboolean(lua, scrambled);
        lua_setfield(lua, -2, "scrambled");
    }
    lua_setfield(lua, -2, "total");

    if(!mod->cc_check)
        mod->cc_check = true;

    if(datarate < bitrate_limit)
        on_air = false;
    if(mod->cc_limit > 0 && cc_errors >= (uint32_t)mod->cc_limit)
        on_air = false;
    if(mod->pmt_ready == 0 || mod->pmt_ready != mod->pmt_count)
        on_air = false;

    lua_pushboolean(lua, on_air);
    lua_setfield(lua, -2, "on_air");

    callback(mod);
}

/*
 *  __  __           _       _
 * |  \/  | ___   __| |_   _| | ___
 * | |\/| |/ _ \ / _` | | | | |/ _ \
 * | |  | | (_) | (_| | |_| | |  __/
 * |_|  |_|\___/ \__,_|\__,_|_|\___|
 *
 */

static void module_init(module_data_t *mod)
{
    module_option_string("name", &mod->name, NULL);
    asc_assert(mod->name != NULL, "[analyze] option 'name' is required");

    lua_getfield(lua, MODULE_OPTIONS_IDX, "callback");
    asc_assert(lua_isfunction(lua, -1), MSG("option 'callback' is required"));
    mod->idx_callback = luaL_ref(lua, LUA_REGISTRYINDEX);

    module_option_boolean("rate_stat", &mod->rate_stat);
    module_option_number("cc_limit", &mod->cc_limit);
    module_option_number("bitrate_limit", &mod->bitrate_limit);
    module_option_boolean("join_pid", &mod->join_pid);

    module_stream_init(mod, on_ts);
    if(mod->join_pid)
    {
        module_stream_demux_set(mod, NULL, NULL);
        module_stream_demux_join_pid(mod, PAT_PID);
        module_stream_demux_join_pid(mod, CAT_PID);
        module_stream_demux_join_pid(mod, NIT_PID);
        module_stream_demux_join_pid(mod, SDT_PID);
        module_stream_demux_join_pid(mod, EIT_PID);
    }

    // PAT
    mod->stream[PAT_PID] = (analyze_item_t *)calloc(1, sizeof(analyze_item_t));
    mod->stream[PAT_PID]->type = MPEGTS_PACKET_PAT;
    mod->pat = mpegts_psi_init(MPEGTS_PACKET_PAT, PAT_PID);
    // CAT
    mod->stream[CAT_PID] = (analyze_item_t *)calloc(1, sizeof(analyze_item_t));
    mod->stream[CAT_PID]->type = MPEGTS_PACKET_CAT;
    mod->cat = mpegts_psi_init(MPEGTS_PACKET_CAT, CAT_PID);
    // NIT
    mod->stream[NIT_PID] = (analyze_item_t *)calloc(1, sizeof(analyze_item_t));
    mod->stream[NIT_PID]->type = MPEGTS_PACKET_NIT;
    mod->nit = mpegts_psi_init(MPEGTS_PACKET_NIT, NIT_PID);
    // SDT
    mod->stream[SDT_PID] = (analyze_item_t *)calloc(1, sizeof(analyze_item_t));
    mod->stream[SDT_PID]->type = MPEGTS_PACKET_SDT;
    mod->sdt = mpegts_psi_init(MPEGTS_PACKET_SDT, SDT_PID);
    // EIT
    mod->stream[EIT_PID] = (analyze_item_t *)calloc(1, sizeof(analyze_item_t));
    mod->stream[EIT_PID]->type = MPEGTS_PACKET_EIT;
    // PMT
    mod->pmt = mpegts_psi_init(MPEGTS_PACKET_PMT, MAX_PID);
    // NULL
    mod->stream[NULL_TS_PID] = (analyze_item_t *)calloc(1, sizeof(analyze_item_t));
    mod->stream[NULL_TS_PID]->type = MPEGTS_PACKET_NULL;

    mod->check_stat = asc_timer_init(1000, on_check_stat, mod);
}

static void module_destroy(module_data_t *mod)
{
    module_stream_destroy(mod);

    if(mod->idx_callback)
    {
        luaL_unref(lua, LUA_REGISTRYINDEX, mod->idx_callback);
        mod->idx_callback = 0;
    }

    for(int i = 0; i < MAX_PID; ++i)
    {
        if(mod->stream[i])
            free(mod->stream[i]);
    }

    mpegts_psi_destroy(mod->pat);
    mpegts_psi_destroy(mod->cat);
    mpegts_psi_destroy(mod->nit);
    mpegts_psi_destroy(mod->sdt);
    mpegts_psi_destroy(mod->pmt);

    asc_timer_destroy(mod->check_stat);

    if(mod->pmt_checksum_list)
        free(mod->pmt_checksum_list);
    if(mod->sdt_checksum_list)
        free(mod->sdt_checksum_list);
}

static const char * module_name(void)
{
    return "mpegts/analyze";
}

MODULE_STREAM_METHODS()
MODULE_LUA_METHODS()
{
    MODULE_STREAM_METHODS_REF()
};
MODULE_LUA_REGISTER(analyze)
