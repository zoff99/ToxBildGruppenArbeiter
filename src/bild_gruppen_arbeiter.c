/*
 * 
 * Zoff <zoff@zoff.cc>
 * in 2017
 *
 * dirty hack (echobot and toxic were used as blueprint)
 *
 *
 */

#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>

// --- tweak in A.S. ---
// --- tweak in A.S. ---
#include "tox/tox.h"
#include "tox/toxav.h"
#include "sodium.h"

#include <tox/tox.h>
#include <tox/toxav.h>
#include <sodium.h>
// --- tweak in A.S. ---
// --- tweak in A.S. ---


// ----------- version -----------
// ----------- version -----------
#define VERSION_MAJOR 0
#define VERSION_MINOR 99
#define VERSION_PATCH 9
static const char global_version_string[] = "0.99.9";
// ----------- version -----------
// ----------- version -----------


#define CURRENT_LOG_LEVEL 9 // 0 -> error, 1 -> warn, 2 -> info, 9 -> debug
#define RECONNECT_AFTER_OFFLINE_SECONDS 90 // 90s offline and we try to reconnect
#define PROXY_PORT_TOR_DEFAULT 9050
#define CLEAR(x) memset(&(x), 0, sizeof(x))
#define c_sleep(x) usleep(1000*x)
#define DEFAULT_FPS_SLEEP_MS 160 // 250=4fps, 500=2fps, 160=6fps  // default video fps (sleep in msecs.)
#define DEFAULT_GLOBAL_MIN_VID_BITRATE 200 // kbit/sec
#define DEFAULT_GLOBAL_MAX_VID_BITRATE 20000 // kbit/sec
#define DEFAULT_GLOBAL_NORMAL_VID_BITRATE 500

static uint64_t last_purge;
uint64_t global_start_time;

static int32_t audio_bitrate = 32; // kbits/s
static int32_t video_bitrate = DEFAULT_GLOBAL_NORMAL_VID_BITRATE; // kbits/s
static const char *savedata_filename = "savedata.tox";
const char *savedata_tmp_filename = "savedata.tox.tmp";
const char *log_filename = "bild_gruppen_arbeiter.log";
static const char *bot_name = "BildGruppenArbeiter";
static const char *bot_status_msg = "VideoConfBot. Send 'help' for Usage";
time_t my_last_offline_timestamp = -1;
time_t my_last_online_timestamp = -1;
int switch_tcponly = 0;
int use_tor = 0;
int switch_nodelist_2 = 0;
FILE *logfile = NULL;
ToxAV *mytox_av = NULL;
Tox *mytox_global = NULL;
int toxav_video_thread_stop = 0;
int toxav_iterate_thread_stop = 0;
int tox_loop_running = 1;
int global_want_restart = 0;
TOX_CONNECTION my_connection_status = TOX_CONNECTION_NONE;
int global_video_active = 0;
int64_t friend_to_take_av_from = -1;

const char *tv_pubkey_filename = "tv_pubkey.txt";
uint8_t *global_tv_toxid = NULL;
int64_t global_tv_friendnum = -1;
int global_tv_video_active = 0;

const char *cam_pubkey_filename = "cam_pubkey.txt";
uint8_t *global_cam_toxid = NULL;
int64_t global_cam_friendnum = -1;
int global_cam_video_active = 0;


typedef struct DHT_node
{
    const char *ip;
    uint16_t port;
    const char key_hex[TOX_PUBLIC_KEY_SIZE * 2 + 1];
    unsigned char key_bin[TOX_PUBLIC_KEY_SIZE];
} DHT_node;




// ------ function defs ------
void update_savedata_file(const Tox *tox);
void get_my_toxid(Tox *tox, char *toxid_str);
void av_local_disconnect(ToxAV *av, uint32_t friendnum);
void disconnect_all_calls(Tox *tox);
// ------ function defs ------




void dbg(int level, const char *fmt, ...)
{
    char *level_and_format = NULL;
    char *fmt_copy = NULL;

    if (fmt == NULL)
    {
        return;
    }

    if (strlen(fmt) < 1)
    {
        return;
    }

    if (!logfile)
    {
        return;
    }

    if ((level < 0) || (level > 9))
    {
        level = 0;
    }

    level_and_format = malloc(strlen(fmt) + 3 + 1);

    if (!level_and_format)
    {
        // fprintf(stderr, "free:000a\n");
        return;
    }

    fmt_copy = level_and_format + 2;
    strcpy(fmt_copy, fmt);
    level_and_format[1] = ':';
    if (level == 0)
    {
        level_and_format[0] = 'E';
    }
    else if (level == 1)
    {
        level_and_format[0] = 'W';
    }
    else if (level == 2)
    {
        level_and_format[0] = 'I';
    }
    else
    {
        level_and_format[0] = 'D';
    }

    level_and_format[(strlen(fmt) + 2)] = '\n';
    level_and_format[(strlen(fmt) + 3)] = '\0';

    time_t t3 = time(NULL);
    struct tm tm3 = *localtime(&t3);

    char *level_and_format_2 = malloc(strlen(level_and_format) + 5 + 3 + 3 + 1 + 3 + 3 + 3 + 1);
    level_and_format_2[0] = '\0';
    snprintf(level_and_format_2, (strlen(level_and_format) + 5 + 3 + 3 + 1 + 3 + 3 + 3 + 1),
             "%04d-%02d-%02d %02d:%02d:%02d:%s",
             tm3.tm_year + 1900, tm3.tm_mon + 1, tm3.tm_mday,
             tm3.tm_hour, tm3.tm_min, tm3.tm_sec, level_and_format);

    if (level <= CURRENT_LOG_LEVEL)
    {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(logfile, level_and_format_2, ap);
        va_end(ap);
    }

    // fprintf(stderr, "free:001\n");
    if (level_and_format)
    {
        // fprintf(stderr, "free:001.a\n");
        free(level_and_format);
    }

    if (level_and_format_2)
    {
        free(level_and_format_2);
    }
    // fprintf(stderr, "free:002\n");
}

void yieldcpu(uint32_t ms)
{
    usleep(1000 * ms);
}


time_t get_unix_time(void)
{
    return time(NULL);
}

int get_number_in_string(const char *str, int default_value)
{
    int number;

    while (!(*str >= '0' && *str <= '9') && (*str != '-') && (*str != '+')) str++;

    if (sscanf(str, "%d", &number) == 1)
    {
        return number;
    }

    // no int found, return default value
    return default_value; 
}

/* ssssshhh I stole this from ToxBot, don't tell anyone.. */
/* ssssshhh and I stole this from EchoBot, don't tell anyone.. */
static void get_elapsed_time_str(char *buf, int bufsize, uint64_t secs)
{
    long unsigned int minutes = (secs % 3600) / 60;
    long unsigned int hours = (secs / 3600) % 24;
    long unsigned int days = (secs / 3600) / 24;

    snprintf(buf, bufsize, "%lud %luh %lum", days, hours, minutes);
}

void bin_to_hex_string(uint8_t *tox_id_bin, size_t tox_id_bin_len, char *toxid_str)
{
    char tox_id_hex_local[TOX_ADDRESS_SIZE * 2 + 1];
    CLEAR(tox_id_hex_local);

    // dbg(9, "bin_to_hex_string:sizeof(tox_id_hex_local)=%d\n", (int)sizeof(tox_id_hex_local));
    // dbg(9, "bin_to_hex_string:strlen(tox_id_bin)=%d\n", (int)tox_id_bin_len);

    sodium_bin2hex(tox_id_hex_local, sizeof(tox_id_hex_local), tox_id_bin, tox_id_bin_len);

    for (size_t i = 0; i < sizeof(tox_id_hex_local) - 1; i++)
    {
        // dbg(9, "i=%d\n", i);
        tox_id_hex_local[i] = toupper(tox_id_hex_local[i]);
    }

    snprintf(toxid_str, (size_t) (TOX_ADDRESS_SIZE * 2 + 1), "%s", (const char *) tox_id_hex_local);
}


unsigned int char_to_int(char c)
{
    if (c >= '0' && c <= '9')
    { return c - '0'; }
    if (c >= 'A' && c <= 'F')
    { return 10 + c - 'A'; }
    if (c >= 'a' && c <= 'f')
    { return 10 + c - 'a'; }
    return -1;
}

uint8_t *hex_string_to_bin(const char *hex_string)
{
    size_t len = TOX_ADDRESS_SIZE;
    uint8_t *val = malloc(len);
    memset(val, 0, (size_t) len);

    // dbg(9, "hex_string_to_bin:len=%d\n", (int)len);

    for (size_t i = 0; i != len; ++i)
    {
        // dbg(9, "hex_string_to_bin:%d %d\n", hex_string[2*i], hex_string[2*i+1]);
        val[i] = (16 * char_to_int(hex_string[2 * i])) + (char_to_int(hex_string[2 * i + 1]));
        // dbg(9, "hex_string_to_bin:i=%d val[i]=%d\n", i, (int)val[i]);
    }

    return val;
}

//
// cut message at 999 chars length !!
//
void send_text_message_to_friend(Tox *tox, uint32_t friend_number, const char *fmt, ...)
{
    char msg2[1000];
    size_t length = 0;

    if (fmt == NULL)
    {
        dbg(9, "send_text_message_to_friend:no message to send");
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg2, 999, fmt, ap);
    va_end(ap);

    length = (size_t) strlen(msg2);
    tox_friend_send_message(tox,
                            friend_number,
                            TOX_MESSAGE_TYPE_NORMAL, (uint8_t *) msg2,
                            length,
                            NULL);
}

int64_t friend_number_for_cam(Tox *tox, uint8_t *tox_id_cam_bin)
{
    size_t i = 0;
    size_t size = tox_self_get_friend_list_size(tox);
    int64_t ret_friendnum = -1;

    if (size == 0)
    {
        return ret_friendnum;
    }

    if (tox_id_cam_bin == NULL)
    {
        return ret_friendnum;
    }

    uint32_t list[size];
    tox_self_get_friend_list(tox, list);
    char friend_key[TOX_PUBLIC_KEY_SIZE];
    CLEAR(friend_key);

    for (i = 0; i < size; ++i)
    {
        if (tox_friend_get_public_key(tox, list[i], (uint8_t *) friend_key, NULL) == 0)
        {
        }
        else
        {
            if (memcmp(tox_id_cam_bin, friend_key, TOX_PUBLIC_KEY_SIZE) == 0)
            {
                ret_friendnum = list[i];
                return ret_friendnum;
            }
        }
    }

    return ret_friendnum;
}


int64_t friend_number_for_tv(Tox *tox, uint8_t *tox_id_tv_bin)
{
    size_t i = 0;
    size_t size = tox_self_get_friend_list_size(tox);
    int64_t ret_friendnum = -1;

    if (size == 0)
    {
        return ret_friendnum;
    }

    if (tox_id_tv_bin == NULL)
    {
        return ret_friendnum;
    }

    uint32_t list[size];
    tox_self_get_friend_list(tox, list);
    char friend_key[TOX_PUBLIC_KEY_SIZE];
    CLEAR(friend_key);

    for (i = 0; i < size; ++i)
    {
        if (tox_friend_get_public_key(tox, list[i], (uint8_t *) friend_key, NULL) == 0)
        {
        }
        else
        {
            if (memcmp(tox_id_tv_bin, friend_key, TOX_PUBLIC_KEY_SIZE) == 0)
            {
                ret_friendnum = list[i];
                return ret_friendnum;
            }
        }
    }

    return ret_friendnum;
}

int is_friend_online(Tox *tox, uint32_t friendnum)
{
    TOX_ERR_FRIEND_QUERY error;
    TOX_CONNECTION res = tox_friend_get_connection_status(tox, friendnum, &error);

    switch (res)
    {
        case TOX_CONNECTION_NONE:
            return 0;
            break;
        case TOX_CONNECTION_TCP:
            return 1;
            break;
        case TOX_CONNECTION_UDP:
            return 1;
            break;
        default:
            return 0;
            break;
    }
}

void start_av_call_to_cam(Tox *tox, uint32_t friendnum)
{
    if (is_friend_online(tox, friendnum) == 1)
    {
        send_text_message_to_friend(tox, friendnum, "i am trying to send my video ...");

        if (mytox_av != NULL)
        {
            TOXAV_ERR_CALL error = 0;
            toxav_call(mytox_av, friendnum, audio_bitrate, video_bitrate, &error);

            if (error != TOXAV_ERR_CALL_OK)
            {
                switch (error)
                {
                    case TOXAV_ERR_CALL_MALLOC:
                        dbg(0, "toxav_call (1):TOXAV_ERR_CALL_MALLOC");
                        break;

                    case TOXAV_ERR_CALL_SYNC:
                        dbg(0, "toxav_call (1):TOXAV_ERR_CALL_SYNC");
                        break;

                    case TOXAV_ERR_CALL_FRIEND_NOT_FOUND:
                        dbg(0, "toxav_call (1):TOXAV_ERR_CALL_FRIEND_NOT_FOUND");
                        break;

                    case TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED:
                        dbg(0, "toxav_call (1):TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED");
                        break;

                    case TOXAV_ERR_CALL_FRIEND_ALREADY_IN_CALL:
                        dbg(0, "toxav_call (1):TOXAV_ERR_CALL_FRIEND_ALREADY_IN_CALL");
                        break;

                    case TOXAV_ERR_CALL_INVALID_BIT_RATE:
                        dbg(0, "toxav_call (1):TOXAV_ERR_CALL_INVALID_BIT_RATE");
                        break;

                    default:
                        dbg(0, "toxav_call (1):*unknown error*");
                        break;
                }
            }
            else
            {
                global_cam_video_active = 1;
                send_text_message_to_friend(tox, friendnum, "starting call to Cam");
            }
        }
        else
        {
            send_text_message_to_friend(tox, friendnum, "sending video failed:toxav==NULL");
        }
    }
}


void start_av_call_to_tv(Tox *tox, uint32_t friendnum)
{
   if (global_tv_video_active == 0)
   {
    if (is_friend_online(tox, friendnum) == 1)
    {
        // send_text_message_to_friend(tox, friendnum, "i am trying to send my video ...");
        // dbg(9, "start_av_call_to_tv ... %d", (int)friendnum);

        if (mytox_av != NULL)
        {
            TOXAV_ERR_CALL error = 0;
            toxav_call(mytox_av, friendnum, audio_bitrate, video_bitrate, &error);

            if (error != TOXAV_ERR_CALL_OK)
            {
                switch (error)
                {
                    case TOXAV_ERR_CALL_MALLOC:
                        dbg(0, "toxav_call (1):TOXAV_ERR_CALL_MALLOC");
                        break;

                    case TOXAV_ERR_CALL_SYNC:
                        dbg(0, "toxav_call (1):TOXAV_ERR_CALL_SYNC");
                        break;

                    case TOXAV_ERR_CALL_FRIEND_NOT_FOUND:
                        dbg(0, "toxav_call (1):TOXAV_ERR_CALL_FRIEND_NOT_FOUND");
                        break;

                    case TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED:
                        dbg(0, "toxav_call (1):TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED");
                        break;

                    case TOXAV_ERR_CALL_FRIEND_ALREADY_IN_CALL:
                        dbg(0, "toxav_call (1):TOXAV_ERR_CALL_FRIEND_ALREADY_IN_CALL");
                        // TODO: maybe end call and call again? sometimes the status is not 100% correct
                        global_tv_video_active = 1;
                        break;

                    case TOXAV_ERR_CALL_INVALID_BIT_RATE:
                        dbg(0, "toxav_call (1):TOXAV_ERR_CALL_INVALID_BIT_RATE");
                        break;

                    default:
                        dbg(0, "toxav_call (1):*unknown error*");
                        break;
                }
            }
            else
            {
                global_tv_video_active = 1;
                // send_text_message_to_friend(tox, friendnum, "starting call to TV");
                dbg(9, "starting call to TV");
            }
        }
        else
        {
            // send_text_message_to_friend(tox, friendnum, "sending video failed:toxav==NULL");
            dbg(9, "sending video failed:toxav==NULL");
        }
    }
   }
}

void invite_cam_as_friend(Tox *tox, uint8_t *tox_id_cam_bin)
{
    if (tox_id_cam_bin == NULL)
    {
        dbg(9, "no Cam ToxID set");
        return;
    }

    int64_t fnum_cam = friend_number_for_cam(tox, tox_id_cam_bin);
    if (fnum_cam == -1)
    {
        dbg(9, "Cam not on friendlist, inviting ...");
        const char *message_str = "invite ...";
        TOX_ERR_FRIEND_ADD error;
        uint32_t friendnum = tox_friend_add(tox, (uint8_t *) tox_id_cam_bin,
                                            (uint8_t *) message_str,
                                            (size_t) strlen(message_str),
                                            &error);

        if (error != 0)
        {
            if (error == TOX_ERR_FRIEND_ADD_ALREADY_SENT)
            {
                dbg(9, "add friend:ERROR:TOX_ERR_FRIEND_ADD_ALREADY_SENT");
            }
            else
            {
                dbg(9, "add friend:ERROR:%d", (int) error);
            }
        }
        else
        {
            dbg(9, "friend request sent.");
        }
    }
    else
    {
        dbg(9, "Cam already a friend");
    }

    update_savedata_file(tox);

}


void invite_tv_as_friend(Tox *tox, uint8_t *tox_id_tv_bin)
{
    if (tox_id_tv_bin == NULL)
    {
        dbg(9, "no TV ToxID set");
        return;
    }

    int64_t fnum_tv = friend_number_for_tv(tox, tox_id_tv_bin);
    if (fnum_tv == -1)
    {
        dbg(9, "TV not on friendlist, inviting ...");
        const char *message_str = "invite ...";
        TOX_ERR_FRIEND_ADD error;
        uint32_t friendnum = tox_friend_add(tox, (uint8_t *) tox_id_tv_bin,
                                            (uint8_t *) message_str,
                                            (size_t) strlen(message_str),
                                            &error);

        if (error != 0)
        {
            if (error == TOX_ERR_FRIEND_ADD_ALREADY_SENT)
            {
                dbg(9, "add friend:ERROR:TOX_ERR_FRIEND_ADD_ALREADY_SENT");
            }
            else
            {
                dbg(9, "add friend:ERROR:%d", (int) error);
            }
        }
        else
        {
            dbg(9, "friend request sent.");
        }
    }
    else
    {
        dbg(9, "TV already a friend");
    }

    update_savedata_file(tox);

}


#if 0
bool file_exists(const char *filename)
{
    return access(filename, 0) != -1;
}
#endif

bool file_exists(const char *path)
{
    struct stat s;
    return stat(path, &s) == 0;
}

off_t file_size(const char *path)
{
    struct stat st;

    if (stat(path, &st) == -1)
    {
        return 0;
    }

    return st.st_size;
}

void delete_cam_file()
{
    unlink(cam_pubkey_filename);
}

void delete_tv_file()
{
    unlink(tv_pubkey_filename);
}

void create_cam_file_if_not_exists()
{
    if (!file_exists(cam_pubkey_filename))
    {
        FILE *fp = fopen(cam_pubkey_filename, "w");

        if (fp == NULL)
        {
            dbg(1, "Warning: failed to create cam_pubkey_filename file");
            return;
        }

        fclose(fp);
        dbg(1, "Warning: creating new cam_pubkey_filename file. Did you lose the old one?");
    }
}

void create_tv_file_if_not_exists()
{
    if (!file_exists(tv_pubkey_filename))
    {
        FILE *fp = fopen(tv_pubkey_filename, "w");

        if (fp == NULL)
        {
            dbg(1, "Warning: failed to create tv_pubkey_filename file");
            return;
        }

        fclose(fp);
        dbg(1, "Warning: creating new tv_pubkey_filename file. Did you lose the old one?");
    }
}

void read_campubkey_from_file(uint8_t **cam_pubkey)
{
    create_cam_file_if_not_exists();
    *cam_pubkey = NULL;

    FILE *fp = fopen(cam_pubkey_filename, "r");
    if (fp == NULL)
    {
        dbg(1, "Warning: failed to read tv_pubkey_filename file");
        return;
    }

    char id[256];
    int len;
    while (fgets(id, sizeof(id), fp))
    {
        len = strlen(id);
        if (len < (TOX_ADDRESS_SIZE * 2))
        {
            continue;
        }

        *cam_pubkey = hex_string_to_bin(id);
        break;
    }

    fclose(fp);
}


void read_tvpubkey_from_file(uint8_t **tv_pubkey)
{
    create_tv_file_if_not_exists();
    *tv_pubkey = NULL;

    FILE *fp = fopen(tv_pubkey_filename, "r");
    if (fp == NULL)
    {
        dbg(1, "Warning: failed to read tv_pubkey_filename file");
        return;
    }

    char id[256];
    int len;
    while (fgets(id, sizeof(id), fp))
    {
        len = strlen(id);
        if (len < (TOX_ADDRESS_SIZE * 2))
        {
            continue;
        }

        *tv_pubkey = hex_string_to_bin(id);
        break;
    }

    fclose(fp);
}

void write_campubkey_to_file(uint8_t *cam_pubkey)
{
    if (cam_pubkey == NULL)
    {
        delete_cam_file();
    }
    else
    {
        create_cam_file_if_not_exists();

        FILE *fp = fopen(cam_pubkey_filename, "wb");
        if (fp == NULL)
        {
            dbg(1, "Warning: failed to read cam_pubkey_filename file");
            return;
        }

        char cam_pubkey_string[TOX_ADDRESS_SIZE * 2 + 1];
        CLEAR(cam_pubkey_string);
        bin_to_hex_string(cam_pubkey, (size_t) TOX_ADDRESS_SIZE, cam_pubkey_string);

        int result = fputs(cam_pubkey_string, fp);
        fclose(fp);
    }
}


void write_tvpubkey_to_file(uint8_t *tv_pubkey)
{
    if (tv_pubkey == NULL)
    {
        delete_tv_file();
    }
    else
    {
        create_tv_file_if_not_exists();

        FILE *fp = fopen(tv_pubkey_filename, "wb");
        if (fp == NULL)
        {
            dbg(1, "Warning: failed to read tv_pubkey_filename file");
            return;
        }

        // dbg(9, "strlen(tv_pubkey)=%d\n", strlen(tv_pubkey));
        char tv_pubkey_string[TOX_ADDRESS_SIZE * 2 + 1];
        CLEAR(tv_pubkey_string);
        bin_to_hex_string(tv_pubkey, (size_t) TOX_ADDRESS_SIZE, tv_pubkey_string);
        // dbg(9, "tv_pubkey_string(0)=%s\n", tv_pubkey_string);

        int result = fputs(tv_pubkey_string, fp);
        fclose(fp);
    }
}


void friend_cleanup(Tox *tox)
{
    uint32_t friend_count = tox_self_get_friend_list_size(tox);

    if (friend_count == 0)
    {
        return;
    }

    uint32_t friends[friend_count];
    tox_self_get_friend_list(tox, friends);

    uint64_t curr_time = time(NULL);
    for (uint32_t i = 0; i < friend_count; i++)
    {
        TOX_ERR_FRIEND_GET_LAST_ONLINE err;
        uint32_t friend = friends[i];
        uint64_t last_online = tox_friend_get_last_online(tox, friend, &err);

        if (err != TOX_ERR_FRIEND_GET_LAST_ONLINE_OK)
        {
            dbg(9, "couldn't obtain 'last online', this should never happen");
            continue;
        }

        if (curr_time - last_online > 2629743)
        {
            dbg(9, "removing friend %d", friend);
            tox_friend_delete(tox, friend, NULL);
        }
    }
}


uint32_t get_online_friend_count(Tox *tox)
{
    uint32_t online_friend_count = 0u;
    uint32_t friend_count = tox_self_get_friend_list_size(tox);
    uint32_t friends[friend_count];

    tox_self_get_friend_list(tox, friends);

    for (uint32_t i = 0; i < friend_count; i++)
    {
        if (tox_friend_get_connection_status(tox, friends[i], NULL) != TOX_CONNECTION_NONE)
        {
            online_friend_count++;
        }
    }

    return online_friend_count;
}

void cb___self_connection_status(Tox *tox, TOX_CONNECTION connection_status, void *userData)
{
    switch (connection_status)
    {
        case TOX_CONNECTION_NONE:
            dbg(2, "Offline");
            my_connection_status = TOX_CONNECTION_NONE;
            my_last_offline_timestamp = get_unix_time();
            break;
        case TOX_CONNECTION_TCP:
            dbg(2, "Online, using TCP");
            my_connection_status = TOX_CONNECTION_TCP;
            my_last_online_timestamp = get_unix_time();
            break;
        case TOX_CONNECTION_UDP:
            dbg(2, "Online, using UDP");
            my_connection_status = TOX_CONNECTION_UDP;
            my_last_online_timestamp = get_unix_time();
            break;
    }
}

void cb___friend_request(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length,
                         void *user_data)
{
    TOX_ERR_FRIEND_ADD err;
    tox_friend_add_norequest(tox, public_key, &err);

    if (err != TOX_ERR_FRIEND_ADD_OK)
    {
        dbg(9, "Could not add friend, error: %d", err);
    }
    else
    {
        dbg(9, "Added to our friend list");
    }

    update_savedata_file(tox);
}

void send_help_to_friend(Tox *tox, uint32_t friend_number)
{
    send_text_message_to_friend(tox, friend_number,
                                "=========================\nBildGruppenArbeiter version:%s\n=========================",
                                global_version_string);

    send_text_message_to_friend(tox, friend_number, " .info          --> show status");
    send_text_message_to_friend(tox, friend_number, " .settv <ToxID> --> Set <ToxID> as TV");
    send_text_message_to_friend(tox, friend_number, " .deltv         --> Delete TV");
    send_text_message_to_friend(tox, friend_number, " .setcam <ToxID>--> Set <ToxID> as Cam");
    send_text_message_to_friend(tox, friend_number, " .delcam        --> Delete Cam");
    send_text_message_to_friend(tox, friend_number,
                                " t              --> make me the current speaker");
    send_text_message_to_friend(tox, friend_number, " .locksp        --> Lock current Speaker");
    send_text_message_to_friend(tox, friend_number, " .unlocksp      --> Unlock Speaker");
    send_text_message_to_friend(tox, friend_number, " .vbr <number>  --> Set <number> as video bitrate");
    send_text_message_to_friend(tox, friend_number, " .kac           --> Kill all calls");
    send_text_message_to_friend(tox, friend_number, " .dmc           --> Disconnect my calls");
}

void cmd_stats(Tox *tox, uint32_t friend_number)
{
    switch (my_connection_status)
    {
        case TOX_CONNECTION_NONE:
            send_text_message_to_friend(tox, friend_number, "BildGruppenArbeiter status:offline");
            break;
        case TOX_CONNECTION_TCP:
            send_text_message_to_friend(tox, friend_number,
                                        "BildGruppenArbeiter status:Online, using TCP");
            break;
        case TOX_CONNECTION_UDP:
            send_text_message_to_friend(tox, friend_number,
                                        "BildGruppenArbeiter status:Online, using UDP");
            break;
        default:
            send_text_message_to_friend(tox, friend_number, "BildGruppenArbeiter status:*unknown*");
            break;
    }

    // ----- uptime -----
    char time_str[200];
    uint64_t cur_time = time(NULL);
    get_elapsed_time_str(time_str, sizeof(time_str), cur_time - global_start_time);
    send_text_message_to_friend(tox, friend_number, "Uptime: %s", time_str);
    // ----- uptime -----

    // ----- friends -----
    send_text_message_to_friend(tox, friend_number, "Friends: %zu (%d online)",
                                tox_self_get_friend_list_size(tox), get_online_friend_count(tox));
    // ----- friends -----

    // ----- calls -----
    // send_text_message_to_friend(tox, friend_number, "Calls: %d active calls",
    //                            (int)1);
    // ----- calls -----

    // ----- Active caller -----
    send_text_message_to_friend(tox, friend_number, "Active Caller: %d [friendnum] global_video_active=%d",
                                (int)friend_to_take_av_from, (int)global_video_active);
    // ----- Active caller -----

    // ----- TV -----
    send_text_message_to_friend(tox, friend_number, "TV: active=%d pubkey_bin=%d  %d [friendnum]",
                                (int)global_tv_video_active, (int)global_tv_toxid, (int)global_tv_friendnum);
    // ----- TV -----

    // ----- Cam -----
    send_text_message_to_friend(tox, friend_number, "Cam: active=%d pubkey_bin=%d",
                                (int)global_cam_video_active, (int)global_cam_toxid);
    // ----- Cam -----

    // ----- bit rates -----
    send_text_message_to_friend(tox, friend_number, "Bitrates (kb/s): audio=%d video=%d",
                                (int)audio_bitrate, (int)video_bitrate);
    // ----- bit rates -----


    // ----- ToxID -----
    char tox_id_hex[TOX_ADDRESS_SIZE * 2 + 1];
    get_my_toxid(tox, tox_id_hex);
    send_text_message_to_friend(tox, friend_number, "tox:%s", tox_id_hex);
    // ----- ToxID -----

}

void
cb___friend_message(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message,
                    size_t length, void *user_data)
{
    char dest_msg[length + 1];
    dest_msg[length] = '\0';
    memcpy(dest_msg, message, length);

	dbg(9, "fnum=%d incoming message=%s", (int) friend_number, dest_msg);

    if (strncmp((char *) dest_msg, ".info", strlen((char *) ".info")) == 0)
    {
        cmd_stats(tox, friend_number);
    }
    else if (!strncmp(".setcam ", dest_msg, (size_t) 7))
    {
        if (strlen(dest_msg) == ((TOX_ADDRESS_SIZE * 2) + 8))
        {
            char *cam_hex_pubkey_string = (dest_msg + 8);
            uint8_t *cam_pubkey = hex_string_to_bin(cam_hex_pubkey_string);
            if (cam_pubkey)
            {

                if (global_cam_video_active == 1)
                {
                    av_local_disconnect(mytox_av, global_cam_friendnum);
                    global_cam_video_active = 0;
                }

                if (global_cam_toxid)
                {
                    free(global_cam_toxid);
                    global_cam_toxid = NULL;
                }
                write_campubkey_to_file(cam_pubkey);
                global_cam_toxid = cam_pubkey;

                // TODO: remove old Cam as friend (but only if Cam ToxID has really changed)
                global_cam_friendnum = friend_number_for_cam(tox, global_cam_toxid);
                if (global_cam_friendnum == -1)
                {
                    invite_cam_as_friend(tox, global_cam_toxid);
                    global_cam_friendnum = friend_number_for_cam(tox, global_cam_toxid);
                }
                else
                {
                    start_av_call_to_cam(tox, global_cam_friendnum);
                }
            }
        }
    }
    else if (!strncmp(".settv ", dest_msg, (size_t) 6))
    {
        if (strlen(dest_msg) == ((TOX_ADDRESS_SIZE * 2) + 7))
        {
            char *tv_hex_pubkey_string = (dest_msg + 7);
            uint8_t *tv_pubkey = hex_string_to_bin(tv_hex_pubkey_string);
            if (tv_pubkey)
            {

                if (global_tv_video_active == 1)
                {
                    av_local_disconnect(mytox_av, global_tv_friendnum);
                    global_tv_video_active = 0;
                }

                if (global_tv_toxid)
                {
                    free(global_tv_toxid);
                    global_tv_toxid = NULL;
                }
                write_tvpubkey_to_file(tv_pubkey);
                global_tv_toxid = tv_pubkey;

                // TODO: remove old TV as friend (but only if TV ToxID has really changed)
                global_tv_friendnum = friend_number_for_tv(tox, global_tv_toxid);
                dbg(9, "[1]global_tv_friendnum %d", (int)global_tv_friendnum);
                if (global_tv_friendnum == -1)
                {
                    invite_tv_as_friend(tox, global_tv_toxid);
                    global_tv_friendnum = friend_number_for_tv(tox, global_tv_toxid);
                    dbg(9, "[2]global_tv_friendnum %d", (int)global_tv_friendnum);
                }
                else
                {
                    start_av_call_to_tv(tox, global_tv_friendnum);
                }
            }
        }
    }
    else if (!strncmp(".vbr ", dest_msg, (size_t) 5))
    {
        if (strlen(dest_msg) > 7) // require 3 digits
        {
            int vbr_new = get_number_in_string(dest_msg, (int)video_bitrate);
            if ((vbr_new >= DEFAULT_GLOBAL_MIN_VID_BITRATE) && (vbr_new <= DEFAULT_GLOBAL_MAX_VID_BITRATE))
            {
                video_bitrate = (int32_t)vbr_new;
                toxav_bit_rate_set(mytox_av, friend_number, audio_bitrate, video_bitrate, NULL);
            }
        }
    }
    else if (strncmp((char *) dest_msg, ".delcam", strlen((char *) ".delcam")) == 0)
    {
        if (global_cam_toxid)
        {

            if (friend_to_take_av_from == global_cam_friendnum)
            {
                friend_to_take_av_from = -1;
            }

            if (global_cam_video_active == 1)
            {
                av_local_disconnect(mytox_av, global_cam_friendnum);
                global_cam_video_active = 0;
            }

            free(global_cam_toxid);
            global_cam_toxid = NULL;
            dbg(9, "global_cam_toxid(4)=NULL");
            global_cam_friendnum = -1;
        }
        write_campubkey_to_file(NULL);
    }
    else if (strncmp((char *) dest_msg, ".deltv", strlen((char *) ".deltv")) == 0)
    {
        if (global_tv_toxid)
        {
            if (global_tv_video_active == 1)
            {
                av_local_disconnect(mytox_av, global_tv_friendnum);
                global_tv_video_active = 0;
            }

            free(global_tv_toxid);
            global_tv_toxid = NULL;
            dbg(9, "global_tv_toxid(4)=NULL");
            global_tv_friendnum = -1;
            dbg(9, "[3]global_tv_friendnum %d", (int)global_tv_friendnum);
        }
        write_tvpubkey_to_file(NULL);
    }
    else if (strncmp((char *) dest_msg, "t", strlen((char *) "t")) == 0)
    {
        friend_to_take_av_from = friend_number;
        dbg(9, "friend_to_take_av_from = %d [2]", (int) friend_to_take_av_from);
    }
    else if (strncmp((char *) dest_msg, "c", strlen((char *) "c")) == 0)
    {
        friend_to_take_av_from = global_cam_friendnum;
        global_video_active = 1;
        dbg(9, "friend_to_take_av_from (CAM) = %d [2]", (int) friend_to_take_av_from);
    }
    else if (strncmp((char *) dest_msg, ".kac", strlen((char *) ".kac")) == 0)
    {
        disconnect_all_calls(tox);

        friend_to_take_av_from = -1;
        global_video_active = 0;

        if (global_tv_video_active == 1)
        {
            // ** // av_local_disconnect(mytox_av, global_tv_friendnum);
            global_tv_video_active = 0;
        }
    }
    else if (strncmp((char *) dest_msg, ".dmc", strlen((char *) ".dmc")) == 0)
    {
        av_local_disconnect(mytox_av, friend_number);

        if (friend_number == friend_to_take_av_from)
        {
            friend_to_take_av_from = -1;
            global_video_active = 0;

            if (global_tv_video_active == 1)
            {
                // ** // av_local_disconnect(mytox_av, global_tv_friendnum);
                global_tv_video_active = 0;
            }
        }
    }
    else if (strncmp((char *) dest_msg, "help", strlen((char *) "help")) == 0)
    {
        send_help_to_friend(tox, friend_number);
    }
}

void cb___file_recv(Tox *tox, uint32_t friend_number, uint32_t file_number, uint32_t kind,
                    uint64_t file_size, const uint8_t *filename, size_t filename_length,
                    void *user_data)
{
    if (kind == TOX_FILE_KIND_AVATAR)
    {
        return;
    }

    tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_CANCEL, NULL);

    const char *msg = "Sorry, I don't support file transfers.";
    tox_friend_send_message(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL, (uint8_t *) msg,
                            strlen(msg), NULL);
}

void cb___call(ToxAV *toxAV, uint32_t friend_number, bool audio_enabled, bool video_enabled,
               void *user_data)
{
    TOXAV_ERR_ANSWER err;
    toxav_answer(toxAV, friend_number, audio_bitrate, video_bitrate, &err);

    if (err != TOXAV_ERR_ANSWER_OK)
    {
        dbg(9, "cb___call:Could not answer call, friend: %d, error: %d", friend_number, err);
    }
    else
    {
        dbg(9, "cb___call:friend_to_take_av_from=%d", (int) friend_to_take_av_from);
        dbg(9, "cb___call:friend_number=%d", (int) friend_number);
        if (friend_to_take_av_from == friend_number)
        {
            global_video_active = 1;
            dbg(9, "cb___call:global_video_active = 1 [8]");
        }
        else if (friend_to_take_av_from == -1)
        {
            friend_to_take_av_from = friend_number;
            global_video_active = 1;
            dbg(9, "cb___call:friend_to_take_av_from = %d [7]", (int) friend_to_take_av_from);
            dbg(9, "cb___call:global_video_active = 1 [7]");
        }
    }
}


static void cb___bit_rate_status(ToxAV *av, uint32_t friend_number,
                                       uint32_t audio_bit_rate, uint32_t video_bit_rate,
                                       void *user_data)
{

	dbg(0, "cb___bit_rate_status:001 video_bit_rate=%d friend_number=%d\n", (int)video_bit_rate, (int)friend_number);
	dbg(0, "cb___bit_rate_status:001 audio_bit_rate=%d friend_number=%d\n", (int)audio_bit_rate, (int)friend_number);

	TOXAV_ERR_BIT_RATE_SET error = 0;

	uint32_t video_bit_rate_ = video_bit_rate;

	if (video_bit_rate < DEFAULT_GLOBAL_MIN_VID_BITRATE)
	{
		video_bit_rate_ = DEFAULT_GLOBAL_MIN_VID_BITRATE;
	}

	// ignore bitrate callback suggested values
	// toxav_bit_rate_set(av, friend_number, audio_bit_rate, video_bit_rate_, &error);

	if (error != 0)
	{
		dbg(0, "ToxAV:Setting new Video bitrate has failed with error #%u\n", error);
	}
	else
	{
		// HINT: don't touch global video bitrate --------
		// video_bitrate = video_bit_rate_;
		// HINT: don't touch global video bitrate --------
	}

    dbg(2, "suggested bit rates: audio: %d video: %d friend_number=%d\n", audio_bit_rate, video_bit_rate, (int)friend_number);
    dbg(2, "default   bit rates: audio: %d video: %d friend_number=%d\n", audio_bitrate, video_bitrate, (int)friend_number);
}


void cb___call_state(ToxAV *toxAV, uint32_t friend_number, uint32_t state, void *user_data)
{
    if (state & TOXAV_FRIEND_CALL_STATE_FINISHED)
    {
        dbg(9, "Call with friend %d finished", friend_number);
        if (friend_number == global_tv_friendnum)
        {
            global_tv_video_active = 0;
        }
        else if (friend_number == global_cam_friendnum)
        {
            global_cam_video_active = 0;
        }

        if (friend_to_take_av_from == friend_number)
        {
            friend_to_take_av_from = -1;
            global_video_active = 0;
            dbg(9, "friend_to_take_av_from = -1 [9]");
            dbg(9, "global_video_active = 0 [9]");
        }

        return;
    }
    else if (state & TOXAV_FRIEND_CALL_STATE_ERROR)
    {
        dbg(9, "Call with friend %d errored", friend_number);
        if (friend_number == global_tv_friendnum)
        {
            // *crash* // av_local_disconnect(mytox_av, friend_number);
            global_tv_video_active = 0;
        }
        else if (friend_number == global_cam_friendnum)
        {
            // *crash* // av_local_disconnect(mytox_av, friend_number);
            global_cam_video_active = 0;
        }
        else
        {
            if (friend_to_take_av_from == friend_number)
            {
                friend_to_take_av_from = -1;
                global_video_active = 0;
                dbg(9, "friend_to_take_av_from = -1 [7]");
                dbg(9, "global_video_active = 0 [7]");
            }
            // *crash* // av_local_disconnect(mytox_av, friend_number);
        }

        return;
    }


    if (
         (state & TOXAV_FRIEND_CALL_STATE_ACCEPTING_V) ||
         (state & TOXAV_FRIEND_CALL_STATE_ACCEPTING_A) ||
         (state & TOXAV_FRIEND_CALL_STATE_SENDING_V) ||
         (state & TOXAV_FRIEND_CALL_STATE_SENDING_A)
       )
    {
        dbg(9, "friend %d accepted call", (int) friend_number);
        dbg(9, "global_tv_friendnum=%d", (int) global_tv_friendnum);

        if (friend_number == global_cam_friendnum)
        {
            global_cam_video_active = 1;
            dbg(9, "global_cam_video_active=1");
        }

        if (friend_number == global_tv_friendnum)
        {
            global_tv_video_active = 1;
            dbg(9, "global_tv_video_active=1");
        }
        else
        {
            dbg(9, "friend_to_take_av_from=%d", (int) friend_to_take_av_from);
            dbg(9, "friend_number=%d", (int) friend_number);
            if (friend_to_take_av_from == -1)
            {
                friend_to_take_av_from = friend_number;
                global_video_active = 1;
                dbg(9, "friend_to_take_av_from = %d [3]", (int) friend_to_take_av_from);
                dbg(9, "global_video_active = 1 [3]");
            }
            else if (friend_to_take_av_from == friend_number)
            {
                global_video_active = 1;
                dbg(9, "global_video_active = 1 [6]");
            }
        }
    }

    bool send_audio = (state & TOXAV_FRIEND_CALL_STATE_SENDING_A) &&
                      (state & TOXAV_FRIEND_CALL_STATE_ACCEPTING_A);
    bool send_video = state & TOXAV_FRIEND_CALL_STATE_SENDING_V &&
                      (state & TOXAV_FRIEND_CALL_STATE_ACCEPTING_V);
    // ** deactviated ** // toxav_bit_rate_set(toxAV, friend_number, send_audio ? audio_bitrate : 0, send_video ? video_bitrate : 0, NULL);

    dbg(9, "Call state for friend %d changed to %d: audio: %d, video: %d", friend_number, state, send_audio, send_video);
}

void cb___audio_receive_frame(ToxAV *toxAV, uint32_t friend_number, const int16_t *pcm,
                              size_t sample_count, uint8_t channels, uint32_t sampling_rate,
                              void *user_data)
{
    if (global_video_active == 1)
    {
        if (friend_to_take_av_from != -1)
        {
            if (friend_to_take_av_from == friend_number)
            {

                TOXAV_ERR_SEND_FRAME err;

                // send to TV ---------------------------
                if (global_tv_friendnum != -1)
                {
                    if (global_tv_video_active == 1)
                    {
                        toxav_audio_send_frame(toxAV,
                                               global_tv_friendnum,
                                               pcm,
                                               sample_count,
                                               channels,
                                               sampling_rate,
                                               &err);
                        if (err != TOXAV_ERR_SEND_FRAME_OK)
                        {
                            // dbg(9, "Could not send audio frame to TV: %d, error: %d",
                            //    friend_number,
                            //    err);
                            global_tv_video_active = 0;
                        }
                    }
                }
                // send to TV ---------------------------


                // TODO: send to all connected friends ---------------------------
                size_t i = 0;
                size_t size = tox_self_get_friend_list_size(mytox_global);

                if (size > 0)
                {
                    uint32_t list[size];
                    tox_self_get_friend_list(mytox_global, list);

                    for (i = 0; i < size; i++)
                    {
                        if (list[i] != global_cam_friendnum)
                        {
                            toxav_audio_send_frame(toxAV,
                                                   list[i],
                                                   pcm,
                                                   sample_count,
                                                   channels,
                                                   sampling_rate,
                                                   &err);
                            if (err != TOXAV_ERR_SEND_FRAME_OK)
                            {
                                // dbg(9, "Could not send audio frame to friend: %d, error: %d",
                                //    friend_number,
                                //    err);
                            }
                        }
                    }
                }
                // TODO: send to all connected friends ---------------------------
            }
        }
    }
}

void cb___video_receive_frame(ToxAV *toxAV, uint32_t friend_number, uint16_t width, uint16_t height,
                              const uint8_t *y, const uint8_t *u, const uint8_t *v, int32_t ystride,
                              int32_t ustride, int32_t vstride, void *user_data)
{
    ystride = abs(ystride);
    ustride = abs(ustride);
    vstride = abs(vstride);

    if (ystride < width || ustride < width / 2 || vstride < width / 2)
    {
        dbg(9, "strange video frame size/stride error");
        return;
    }

    uint8_t *y_dest = (uint8_t *) malloc(width * height);
    uint8_t *u_dest = (uint8_t *) malloc(width * height / 2);
    uint8_t *v_dest = (uint8_t *) malloc(width * height / 2);

    for (size_t h = 0; h < height; h++)
    {
        memcpy(&y_dest[h * width], &y[h * ystride], width);
    }

    for (size_t h = 0; h < height / 2; h++)
    {
        memcpy(&u_dest[h * width / 2], &u[h * ustride], width / 2);
        memcpy(&v_dest[h * width / 2], &v[h * vstride], width / 2);
    }

    // dbg(9, "cb___video_receive_frame:global_video_active=%d", (int) global_video_active);
    if (global_video_active == 1)
    {
        // dbg(9, "cb___video_receive_frame:friend_to_take_av_from=%d", (int) friend_to_take_av_from);
        if (friend_to_take_av_from != -1)
        {
            // dbg(9, "cb___video_receive_frame:friend_number=%d", (int) friend_number);
            if (friend_to_take_av_from == friend_number)
            {
                TOXAV_ERR_SEND_FRAME err;

                // send to TV ---------------------------
                if (global_tv_friendnum != -1)
                {
                    // dbg(9, "cb___video_receive_frame:global_tv_friendnum=%d",
                    //   (int) global_tv_friendnum);

                    if (global_tv_video_active == 1)
                    {
                        //dbg(9, "cb___video_receive_frame:global_tv_video_active=%d",
                        //   (int) global_tv_video_active);

                        toxav_video_send_frame(toxAV,
                                               global_tv_friendnum,
                                               width,
                                               height,
                                               y_dest,
                                               u_dest,
                                               v_dest,
                                               &err);
                        if (err != TOXAV_ERR_SEND_FRAME_OK)
                        {
                            // dbg(9, "Could not send video frame to TV: %d, error: %d", (int)global_tv_friendnum,
                            //   (int)err);
                            global_tv_video_active = 0;
                        }
                    }
                }
                // send to TV ---------------------------

                // TODO: send to all connected friends ---------------------------
                size_t i = 0;
                size_t size = tox_self_get_friend_list_size(mytox_global);

                if (size > 0)
                {
                    uint32_t list[size];
                    tox_self_get_friend_list(mytox_global, list);
                    // dbg(9, "cb___video_receive_frame:friend_list_size=%d", (int)size);

                    for (i = 0; i < size; i++)
                    {
                        // dbg(9, "list[i]=%d", (int)list[i]);

                        if (list[i] != global_cam_friendnum)
                        {
                            toxav_video_send_frame(toxAV,
                                                   list[i],
                                                   width,
                                                   height,
                                                   y_dest,
                                                   u_dest,
                                                   v_dest,
                                                   &err);
                            if (err != TOXAV_ERR_SEND_FRAME_OK)
                            {
                                // dbg(9, "Could not send video frame to friend: %d, error: %d",
                                //   (int)list[i],
                                //   (int)err);
                            }
                        }
                    }
                }
                // TODO: send to all connected friends ---------------------------
            }
        }
    }

    free(y_dest);
    free(u_dest);
    free(v_dest);
}


void
tox_log_cb__custom(Tox *tox, TOX_LOG_LEVEL level, const char *file, uint32_t line, const char *func,
                   const char *message, void *user_data)
{
    dbg(9, "%d:%s:%d:%s:%s", (int) level, file, (int) line, func, message);
}


Tox *create_tox()
{
    Tox *tox;
    struct Tox_Options options;

/*
	TOX_ERR_OPTIONS_NEW err_options;
    struct Tox_Options options = tox_options_new(&err_options);
	if (err_options != TOX_ERR_OPTIONS_NEW_OK)
	{
		dbg(0, "tox_options_new error\n");
	}
*/

    tox_options_default(&options);

    // ----------------------------------------------
    // uint16_t tcp_port = 33445; // act as TCP relay
    uint16_t tcp_port = 0; // DON'T act as TCP relay
    // ----------------------------------------------

    // ----------------------------------------------
    if (switch_tcponly == 0)
    {
        options.udp_enabled = true; // UDP mode
        dbg(0, "setting UDP mode");
    }
    else
    {
        options.udp_enabled = false; // TCP mode
        dbg(0, "setting TCP mode");
    }
    // ----------------------------------------------

    options.ipv6_enabled = false;
    options.local_discovery_enabled = true;
    options.hole_punching_enabled = true;
    options.tcp_port = tcp_port;

    if (use_tor == 1)
    {
        dbg(0, "setting Tor Relay mode");
        options.udp_enabled = false; // TCP mode
        dbg(0, "setting TCP mode");
        const char *proxy_host = "127.0.0.1";
        dbg(0, "setting proxy_host %s", proxy_host);
        uint16_t proxy_port = PROXY_PORT_TOR_DEFAULT;
        dbg(0, "setting proxy_port %d", (int) proxy_port);
        options.proxy_type = TOX_PROXY_TYPE_SOCKS5;
        options.proxy_host = proxy_host;
        options.proxy_port = proxy_port;
    }
    else
    {
        options.proxy_type = TOX_PROXY_TYPE_NONE;
    }

    // ------------------------------------------------------------
    // set our own handler for c-toxcore logging messages!!
    options.log_callback = tox_log_cb__custom;
    // ------------------------------------------------------------


    FILE *f = fopen(savedata_filename, "rb");
    if (f)
    {
        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);

        uint8_t *savedata = malloc(fsize);

        size_t dummy = fread(savedata, fsize, 1, f);
        if (dummy < 1)
        {
            dbg(0, "reading savedata failed");
        }
        fclose(f);

        options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
        options.savedata_data = savedata;
        options.savedata_length = fsize;

        tox = tox_new(&options, NULL);

        free((void *) savedata);
    }
    else
    {
        tox = tox_new(&options, NULL);
    }

    bool local_discovery_enabled = tox_options_get_local_discovery_enabled(&options);
    dbg(9, "local discovery enabled = %d", (int) local_discovery_enabled);

    return tox;
}

void update_savedata_file(const Tox *tox)
{
    size_t size = tox_get_savedata_size(tox);
    char *savedata = malloc(size);
    tox_get_savedata(tox, (uint8_t *) savedata);

    FILE *f = fopen(savedata_tmp_filename, "wb");
    fwrite(savedata, size, 1, f);
    fclose(f);

    rename(savedata_tmp_filename, savedata_filename);

    free(savedata);
}


void shuffle(int *array, size_t n)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int usec = tv.tv_usec;
    srand48(usec);

    if (n > 1)
    {
        size_t i;
        for (i = n - 1; i > 0; i--)
        {
            size_t j = (unsigned int) (drand48() * (i + 1));
            int t = array[j];
            array[j] = array[i];
            array[i] = t;
        }
    }
}


void bootstap_nodes(Tox *tox, DHT_node nodes[], int number_of_nodes, int add_as_tcp_relay)
{

    bool res = 0;
    size_t i = 0;
    int random_order_nodenums[number_of_nodes];
    for (size_t j = 0; (int) j < (int) number_of_nodes; j++)
    {
        random_order_nodenums[j] = (int) j;
    }

    shuffle(random_order_nodenums, number_of_nodes);

    for (size_t j = 0; (int) j < (int) number_of_nodes; j++)
    {
        i = (size_t) random_order_nodenums[j];

        res = sodium_hex2bin(nodes[i].key_bin, sizeof(nodes[i].key_bin),
                             nodes[i].key_hex, sizeof(nodes[i].key_hex) - 1, NULL, NULL, NULL);
        // dbg(9, "sodium_hex2bin:res=%d\n", res);

        TOX_ERR_BOOTSTRAP error;
        res = tox_bootstrap(tox, nodes[i].ip, nodes[i].port, nodes[i].key_bin, &error);
        if (res != true)
        {
            if (error == TOX_ERR_BOOTSTRAP_OK)
            {
                // dbg(9, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_OK\n", nodes[i].ip, nodes[i].port);
            }
            else if (error == TOX_ERR_BOOTSTRAP_NULL)
            {
                // dbg(9, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_NULL\n", nodes[i].ip, nodes[i].port);
            }
            else if (error == TOX_ERR_BOOTSTRAP_BAD_HOST)
            {
                // dbg(9, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_BAD_HOST\n", nodes[i].ip, nodes[i].port);
            }
            else if (error == TOX_ERR_BOOTSTRAP_BAD_PORT)
            {
                // dbg(9, "bootstrap:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_BAD_PORT\n", nodes[i].ip, nodes[i].port);
            }
        }
        else
        {
            // dbg(9, "bootstrap:%s %d [TRUE]res=%d\n", nodes[i].ip, nodes[i].port, res);
        }


        if ((add_as_tcp_relay == 1) && (switch_tcponly == 1))
        {
            res = tox_add_tcp_relay(tox, nodes[i].ip, nodes[i].port, nodes[i].key_bin,
                                    &error); // use also as TCP relay
            if (res != true)
            {
                if (error == TOX_ERR_BOOTSTRAP_OK)
                {
                    // dbg(9, "add_tcp_relay:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_OK\n", nodes[i].ip, nodes[i].port);
                }
                else if (error == TOX_ERR_BOOTSTRAP_NULL)
                {
                    // dbg(9, "add_tcp_relay:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_NULL\n", nodes[i].ip, nodes[i].port);
                }
                else if (error == TOX_ERR_BOOTSTRAP_BAD_HOST)
                {
                    // dbg(9, "add_tcp_relay:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_BAD_HOST\n", nodes[i].ip, nodes[i].port);
                }
                else if (error == TOX_ERR_BOOTSTRAP_BAD_PORT)
                {
                    // dbg(9, "add_tcp_relay:%s %d [FALSE]res=TOX_ERR_BOOTSTRAP_BAD_PORT\n", nodes[i].ip, nodes[i].port);
                }
            }
            else
            {
                // dbg(9, "add_tcp_relay:%s %d [TRUE]res=%d\n", nodes[i].ip, nodes[i].port, res);
            }
        }
        else
        {
            dbg(2, "Not adding any TCP relays");
        }
    }
}


void bootstrap(Tox *tox)
{

    // these nodes seem to be faster!!
    DHT_node nodes1[] =
            {
                    {"178.62.250.138",  33445, "788236D34978D1D5BD822F0A5BEBD2C53C64CC31CD3149350EE27D4D9A2F9B6B", {0}},
                    {"51.15.37.145",    33445, "6FC41E2BD381D37E9748FC0E0328CE086AF9598BECC8FEB7DDF2E440475F300E", {0}},
                    {"130.133.110.14",  33445, "461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F", {0}},
                    {"23.226.230.47",   33445, "A09162D68618E742FFBCA1C2C70385E6679604B2D80EA6E84AD0996A1AC8A074", {0}},
                    {"163.172.136.118", 33445, "2C289F9F37C20D09DA83565588BF496FAB3764853FA38141817A72E3F18ACA0B", {0}},
                    {"217.182.143.254", 443,   "7AED21F94D82B05774F697B209628CD5A9AD17E0C073D9329076A4C28ED28147", {0}},
                    {"185.14.30.213",   443,   "2555763C8C460495B14157D234DD56B86300A2395554BCAE4621AC345B8C1B1B", {0}},
                    {"136.243.141.187", 443,   "6EE1FADE9F55CC7938234CC07C864081FC606D8FE7B751EDA217F268F1078A39", {0}},
                    {"128.199.199.197", 33445, "B05C8869DBB4EDDD308F43C1A974A20A725A36EACCA123862FDE9945BF9D3E09", {0}},
                    {"198.46.138.44",   33445, "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67", {0}}
            };


    // more nodes here, but maybe some issues
    DHT_node nodes2[] =
            {
                    {"178.62.250.138",           33445, "788236D34978D1D5BD822F0A5BEBD2C53C64CC31CD3149350EE27D4D9A2F9B6B", {0}},
                    {"136.243.141.187",          443,   "6EE1FADE9F55CC7938234CC07C864081FC606D8FE7B751EDA217F268F1078A39", {0}},
                    {"185.14.30.213",            443,   "2555763C8C460495B14157D234DD56B86300A2395554BCAE4621AC345B8C1B1B", {0}},
                    {"198.46.138.44",            33445, "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67", {0}},
                    {"51.15.37.145",             33445, "6FC41E2BD381D37E9748FC0E0328CE086AF9598BECC8FEB7DDF2E440475F300E", {0}},
                    {"130.133.110.14",           33445, "461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F", {0}},
                    {"205.185.116.116",          33445, "A179B09749AC826FF01F37A9613F6B57118AE014D4196A0E1105A98F93A54702", {0}},
                    {"198.98.51.198",            33445, "1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931EB8FD3AB8E7BF7DAF6F", {0}},
                    {"108.61.165.198",           33445, "8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832", {0}},
                    {"194.249.212.109",          33445, "3CEE1F054081E7A011234883BC4FC39F661A55B73637A5AC293DDF1251D9432B", {0}},
                    {"185.25.116.107",           33445, "DA4E4ED4B697F2E9B000EEFE3A34B554ACD3F45F5C96EAEA2516DD7FF9AF7B43", {0}},
                    {"5.189.176.217",            5190,  "2B2137E094F743AC8BD44652C55F41DFACC502F125E99E4FE24D40537489E32F", {0}},
                    {"217.182.143.254",          2306,  "7AED21F94D82B05774F697B209628CD5A9AD17E0C073D9329076A4C28ED28147", {0}},
                    {"104.223.122.15",           33445, "0FB96EEBFB1650DDB52E70CF773DDFCABE25A95CC3BB50FC251082E4B63EF82A", {0}},
                    {"tox.verdict.gg",           33445, "1C5293AEF2114717547B39DA8EA6F1E331E5E358B35F9B6B5F19317911C5F976", {0}},
                    {"d4rk4.ru",                 1813,  "53737F6D47FA6BD2808F378E339AF45BF86F39B64E79D6D491C53A1D522E7039", {0}},
                    {"104.233.104.126",          33445, "EDEE8F2E839A57820DE3DA4156D88350E53D4161447068A3457EE8F59F362414", {0}},
                    {"51.254.84.212",            33445, "AEC204B9A4501412D5F0BB67D9C81B5DB3EE6ADA64122D32A3E9B093D544327D", {0}},
                    {"88.99.133.52",             33445, "2D320F971EF2CA18004416C2AAE7BA52BF7949DB34EA8E2E21AF67BD367BE211", {0}},
                    {"185.58.206.164",           33445, "24156472041E5F220D1FA11D9DF32F7AD697D59845701CDD7BE7D1785EB9DB39", {0}},
                    {"92.54.84.70",              33445, "5625A62618CB4FCA70E147A71B29695F38CC65FF0CBD68AD46254585BE564802", {0}},
                    {"195.93.190.6",             33445, "FB4CE0DDEFEED45F26917053E5D24BDDA0FA0A3D83A672A9DA2375928B37023D", {0}},
                    {"tox.uplinklabs.net",       33445, "1A56EA3EDF5DF4C0AEABBF3C2E4E603890F87E983CAC8A0D532A335F2C6E3E1F", {0}},
                    {"toxnode.nek0.net",         33445, "20965721D32CE50C3E837DD75B33908B33037E6225110BFF209277AEAF3F9639", {0}},
                    {"95.215.44.78",             33445, "672DBE27B4ADB9D5FB105A6BB648B2F8FDB89B3323486A7A21968316E012023C", {0}},
                    {"163.172.136.118",          33445, "2C289F9F37C20D09DA83565588BF496FAB3764853FA38141817A72E3F18ACA0B", {0}},
                    {"sorunome.de",              33445, "02807CF4F8BB8FB390CC3794BDF1E8449E9A8392C5D3F2200019DA9F1E812E46", {0}},
                    {"37.97.185.116",            33445, "E59A0E71ADA20D35BD1B0957059D7EF7E7792B3D680AE25C6F4DBBA09114D165", {0}},
                    {"193.124.186.205",          5228,  "9906D65F2A4751068A59D30505C5FC8AE1A95E0843AE9372EAFA3BAB6AC16C2C", {0}},
                    {"80.87.193.193",            33445, "B38255EE4B054924F6D79A5E6E5889EC94B6ADF6FE9906F97A3D01E3D083223A", {0}},
                    {"initramfs.io",             33445, "3F0A45A268367C1BEA652F258C85F4A66DA76BCAA667A49E770BCC4917AB6A25", {0}},
                    {"hibiki.eve.moe",           33445, "D3EB45181B343C2C222A5BCF72B760638E15ED87904625AAD351C594EEFAE03E", {0}},
                    {"tox.deadteam.org",         33445, "C7D284129E83877D63591F14B3F658D77FF9BA9BA7293AEB2BDFBFE1A803AF47", {0}},
                    {"46.229.52.198",            33445, "813C8F4187833EF0655B10F7752141A352248462A567529A38B6BBF73E979307", {0}},
                    {"node.tox.ngc.network",     33445, "A856243058D1DE633379508ADCAFCF944E40E1672FF402750EF712E30C42012A", {0}},
                    {"144.217.86.39",            33445, "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A2A2FD34C", {0}},
                    {"185.14.30.213",            443,   "2555763C8C460495B14157D234DD56B86300A2395554BCAE4621AC345B8C1B1B", {0}},
                    {"77.37.160.178",            33440, "CE678DEAFA29182EFD1B0C5B9BC6999E5A20B50A1A6EC18B91C8EBB591712416", {0}},
                    {"85.21.144.224",            33445, "8F738BBC8FA9394670BCAB146C67A507B9907C8E564E28C2B59BEBB2FF68711B", {0}},
                    {"tox.natalenko.name",       33445, "1CB6EBFD9D85448FA70D3CAE1220B76BF6FCE911B46ACDCF88054C190589650B", {0}},
                    {"37.187.122.30",            33445, "BEB71F97ED9C99C04B8489BB75579EB4DC6AB6F441B603D63533122F1858B51D", {0}},
                    {"completelyunoriginal.moe", 33445, "FBC7DED0B0B662D81094D91CC312D6CDF12A7B16C7FFB93817143116B510C13E", {0}},
                    {"136.243.141.187",          443,   "6EE1FADE9F55CC7938234CC07C864081FC606D8FE7B751EDA217F268F1078A39", {0}},
                    {"tox.abilinski.com",        33445, "0E9D7FEE2AA4B42A4C18FE81C038E32FFD8D907AAA7896F05AA76C8D31A20065", {0}},
                    {"95.215.46.114",            33445, "5823FB947FF24CF83DDFAC3F3BAA18F96EA2018B16CC08429CB97FA502F40C23", {0}},
                    {"51.15.54.207",             33445, "1E64DBA45EC810C0BF3A96327DC8A9D441AB262C14E57FCE11ECBCE355305239", {0}}
            };

    // only nodes.tox.chat
    DHT_node nodes3[] =
            {
                    {"51.15.37.145", 33445, "6FC41E2BD381D37E9748FC0E0328CE086AF9598BECC8FEB7DDF2E440475F300E", {0}}
            };


    if (switch_nodelist_2 == 0)
    {
        dbg(9, "nodeslist:1");
        bootstap_nodes(tox, &nodes1, (int) (sizeof(nodes1) / sizeof(DHT_node)), 1);
    }
    else if (switch_nodelist_2 == 2)
    {
        dbg(9, "nodeslist:3");
        bootstap_nodes(tox, &nodes3, (int) (sizeof(nodes3) / sizeof(DHT_node)), 0);
    }
    else // (switch_nodelist_2 == 1)
    {
        dbg(9, "nodeslist:2");
        bootstap_nodes(tox, &nodes2, (int) (sizeof(nodes2) / sizeof(DHT_node)), 1);
    }
}

void av_local_disconnect(ToxAV *av, uint32_t friendnum)
{
    dbg(9, "av_local_disconnect friendnum=%d", (int)friendnum);
    TOXAV_ERR_CALL_CONTROL error = 0;
    toxav_call_control(av, friendnum, TOXAV_CALL_CONTROL_CANCEL, &error);
}

void disconnect_all_calls(Tox *tox)
{
    size_t i = 0;
    size_t size = tox_self_get_friend_list_size(tox);

    if (size == 0)
    {
        return;
    }

    uint32_t list[size];
    tox_self_get_friend_list(tox, list);
    char friend_key[TOX_PUBLIC_KEY_SIZE];
    CLEAR(friend_key);

    for (i = 0; i < size; ++i)
    {
        av_local_disconnect(mytox_av, list[i]);
    }
}

void cb___friend_connection_status(Tox *tox, uint32_t friendnum, TOX_CONNECTION connection_status,
                                   void *user_data)
{
    // if (is_friend_online(tox, friendnum) == 1)
    if (connection_status != TOX_CONNECTION_NONE)
    {
        // dbg(0, "friend %d just got online", friendnum);

        if (global_tv_friendnum == friendnum)
        {
            start_av_call_to_tv(tox, global_tv_friendnum);
        }
        else
        {
        }
    }
    else
    {
        dbg(0, "friend %d went *OFFLINE*", friendnum);

        // friend went offline -> hang up on all calls

        if (global_cam_friendnum == friendnum)
        {
            av_local_disconnect(mytox_av, friendnum);
            global_cam_video_active = 0;
        }

        if (global_tv_friendnum == friendnum)
        {
            av_local_disconnect(mytox_av, friendnum);
            global_tv_video_active = 0;
        }
        else
        {
            if (friend_to_take_av_from == friendnum)
            {
                friend_to_take_av_from = -1;
                global_video_active = 0;
                dbg(9, "friend_to_take_av_from = -1 [1]");
                dbg(9, "global_video_active = 0 [1]");
            }
            av_local_disconnect(mytox_av, friendnum);
        }
    }

    if (connection_status == TOX_CONNECTION_TCP)
    {
        // dbg(2, "cb___friend_connection_status:*READY*:friendnum=%d %d (TCP)",
        //    (int) friendnum,
        //    (int) connection_status);
    }
    else
    {
        //dbg(2, "cb___friend_connection_status:*READY*:friendnum=%d %d (UDP)",
        //    (int) friendnum,
        //    (int) connection_status);
    }
}

void *thread_av(void *data)
{
    ToxAV *av = (ToxAV *) data;

    pthread_t id = pthread_self();
    pthread_mutex_t av_thread_lock;

    if (pthread_mutex_init(&av_thread_lock, NULL) != 0)
    {
        dbg(0, "Error creating av_thread_lock");
    }
    else
    {
        dbg(2, "av_thread_lock created successfully");
    }

    dbg(2, "AV Thread #%d: starting", (int) id);


    while (toxav_iterate_thread_stop != 1)
    {
        if (global_video_active == 1)
        {
            pthread_mutex_lock(&av_thread_lock);
            // dbg(9, "AV Thread #%d:get frame\n", (int) id);

            pthread_mutex_unlock(&av_thread_lock);
            yieldcpu(DEFAULT_FPS_SLEEP_MS); /* ~4 frames per second */
        }
        else
        {
            yieldcpu(100);
        }
    }


    dbg(2, "ToxVideo:Clean thread exit!");
}


void *thread_video_av(void *data)
{
    ToxAV *av = (ToxAV *) data;

    pthread_t id = pthread_self();
    pthread_mutex_t av_thread_lock;

    if (pthread_mutex_init(&av_thread_lock, NULL) != 0)
    {
        dbg(0, "Error creating video av_thread_lock");
    }
    else
    {
        dbg(2, "av_thread_lock video created successfully");
    }

    dbg(2, "AV video Thread #%d: starting", (int) id);

    while (toxav_video_thread_stop != 1)
    {
        pthread_mutex_lock(&av_thread_lock);
        toxav_iterate(av);
        // dbg(9, "AV video Thread #%d running ...", (int) id);
        pthread_mutex_unlock(&av_thread_lock);
        // usleep(toxav_iteration_interval(av) * 1000);
	usleep(5 * 1000);
    }

    dbg(2, "ToxVideo:Clean video thread exit!");
}


// fill string with toxid in upper case hex.
// size of toxid_str needs to be: [TOX_ADDRESS_SIZE*2 + 1] !!
void get_my_toxid(Tox *tox, char *toxid_str)
{
    uint8_t tox_id_bin[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox, tox_id_bin);

    char tox_id_hex_local[TOX_ADDRESS_SIZE * 2 + 1];
    sodium_bin2hex(tox_id_hex_local, sizeof(tox_id_hex_local), tox_id_bin, sizeof(tox_id_bin));

    for (size_t i = 0; i < sizeof(tox_id_hex_local) - 1; i++)
    {
        tox_id_hex_local[i] = toupper(tox_id_hex_local[i]);
    }

    snprintf(toxid_str, (size_t) (TOX_ADDRESS_SIZE * 2 + 1), "%s", (const char *) tox_id_hex_local);
}


void reconnect(Tox *tox)
{
    bootstrap(tox);

    // -------- try to go online --------
    long long unsigned int cur_time = time(NULL);
    uint8_t off = 1;
    long long loop_counter = 0;
    long long overall_loop_counter = 0;
    while (1)
    {
        tox_iterate(tox, NULL);
        usleep(tox_iteration_interval(tox) * 1000);
        if (tox_self_get_connection_status(tox) && off)
        {
            dbg(2, "Reconnect: Tox online, took %llu seconds", time(NULL) - cur_time);
            off = 0;
            break;
        }
        c_sleep(20);
        loop_counter++;
        overall_loop_counter++;

        if (overall_loop_counter > (100 * 20)) // 40 secs
        {
            dbg(2, "Reconnect: Giving up after %llu seconds", time(NULL) - cur_time);
            break;
        }

        if (loop_counter > (50 * 20))
        {
            loop_counter = 0;
            // if not yet online, bootstrap every 20 seconds
            dbg(2, "Reconnect: Tox NOT online yet, bootstrapping again");
            bootstrap(tox);
        }
    }
    // -------- try to go online --------
}


void check_online_status(Tox *tox)
{
    if (my_connection_status == TOX_CONNECTION_NONE)
    {
        if ((get_unix_time() - my_last_offline_timestamp) > RECONNECT_AFTER_OFFLINE_SECONDS)
        {
            // we are offline for too long, try to reconnect
            reconnect(tox);
        }
    }
}


void print_tox_id(Tox *tox)
{
    char tox_id_hex[TOX_ADDRESS_SIZE * 2 + 1];
    get_my_toxid(tox, tox_id_hex);

    if (logfile)
    {
        dbg(2, "--MyToxID--:%s", tox_id_hex);
        int fd = fileno(logfile);
        fsync(fd);
    }
}


void sigint_handler(int signo)
{
    if (signo == SIGINT)
    {
        dbg(9, "received SIGINT, pid=%d", getpid());
        tox_loop_running = 0;
    }
}


int main(int argc, char *argv[])
{
    global_want_restart = 0;
    my_last_offline_timestamp = -1;
    my_last_online_timestamp = -1;

    logfile = fopen(log_filename, "wb");
    setvbuf(logfile, NULL, _IONBF, 0);

    global_video_active = 0;
    friend_to_take_av_from = -1;

    Tox *tox = create_tox();
    mytox_global = tox;
    global_start_time = time(NULL);

    tox_self_set_name(tox, (uint8_t *) bot_name, strlen(bot_name), NULL);
    tox_self_set_status_message(tox, (uint8_t *) bot_status_msg, strlen(bot_status_msg), NULL);

    bootstrap(tox);

    print_tox_id(tox);

    // init callbacks ----------------------------------
    tox_callback_self_connection_status(tox, cb___self_connection_status);
    tox_callback_friend_request(tox, cb___friend_request);
    tox_callback_friend_message(tox, cb___friend_message);
    tox_callback_friend_connection_status(tox, cb___friend_connection_status);
    tox_callback_file_recv(tox, cb___file_recv);
    // init callbacks ----------------------------------


    global_tv_toxid = NULL;
    global_tv_friendnum = -1;
    dbg(9, "[4]global_tv_friendnum %d", (int)global_tv_friendnum);
    global_tv_video_active = 0;
    dbg(9, "main:global_tv_toxid [1] %d", (int)global_tv_toxid);
    read_tvpubkey_from_file(&global_tv_toxid);
    dbg(9, "main:global_tv_toxid [2] %d", (int)global_tv_toxid);

    global_cam_toxid = NULL;
    global_cam_friendnum = -1;
    global_cam_video_active = 0;
    read_campubkey_from_file(&global_cam_toxid);


    update_savedata_file(tox);

    // -------- try to go online --------
    long long unsigned int cur_time = time(NULL);
    uint8_t off = 1;
    long long loop_counter = 0;
    while (1)
    {
        tox_iterate(tox, NULL);
        usleep(tox_iteration_interval(tox) * 1000);
        if (tox_self_get_connection_status(tox) && off)
        {
            dbg(2, "Tox online, took %llu seconds", time(NULL) - cur_time);
            off = 0;
            break;
        }
        c_sleep(20);
        loop_counter++;

        if (loop_counter > (50 * 20))
        {
            loop_counter = 0;
            // if not yet online, bootstrap every 20 seconds
            dbg(2, "Tox NOT online yet, bootstrapping again");
            bootstrap(tox);
        }
    }
    // -------- try to go online --------

    dbg(9, "global_tv_friendnum=%d global_tv_video_active=%d", (int)global_tv_friendnum, (int)global_tv_video_active);
    if (global_tv_friendnum == -1)
    {
        dbg(9, "global_tv_toxid %d", (int)global_tv_toxid);
        if (global_tv_toxid != NULL)
        {
            invite_tv_as_friend(tox, global_tv_toxid);
            dbg(9, "invite_tv_as_friend %d", (int)global_tv_toxid);
            global_tv_friendnum = friend_number_for_tv(tox, global_tv_toxid);
            dbg(9, "[5]global_tv_friendnum %d", (int)global_tv_friendnum);
            update_savedata_file(tox);
        }
    }

    if (global_cam_friendnum == -1)
    {
        if (global_cam_toxid != NULL)
        {
            invite_cam_as_friend(tox, global_cam_toxid);
            dbg(9, "invite_cam_as_friend %d", (int)global_cam_toxid);
            global_cam_friendnum = friend_number_for_cam(tox, global_cam_toxid);
            dbg(9, "global_cam_friendnum %d", (int)global_cam_friendnum);
            update_savedata_file(tox);
        }
    }


    TOXAV_ERR_NEW rc;
    dbg(2, "new Tox AV");
    mytox_av = toxav_new(tox, &rc);
    if (rc != TOXAV_ERR_NEW_OK)
    {
        dbg(0, "Error at toxav_new: %d", rc);
    }

    // init AV callbacks -------------------------------
    toxav_callback_call(mytox_av, cb___call, NULL);
    toxav_callback_call_state(mytox_av, cb___call_state, NULL);
    toxav_callback_bit_rate_status(mytox_av, cb___bit_rate_status, NULL);
    toxav_callback_audio_receive_frame(mytox_av, cb___audio_receive_frame, NULL);
    toxav_callback_video_receive_frame(mytox_av, cb___video_receive_frame, NULL);
    // init AV callbacks -------------------------------



    // start toxav thread ------------------------------
    pthread_t tid[2]; // 0 -> toxav_iterate thread, 1 -> video send thread

    toxav_iterate_thread_stop = 0;
    if (pthread_create(&(tid[0]), NULL, thread_av, (void *) mytox_av) != 0)
    {
        dbg(0, "AV iterate Thread create failed");
    }
    else
    {
        dbg(2, "AV iterate Thread successfully created");
    }

    toxav_video_thread_stop = 0;
    if (pthread_create(&(tid[1]), NULL, thread_video_av, (void *) mytox_av) != 0)
    {
        dbg(0, "AV video Thread create failed");
    }
    else
    {
        dbg(2, "AV video Thread successfully created");
    }
    // start toxav thread ------------------------------



    tox_loop_running = 1;
    signal(SIGINT, sigint_handler);

    while (tox_loop_running)
    {
        tox_iterate(tox, NULL);
	    
	if (global_video_active == 1)
	{
		usleep(3 * 1000);
	}
	else
	{
        	usleep(tox_iteration_interval(tox) * 1000);
	}

        if (global_want_restart == 1)
        {
            // need to restart me!
            break;
        }
        else
        {
            check_online_status(tox);
            if (global_tv_video_active == 0)
            {
                // dbg(9, "main:global_tv_video_active=%d", (int)global_tv_video_active);
                // dbg(9, "main:global_tv_friendnum=%d", (int)global_tv_friendnum);
                if (global_tv_friendnum == -1)
                {
                    // dbg(9, "main:global_tv_toxid=%d", (int)global_tv_toxid);
                    if (global_tv_toxid != NULL)
                    {
                        global_tv_friendnum = friend_number_for_tv(tox, global_tv_toxid);
                        dbg(9, "[6]global_tv_friendnum %d", (int)global_tv_friendnum);
                        update_savedata_file(tox);
                    }
                }

                // dbg(9, "main:global_video_active=%d", (int)global_video_active);
                if (global_video_active == 1)
                {
                    // dbg(9, "main:global_tv_friendnum=%d", (int)global_tv_friendnum);
                    if (global_tv_friendnum != -1)
                    {
                        // dbg(9, "main:is_friend_online(tox, global_tv_friendnum)=%d", (int)is_friend_online(tox, global_tv_friendnum));
                        if (is_friend_online(tox, global_tv_friendnum) == 1)
                        {
                            dbg(9, "main:is_friend_online(tox, global_tv_friendnum)=%d global_tv_friendnum=%d", (int)is_friend_online(tox, global_tv_friendnum), (int)global_tv_friendnum);
                            start_av_call_to_tv(tox, global_tv_friendnum);
                        }
                    }
                }
            }

            if (global_cam_video_active == 0)
            {
                if (is_friend_online(tox, global_cam_friendnum) == 1)
                {
                    start_av_call_to_cam(tox, global_cam_friendnum);
                }
            }

            if (global_video_active == 0)
            {
                if (global_tv_video_active == 1)
                {
                    if (global_tv_friendnum != -1)
                    {
                        // no active caller, hang up TV call
                        av_local_disconnect(mytox_av, global_tv_friendnum);
                        global_tv_video_active = 0;
                        dbg(9, "main:av_local_disconnect %d hang up call to TV", (int)global_tv_friendnum);
                    }
                }
            }
        }
    }

    update_savedata_file(tox);
    disconnect_all_calls(tox);

    toxav_kill(mytox_av);
    tox_kill(tox);

    if (logfile)
    {
        fclose(logfile);
        logfile = NULL;
    }

    return 0;

}


