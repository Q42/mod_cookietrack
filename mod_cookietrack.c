/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"

#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"

#include <math.h>


module AP_MODULE_DECLARE_DATA cookietrack_module;

/* ********************************************

    Structs & Defines

   ******************************************** */


#define COOKIE_NAME "Apache"    // default name if you did not provide one
#define NOTE_NAME   "cookie"    // default note name if you did not provide one
                                // Backwards compatible with mod_usertrack
#define HEADER_NAME "X-UUID"    // default header name if you did not provide one

#define NUM_SUBS 3              // Amount of regex sub expressions

#define GENERATED_NOTE_NAME "cookie_generated"
                                // Was the cookie generated on this visit?

#ifdef MAX_COOKIE_LENGTH        // maximum size of the cookie value
#define _MAX_COOKIE_LENGTH MAX_COOKIE_LENGTH
#else
#define _MAX_COOKIE_LENGTH 40   // At least IP address + dots + microsecond timestamp
#endif                          // So 16 + 4 + 16 = 36.

#ifdef DEBUG                    // To print diagnostics to the error log
#define _DEBUG 1                // enable through gcc -DDEBUG
#else
#define _DEBUG 0
#endif

#ifdef LIBRARY
// because #include doesn't support macro expansion, we use a fixed
// header file, which the build scripts writes the dynamic header file
// name too. Yes, hackish, but the easiest way while not using autoconf.
#include "mod_cookietrack_external_uid.h"
#define _EXTERNAL_UID_FUNCTION 1
#else
// Inlining the code now, as it's straight forward, but this would
// work for aliasing ( see http://xrl.us/AliasC ):
// void __builtin_gen_uid( char *uid, char *ptr );
// void gen_uid() __attribute__((alias("__builtin_gen_uid")));
#define _EXTERNAL_UID_FUNCTION 0
#endif

// the type of cookie to set
typedef enum {
    CT_UNSET,       // falls back to netscape
    CT_NETSCAPE,    // uses original netscape expires syntax
    CT_COOKIE,      // rfc 2109, using max-age
    CT_COOKIE2      // rfc 2965, using max-age
} cookie_type_e;

// module configuration - this is basically a global struct
typedef struct {
    int enabled;            // module enabled?
    cookie_type_e style;    // type of cookie, see above
    char *cookie_name;      // name of cookie
    char *cookie_domain;    // domain
    char *cookie_ip_header; // header to take the client ip from
    char *note_name;        // note to set for log files
    char *generated_note_name;
                            // note to indicate a cookie was generated this request
    char *header_name;      // name of the incoming/outgoing header
    char *regexp_string;    // used to compile regexp; save for debugging
    ap_regex_t *regexp;     // used to find cookietrack cookie in cookie header
    int expires;            // holds the expires value for the cookie
    int send_header;        // whether or not to send headers
} cookietrack_settings_rec;


/* ********************************************

    Functions for spotting, generating &
    setting cookies

   ******************************************** */

// Generate a unique ID -
void __builtin_gen_uid( char uid[], char input[] )
{

}

// Generate the actual cookie
void make_cookie(request_rec *r, char uid[], char cur_uid[])
{   // configuration
    cookietrack_settings_rec *dcfg;
    dcfg = ap_get_module_config(r->per_dir_config, &cookietrack_module);

    /* 1024 == hardcoded constant */
    char cookiebuf[1024];
    char *new_cookie;

    const char *rname = ap_get_remote_host(r->connection, r->per_dir_config,
                                            REMOTE_NAME, NULL);
    apr_snprintf(cookiebuf, sizeof(cookiebuf), "%s", uid );

    if (dcfg->expires) {

        /* Cookie with date; as strftime '%a, %d-%h-%y %H:%M:%S GMT' */
        new_cookie = apr_psprintf(r->pool, "%s=%s; path=/",
                                  dcfg->cookie_name, cookiebuf);

        if ((dcfg->style == CT_UNSET) || (dcfg->style == CT_NETSCAPE)) {
            apr_time_exp_t tms;
            apr_time_exp_gmt(&tms, r->request_time
                                 + apr_time_from_sec(dcfg->expires));

            new_cookie = apr_psprintf( r->pool,
                            "%s; expires=%s, %.2d-%s-%.2d %.2d:%.2d:%.2d GMT",
                            new_cookie, apr_day_snames[tms.tm_wday],
                            tms.tm_mday,
                            apr_month_snames[tms.tm_mon],
                            tms.tm_year % 100,
                            tms.tm_hour, tms.tm_min, tms.tm_sec
                            );
        } else {
            int expires = dcfg->expires;
            _DEBUG && fprintf( stderr, "Expires = %d\n", expires );

            new_cookie = apr_psprintf( r->pool,
                                       "%s; max-age=%d",
                                       new_cookie,
                                       expires );
        }

    } else {
        new_cookie = apr_psprintf(r->pool, "%s=%s; path=/",
                                  dcfg->cookie_name, cookiebuf);
    }

    if (dcfg->cookie_domain != NULL) {
        new_cookie = apr_pstrcat(r->pool, new_cookie, "; domain=",
                                 dcfg->cookie_domain,
                                 (dcfg->style == CT_COOKIE2
                                  ? "; version=1"
                                  : ""),
                                 NULL);
    }

    // r->err_headers_out also honors non-2xx responses and
    // internal redirects. See the patch here:
    // http://svn.apache.org/viewvc?view=revision&revision=1154620
    apr_table_addn( r->err_headers_out,
                    (dcfg->style == CT_COOKIE2 ? "Set-Cookie2" : "Set-Cookie"),
                    new_cookie );

    // we also set it on the INCOMING cookie header, so the app can
    // Just Use It without worrying. Only do so if we don't already
    // have an incoming cookie value, or it will send 2 cookies with
    // the same name, with both the old and new value :(
    if( !cur_uid ) {

        // set the cookie name
        apr_table_addn( r->headers_in, "Cookie",  new_cookie );

        _DEBUG && fprintf( stderr, "Adding cookie '%s' to incoming header\n", new_cookie );
    }

    // Created a new cookie or not?
    _DEBUG && fprintf( stderr, "Generated cookie: %d\n", !cur_uid );

    // set a note indicating we generated a cookie
    // apr_table_setn wants a char, not an int, so we do the conversion like this
    apr_table_setn( r->notes, dcfg->generated_note_name, cur_uid ? "0" : "1" );

    // set a note, so we can capture it in the logs
    // this expects chars, and apr_pstrdup will make sure any char stays
    // in scope for the function. If not, it ends up being empty.
    apr_table_setn( r->notes, dcfg->note_name, apr_pstrdup(r->pool, uid) );

}

// Find the cookie and figure out what to do
static int spot_cookie(request_rec *r)
{
    cookietrack_settings_rec *dcfg = ap_get_module_config(r->per_dir_config,
                                                &cookietrack_module);

    const char *cookie_header;
    ap_regmatch_t regm[NUM_SUBS];

    /* Do not run in subrequests */
    if (!dcfg->enabled || r->main) {
        return DECLINED;
    }

    /* Do we already have a cookie? */
    char *cur_cookie_value = NULL;
    if( (cookie_header = apr_table_get(r->headers_in, "Cookie")) ) {

        // this will match the FIRST occurance of the cookiename, not
        // subsequent ones.
        if( !ap_regexec(dcfg->regexp, cookie_header, NUM_SUBS, regm, 0) ) {
            /* Our regexp,
             * ^cookie_name=([^;]+)|;[ \t]+cookie_name=([^;]+)
             * only allows for $1 or $2 to be available. ($0 is always
             * filled with the entire matched expression, not just
             * the part in parentheses.) So just check for either one
             * and assign to cookieval if present. */
            if( regm[1].rm_so != -1 ) {
                cur_cookie_value = ap_pregsub(r->pool, "$1", cookie_header,
                                       NUM_SUBS, regm);
            }
            if( regm[2].rm_so != -1 ) {
                cur_cookie_value = ap_pregsub(r->pool, "$2", cookie_header,
                                       NUM_SUBS, regm);
            }
        }
    }

    _DEBUG && fprintf( stderr, "Current Cookie: %s\n", cur_cookie_value );

    /* XFF support inspired by this patch:
       http://www.mail-archive.com/dev@httpd.apache.org/msg17378.html

       And this implementation for scanning for remote ip:
       http://apache.wirebrain.de/lxr/source/modules/metadata/mod_remoteip.c?v=2.3-trunk#267
    */

    // Get the IP address of the originating request
    const char *rname = NULL;   // Originating IP address
    char *xff         = NULL;   // X-Forwarded-For, or equivalent header type

    // Should we look at a header?
    /// apr_table_get returns a const char, so strdup it.
    if( xff = apr_pstrdup( r->pool, apr_table_get(r->headers_in, dcfg->cookie_ip_header) ) ) {

        // There might be multiple addresses in the header
        // Check if there's a comma in there somewhere

        // no comma, this is the address we can use
        if( (rname = strrchr(xff, ',')) == NULL ) {
            rname = xff;

        // whitespace/commas left, remove 'm
        } else {

            // move past the comma
            rname++;

            // and any whitespace we might find
            while( *rname == ' ' ) {
                rname++;
            }
        }

    // otherwise, get it from the remote host
    } else {
        rname = ap_get_remote_host( r->connection, r->per_dir_config,
                                    REMOTE_NAME, NULL );
    }

    _DEBUG && fprintf( stderr, "Remote Address: %s\n", rname );

    /* Determine the value of the cookie we're going to set: */
    /* Make sure we have enough room here by adding an extra char of space. */
    char new_cookie_value[ _MAX_COOKIE_LENGTH + 1 ];

    _DEBUG && fprintf( stderr, "Maximum supported cookie length: %d\n", _MAX_COOKIE_LENGTH );

    // it's either carbage, or not set; either way,
    // we need to generate a new one
    const char *unique_id;
    if( !cur_cookie_value ) {
        // if we have some sort of library that's generating the
        // UID, call that with the cookie we would be setting
        if( _EXTERNAL_UID_FUNCTION ) {
            char ts[ _MAX_COOKIE_LENGTH ];
            sprintf( ts, "%" APR_TIME_T_FMT, apr_time_now() );
            gen_uid( new_cookie_value, ts, rname );

        // Use mod_unique_id if available
        } else if((unique_id = apr_table_get(r->subprocess_env, "UNIQUE_ID"))) {
            apr_cpystrn(new_cookie_value, unique_id, sizeof(new_cookie_value));

        // otherwise, just set it
        } else {
            sprintf( new_cookie_value,
                        "%s.%" APR_TIME_T_FMT, rname, apr_time_now() );
        }

        _DEBUG && fprintf( stderr, "New cookie: %s\n", new_cookie_value );
    }

    // Set incoming headers?
    if( dcfg->send_header ) {
        if( cur_cookie_value ) {
            apr_table_addn( r->headers_in,
                            dcfg->header_name,
                            apr_pstrdup(r->pool, cur_cookie_value) );
        } else {
            apr_table_addn( r->headers_in,
                            dcfg->header_name,
                            apr_pstrdup(r->pool, new_cookie_value) );
        }
    }

    // there already is a cookie set
    if( cur_cookie_value ) {
        return DECLINED;
    }

    /* Set the cookie in a note, for logging */
    apr_table_setn(r->notes, dcfg->note_name, new_cookie_value);

    make_cookie(r,  new_cookie_value, cur_cookie_value);

    // We need to flush the stream for messages to appear right away.
    // Performing an fflush() in a production system is not good for
    // performance - don't do this for real.
    _DEBUG && fflush(stderr);

    return OK;                  /* We set our cookie */
}

/* ********************************************

    Get / Set / Create settings

   ******************************************** */

static const char *set_cookie_exp(cmd_parms *parms, void *mconfig,
                                  const char *arg)
{
    //cookie_log_state *cls;
    time_t factor, modifier = 0;
    time_t num = 0;
    char *word;

    cookietrack_settings_rec *dcfg = mconfig;

    /* The simple case first - all numbers (we assume) */
    if (apr_isdigit(arg[0]) && apr_isdigit(arg[strlen(arg) - 1])) {
        dcfg->expires = atol(arg);
        return NULL;
    }

    /*
     * The harder case - stolen from mod_expires
     *
     * CookieExpires "[plus] {<num> <type>}*"
     */

    word = ap_getword_conf(parms->pool, &arg);
    if (!strncasecmp(word, "plus", 1)) {
        word = ap_getword_conf(parms->pool, &arg);
    };

    /* {<num> <type>}* */
    while (word[0]) {
        /* <num> */
        if (apr_isdigit(word[0])) {
            num = atoi(word);
        } else {
            return "bad expires code, numeric value expected.";
        }

        /* <type> */
        word = ap_getword_conf(parms->pool, &arg);
        if (!word[0]) { return "bad expires code, missing <type>"; }

        factor = 0;
        if (!strncasecmp(word, "years", 1)) {
            factor = 60 * 60 * 24 * 365;
        } else if (!strncasecmp(word, "months", 2)) {
            factor = 60 * 60 * 24 * 30;
        } else if (!strncasecmp(word, "weeks", 1)) {
            factor = 60 * 60 * 24 * 7;
        } else if (!strncasecmp(word, "days", 1)) {
            factor = 60 * 60 * 24;
        } else if (!strncasecmp(word, "hours", 1)) {
            factor = 60 * 60;
        } else if (!strncasecmp(word, "minutes", 2)) {
            factor = 60;
        } else if (!strncasecmp(word, "seconds", 1)) {
            factor = 1;
        } else {
            return "bad expires code, unrecognized type";
        }

        modifier = modifier + factor * num;

        /* next <num> */
        word = ap_getword_conf(parms->pool, &arg);
    }

    dcfg->expires = modifier;

    return NULL;
}

/* dcfg->regexp is "^cookie_name=([^;]+)|;[ \t]+cookie_name=([^;]+)",
 * which has three subexpressions, $0..$2 */
static void set_and_comp_regexp(cookietrack_settings_rec *dcfg,
                                apr_pool_t *p,
                                const char *cookie_name)
{
    int danger_chars = 0;
    const char *sp = cookie_name;

    /* The goal is to end up with this regexp,
     * ^cookie_name=([^;,]+)|[;,][ \t]+cookie_name=([^;,]+)
     * with cookie_name obviously substituted either
     * with the real cookie name set by the user in httpd.conf, or with the
     * default COOKIE_NAME. */

    /* Anyway, we need to escape the cookie_name before pasting it
     * into the regex
     */
    while (*sp) {
        if (!apr_isalnum(*sp)) {
            ++danger_chars;
        }
        ++sp;
    }

    if (danger_chars) {
        char *cp;
        cp = apr_palloc(p, sp - cookie_name + danger_chars + 1); /* 1 == \0 */
        sp = cookie_name;
        cookie_name = cp;
        while (*sp) {
            if (!apr_isalnum(*sp)) {
                *cp++ = '\\';
            }
            *cp++ = *sp++;
        }
        *cp = '\0';
    }

    dcfg->regexp_string = apr_pstrcat(p, "^",
                                      cookie_name,
                                      "=([^;,]+)|[;,][ \t]*",
                                      cookie_name,
                                      "=([^;,]+)", NULL);

    dcfg->regexp = ap_pregcomp(p, dcfg->regexp_string, AP_REG_EXTENDED);
    ap_assert(dcfg->regexp != NULL);
}

/* initialize all attributes */
static void *make_cookietrack_settings(apr_pool_t *p, char *d)
{
    cookietrack_settings_rec *dcfg;

    dcfg = (cookietrack_settings_rec *) apr_pcalloc(p, sizeof(cookietrack_settings_rec));
    dcfg->cookie_name           = COOKIE_NAME;
    dcfg->cookie_domain         = NULL;
    dcfg->cookie_ip_header      = NULL;
    dcfg->style                 = CT_UNSET;
    dcfg->enabled               = 0;
    dcfg->expires               = 0;
    dcfg->note_name             = NOTE_NAME;
    dcfg->generated_note_name   = GENERATED_NOTE_NAME;
    dcfg->header_name           = HEADER_NAME;
    dcfg->send_header           = 0;

    /* In case the user does not use the CookieName directive,
     * we need to compile the regexp for the default cookie name. */
    set_and_comp_regexp(dcfg, p, COOKIE_NAME);

    return dcfg;
}

/* Set the value of a config variabe, ints/booleans only */
static const char *set_config_enable(cmd_parms *cmd, void *mconfig,
                                    int value)
{
    cookietrack_settings_rec *dcfg;

    dcfg = (cookietrack_settings_rec *) mconfig;

    char name[50];
    sprintf( name, "%s", cmd->cmd->name );

    /* Unfortunately, C does not have the equivalent of Perls
       $struct->$name = $value. So we're using a switch instead.
       Suggestions welcome.
    */
    /* Oh hey, switch statements aren't for strings, so we're
       going to be using if (strcasecmp(name, "y") == 0) {
       instead. sexy times!
    */

    if( strcasecmp(name, "CookieTracking") == 0 ) {
        dcfg->enabled           = value;

    } else if( strcasecmp(name, "CookieSendHeader") == 0 ) {
        dcfg->send_header       = value;

    } else {
        return apr_psprintf(cmd->pool, "No such variable %s", name);
    }

    return NULL;
}

/* Set the value of a config variabe, strings only */
static const char *set_config_value(cmd_parms *cmd, void *mconfig,
                                    const char *value)
{
    cookietrack_settings_rec *dcfg;

    dcfg = (cookietrack_settings_rec *) mconfig;

    char name[50];
    sprintf( name, "%s", cmd->cmd->name );

    /* Unfortunately, C does not have the equivalent of Perls
       $struct->$name = $value. So we're using a switch instead.
       Suggestions welcome.
    */
    /* Oh hey, switch statements aren't for strings, so we're
       going to be using if (strcasecmp(name, "y") == 0) {
       instead. sexy times!
    */

    /*
     * Apply restrictions on attributes.
     */
    if( strlen(value) == 0 ) {
        return apr_psprintf(cmd->pool, "%s not allowed to be NULL", name);
    }

    /* Name of the cookie header to send */
    if( strcasecmp(name, "CookieHeaderName") == 0 ) {
        dcfg->header_name   = apr_pstrdup(cmd->pool, value);

    /* Name of the note to use in the logs */
    } else if( strcasecmp(name, "CookieNoteName") == 0 ) {
        dcfg->note_name     = apr_pstrdup(cmd->pool, value);

    /* Name of the note to use in the logs to indicate a cookie was generated */
    } else if( strcasecmp(name, "CookieGeneratedNoteName") == 0 ) {
        dcfg->generated_note_name
                            = apr_pstrdup(cmd->pool, value);

    /* Cookie style to sue */
    } else if( strcasecmp(name, "CookieStyle") == 0 ) {

        if( strcasecmp(value, "Netscape") == 0 ) {
            dcfg->style = CT_NETSCAPE;

        } else if( (strcasecmp(value, "Cookie") == 0)
                 || (strcasecmp(value, "RFC2109") == 0) ) {
            dcfg->style = CT_COOKIE;

        } else if( (strcasecmp(value, "Cookie2") == 0)
                 || (strcasecmp(value, "RFC2965") == 0) ) {
            dcfg->style = CT_COOKIE2;

        } else {
            return apr_psprintf(cmd->pool, "Invalid %s: %s", name, value);
        }

    /* Name of the note to use in the logs */
    } else if( strcasecmp(name, "CookieIPHeader") == 0 ) {
        dcfg->cookie_ip_header  = apr_pstrdup(cmd->pool, value);

    /* Domain to set the cookie in */
    } else if( strcasecmp(name, "CookieDomain") == 0 ) {

        if( value[0] != '.' ) {
            return "CookieDomain values must begin with a dot";
        }

        if( ap_strchr_c( &value[1], '.' ) == NULL ) {
            return "CookieDomain values must contain at least one embedded dot";
        }

        dcfg->cookie_domain = apr_pstrdup(cmd->pool, value);

    /* Name of the cookie */
    } else if( strcasecmp(name, "CookieName") == 0 ) {
        dcfg->cookie_name = apr_pstrdup(cmd->pool, value);

        /* build regex to compare against */
        set_and_comp_regexp(dcfg, cmd->pool, value);

        if (dcfg->regexp == NULL) {
            return "Regular expression could not be compiled.";
        }

        if (dcfg->regexp->re_nsub + 1 != NUM_SUBS) {
            return apr_psprintf(cmd->pool, "Invalid cookie name: %s", value);
        }

    } else {
        return apr_psprintf(cmd->pool, "No such variable %s", name);
    }

    return NULL;
}

/* ********************************************

    Registering variables, hooks, etc

   ******************************************** */


static const command_rec cookietrack_cmds[] = {
    AP_INIT_TAKE1("CookieExpires",          set_cookie_exp,     NULL, OR_FILEINFO,
                  "an expiry date code"),
    AP_INIT_TAKE1("CookieDomain",           set_config_value,   NULL, OR_FILEINFO,
                  "domain to which this cookie applies"),
    AP_INIT_TAKE1("CookieStyle",            set_config_value,   NULL, OR_FILEINFO,
                  "'Netscape', 'Cookie' (RFC2109), or 'Cookie2' (RFC2965)"),
    AP_INIT_TAKE1("CookieName",             set_config_value,   NULL, OR_FILEINFO,
                  "name of the tracking cookie"),
    AP_INIT_TAKE1("CookieIPHeader",         set_config_value,   NULL, OR_FILEINFO,
                  "name of the header to use for the client IP"),
    AP_INIT_FLAG( "CookieTracking",         set_config_enable,  NULL, OR_FILEINFO,
                  "whether or not to enable cookies"),
    AP_INIT_FLAG( "CookieSendHeader",       set_config_enable,  NULL, OR_FILEINFO,
                  "whether or not to send extra header with the tracking cookie"),
    AP_INIT_TAKE1("CookieHeaderName",       set_config_value,   NULL, OR_FILEINFO,
                  "name of the incoming/outgoing header to set to the cookie value"),
    AP_INIT_TAKE1("CookieNoteName",         set_config_value,   NULL, OR_FILEINFO,
                  "name of the note to set to for the Apache logs"),
    AP_INIT_TAKE1("CookieGeneratedNoteName",set_config_value,   NULL, OR_FILEINFO,
                  "name of the note indicating a cookie was generated this request" ),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{   /* code gets skipped if modules return a status code from
       their fixup hooks, so be sure to run REALLY first. See:
       http://svn.apache.org/viewvc?view=revision&revision=1154620
    */
    ap_hook_fixups( spot_cookie, NULL, NULL, APR_HOOK_REALLY_FIRST );
}

module AP_MODULE_DECLARE_DATA cookietrack_module = {
    STANDARD20_MODULE_STUFF,
    make_cookietrack_settings,  /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server configs */
    cookietrack_cmds,           /* command apr_table_t */
    register_hooks              /* register hooks */
};
