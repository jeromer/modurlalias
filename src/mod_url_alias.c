/**
 * Copyright [2009] [Jérôme Renard jerome.renard@gmail.com]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 **/

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_request.h"
#include "apr_dbd.h"
#include "mod_dbd.h"

#define ENGINE_DISABLED 0
#define ENGINE_ENABLED  1

#define QUERY_SQL   "SELECT * FROM urlalias WHERE source = %s"
#define QUERY_LABEL "urlalias_stmt"

/*
 * Optional function pointers : needed in post_config
 * - ap_dbdd_prepare
 * - ap_dbd_acquire
 */
static ap_dbd_t *(*urlalias_dbd_acquire_fn)(request_rec*)                          = NULL;
static void      (*urlalias_dbd_prepare_fn)(server_rec*, const char*, const char*) = NULL;

/*
 * Structure : per <Directory> configuration
 */
typedef struct {
    int engine_status; /* URLAliasEngine */
} urlalias_perdir_config;

/*
 * Structure : per <VirtualHost> configuration
 */
typedef struct {
    int engine_status; /* URLAliasEngine */
} urlalias_server_config;

/*
 * Structure : global data structure declaration
 */
module AP_MODULE_DECLARE_DATA urlalias_module;

/*
 * Hook : post config, create the SQL prepared statement for
 *        the SQL query.
 */
static int post_config(apr_pool_t *pconf, 
                       apr_pool_t *plog,
                       apr_pool_t *ptemp,
                       server_rec *s)
{
    /* Fetching needed function pointers */
    if (urlalias_dbd_prepare_fn == NULL) {
        urlalias_dbd_prepare_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_prepare);
        if (urlalias_dbd_prepare_fn == NULL) {
            /* mod DBD is not loaded */
            return DECLINED;
        }
        urlalias_dbd_acquire_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
    }

    urlalias_dbd_prepare_fn(s, QUERY_SQL, QUERY_LABEL);

    return OK;
}

/*
 * Conf : create and initialize per <VirtualHost> configuration structure
 */
static void *config_server_create(apr_pool_t *p, server_rec *s)
{
    urlalias_server_config *server_config;

    server_config = (urlalias_server_config *) apr_pcalloc(p, sizeof(urlalias_server_config));

    server_config->engine_status = ENGINE_DISABLED;
    
    return (void *)server_config;
}

/*
 * Conf : create and initialize per <Directory> configuration structure
 */
static void *config_perdir_create(apr_pool_t *p, char *path)
{
    urlalias_perdir_config *directory_config;

    directory_config = (urlalias_perdir_config *) apr_pcalloc(p, sizeof(urlalias_perdir_config));

    directory_config->engine_status = ENGINE_DISABLED;

    return (void *) directory_config;
}

/*
 * Conf : engine state, On or Off
 */
static const char *cmd_urlaliasengine(cmd_parms *cmd, void *in_directory_config, int flag)
{
    urlalias_perdir_config *directory_config;
    urlalias_server_config *server_config;

    directory_config = in_directory_config;
    server_config    = ap_get_module_config(cmd->server->module_config, &urlalias_module);

    if (cmd->path == NULL) { 
        /* <VirtualHost> configuration */
        server_config->engine_status = (flag ? ENGINE_ENABLED : ENGINE_DISABLED);
    }
    else {
        /* <Directory> configuration */
        directory_config->engine_status = (flag ? ENGINE_ENABLED : ENGINE_DISABLED);
    }

    return NULL;
}

/*
 * Hook : global hook table
 */
static void url_alias_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_FIRST);
}

/*
 * Conf : configuration directives declaration
 */
static const command_rec command_table[] = {
    AP_INIT_FLAG( "URLAliasEngine",
                  cmd_urlaliasengine, 
                  NULL,
                  OR_FILEINFO,
                  "On or Off : enable or disable (default) the URL alias engine"),

    { NULL }
};

/* 
 * Structure : module config global structure
 */
module AP_MODULE_DECLARE_DATA urlalias_module = {
    STANDARD20_MODULE_STUFF, 
    config_perdir_create,     /* create per-dir    config structures */
    NULL,                     /* merge  per-dir    config structures */
    config_server_create,     /* create per-server config structures */
    NULL,                     /* merge  per-server config structures */
    command_table,            /* table of config file commands       */
    url_alias_register_hooks  /* register hooks                      */
};