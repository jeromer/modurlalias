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
 *
 * The actual table used
 * +------------+--------------+------+-----+---------+-------+
 * | Field      | Type         | Null | Key | Default | Extra |
 * +------------+--------------+------+-----+---------+-------+
 * | source     | varchar(200) | NO   | PRI |         |       | 
 * | module     | varchar(30)  | NO   |     |         |       | 
 * | view       | varchar(30)  | NO   |     |         |       | 
 * | parameters | varchar(200) | NO   |     |         |       | 
 * +------------+--------------+------+-----+---------+-------+
 **/

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "http_request.h"
#include "apr_dbd.h"
#include "mod_dbd.h"
#include "apr_strings.h"

#define ENGINE_DISABLED 0
#define ENGINE_ENABLED  1

#define QUERY_SQL   "SELECT * FROM urlalias WHERE source = %s"
#define QUERY_LABEL "urlalias_stmt"

#define DIRECTORY_SEPARATOR "/"

#define REGEX_FILE_EXT_EXCLUSION "\\.(?:gif|jp[e]?g|png|ico|css|js|mp3|flv)$"

/*
 * Optional function pointers : needed in post_config
 * - ap_dbdd_prepare
 * - ap_dbd_acquire
 */
static ap_dbd_t *(*urlalias_dbd_acquire_fn)(request_rec*)                          = NULL;
static void      (*urlalias_dbd_prepare_fn)(server_rec*, const char*, const char*) = NULL;

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
 * Hook : content handler for internal redirections
 *
 * This function is called after hook_fixup.
 */
static int hook_handler(request_rec *r)
{
    /* using the handler name is not enough to do the job */
    if (strcmp(r->handler, "urlalias-internal-redirect-handler")) {
        return DECLINED;
    }

    /* this comes from hook_fixup and is safer*/
    if (strncmp(r->filename, "urlalias-redirect:", 18) != 0) {
        return DECLINED;
    }

    /* now the internal redirect */
    ap_internal_redirect(apr_pstrcat(r->pool,
                                     r->filename+18,
                                     /* shall we append arguments ? */
                                     r->args ? "?" : NULL, r->args, NULL),
                         r);

    return OK;
}

/*
 * Hook : maps the nice URL to the system one
 *
 * This function does all the source to target mapping stuff
 * and then it modifies the current requests on the fly so it
 * is handled by hook_handler for the redirection on the
 * real file.
 */
static int hook_fixup(request_rec *r)
{
    /* The actual database connection */
    ap_dbd_t *dbd = urlalias_dbd_acquire_fn(r);

    /* The prepared statement for our SQL query */
    apr_dbd_prepared_t *prepared_stmt = NULL;

    /* The error code of execution of our SQL query */
    apr_int16_t select_error_code = -1;

    /* The result set */
    apr_dbd_results_t *res = NULL;

    /* The result row */
    apr_dbd_row_t *row = NULL;

    /* The compiled regex we want to apply on each requested URI */
    ap_regex_t *regex = NULL;

    /* The regex execution result */
    int regexec_result = AP_REG_NOMATCH;

    /* The list of regex captures */
    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];

    /* Table's fields */
    const char *source     = NULL;
    const char *module     = NULL;
    const char *view       = NULL;
    const char *parameters = NULL;

    /* the system URL to redirect to */
    char *target = NULL;

    /* We ignore the most common binary files */
    regex = ap_pregcomp(r->pool, REGEX_FILE_EXT_EXCLUSION, AP_REG_EXTENDED | AP_REG_ICASE | AP_REG_NOSUB);

    if( !regex ) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unable to compile regex : %s", REGEX_FILE_EXT_EXCLUSION);
        return DECLINED;
    }

    regexec_result = ap_regexec(regex, r->uri, AP_MAX_REG_MATCH, regmatch, AP_REG_EXTENDED | AP_REG_ICASE | AP_REG_NOSUB);

    /* regex successfully applied */
    if( regexec_result == 0 ) {
        /* then this request is a binary file which is not relevant for us */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "%s is a binary file, skipping", r->uri);
        return DECLINED;
    }

    /* Extra database connection check */
    if(dbd == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unable to acquire a database connection ");
        return DECLINED;
    }

    /* This is not for us */
    if( !r->uri || strlen(r->uri) == 0) {
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "r->uri : %s", r->uri);

    prepared_stmt = apr_hash_get(dbd->prepared, QUERY_LABEL, APR_HASH_KEY_STRING);

    /* the prepared statement disapearred */
    if (prepared_stmt == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "A prepared statement could not be found");
        return DECLINED;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "prepared statement found");

    select_error_code = apr_dbd_pvselect(dbd->driver,
                                         r->pool,
                                         dbd->handle,
                                         &res,
                                         prepared_stmt,
                                         0,
                                         r->uri,
                                         NULL);

    if (select_error_code != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Query execution error looking up '%s' "
                      "in database", r->uri);
        return DECLINED;
    }

    if(apr_dbd_get_row(dbd->driver, r->pool, res, &row, 1) == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "no results found");
        return DECLINED;
    }

    /* since the source field is unique there is only one result */
    /* no need for a loop here                                   */
    source     = apr_dbd_get_entry(dbd->driver, row, 0);
    module     = apr_dbd_get_entry(dbd->driver, row, 1);
    view       = apr_dbd_get_entry(dbd->driver, row, 2);
    parameters = apr_dbd_get_entry(dbd->driver, row, 3);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "source     : %s", source);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "module     : %s", module);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "view       : %s", view);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "parameters : %s", parameters);

    /* assembling the module/view URL */
    target = apr_pstrcat(r->pool,
                         DIRECTORY_SEPARATOR, module,
                         DIRECTORY_SEPARATOR, view,
                         NULL);

    r->filename = apr_pstrdup(r->pool, target);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "target : %s", target);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "r->filename : %s", r->filename);

    /* adding parameters to our request */
    r->args = apr_pstrdup(r->pool, parameters);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "r->args : %s", r->args);

    /* avoid deadlooping */
    if (strcmp(r->uri, target) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "deadlooping URI : %s on target : %s ", r->uri, target);
        return HTTP_BAD_REQUEST;
    }

    /* the filename must be either an absolute local path or an
    * absolute local URL.
    */
    if (*r->filename != '/' && !ap_os_is_path_absolute(r->pool, r->filename)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "non absolute path : %s", r->filename);
        return HTTP_BAD_REQUEST;
    }


    /* now we redirect internally to the real filename */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "internal redirect from %s to %s ", r->uri, r->filename);
    r->filename = apr_pstrcat(r->pool, "urlalias-redirect:", r->filename, NULL);
    r->handler = "urlalias-internal-redirect-handler";

    return OK;
}

/*
 * Conf : creates and initializes per <VirtualHost> configuration structure
 */
static void *config_server_create(apr_pool_t *p, server_rec *s)
{
    urlalias_server_config *server_config;

    server_config = (urlalias_server_config *) apr_pcalloc(p, sizeof(urlalias_server_config));

    server_config->engine_status = ENGINE_DISABLED;
    
    return (void *)server_config;
}

/*
 * Conf : engine state, On or Off
 */
static const char *cmd_urlaliasengine(cmd_parms *cmd, void *in_directory_config, int flag)
{
    urlalias_server_config *server_config;

    server_config    = ap_get_module_config(cmd->server->module_config, &urlalias_module);

    if (cmd->path == NULL) {
        /* <VirtualHost> configuration */
        server_config->engine_status = (flag ? ENGINE_ENABLED : ENGINE_DISABLED);
    }

    /* Only use the connection if the URLAlias engine is enabled */
    if (server_config->engine_status == ENGINE_DISABLED) {
        return NULL;
    }

    /* Fetching needed function pointers */
    if (urlalias_dbd_prepare_fn == NULL) {
        urlalias_dbd_prepare_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_prepare);
        if (urlalias_dbd_prepare_fn == NULL) {
            return "mod_dbd must be enabled in order to get mod_url_alias working";
        }
        urlalias_dbd_acquire_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
    }

    urlalias_dbd_prepare_fn(cmd->server, QUERY_SQL, QUERY_LABEL);

    return NULL;
}

/*
 * Hook : global hook table
 */
static void url_alias_register_hooks(apr_pool_t *p)
{
    ap_hook_fixups (hook_fixup  , NULL, NULL, APR_HOOK_FIRST);
    ap_hook_handler(hook_handler, NULL, NULL, APR_HOOK_MIDDLE);
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
    NULL,                     /* create per-dir    config structures */
    NULL,                     /* merge  per-dir    config structures */
    config_server_create,     /* create per-server config structures */
    NULL,                     /* merge  per-server config structures */
    command_table,            /* table of config file commands       */
    url_alias_register_hooks  /* register hooks                      */
};