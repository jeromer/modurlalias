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
#include "http_core.h"
#include "apr_file_info.h"

#define ENGINE_DISABLED 0
#define ENGINE_ENABLED  1

#define SQL_QUERY_PART_1 "SELECT * FROM "
#define SQL_QUERY_PART_2 " WHERE source = %s"
#define QUERY_LABEL "urlalias_stmt"

#define DIRECTORY_SEPARATOR "/"

#define REGEX_FILE_EXT_EXCLUSION "\\.(?:gif|jp[e]?g|png|ico|css|js|mp3|flv)$"
#define TABLE_NAME "urlalias"

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
    int engine_status;          /* URLAliasEngine */
    const char *table_name;     /* URLAliasTableName*/
    const char *regex;          /* URLAliasExcludeFiles */
    ap_regex_t *compiled_regex; /* Compiled version of URLAliasExcludeFiles */
} urlalias_server_config;

/*
 * Structure : global data structure declaration
 */
module AP_MODULE_DECLARE_DATA urlalias_module;

/*
 * Hook : maps the nice URL to the system one
 *
 * This function does all the source to target mapping stuff
 * and then it modifies the current requests on the fly so it
 * is handled by hook_handler for the redirection on the
 * real file.
 */
static int hook_translate_name(request_rec *r)
{
    /* The perserver configuration */
    urlalias_server_config *server_config;

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

    /* The regex execution result */
    int regexec_result = AP_REG_NOMATCH;

    /* The list of regex captures */
    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];

    /* Table's fields */
    const char *module     = NULL;
    const char *view       = NULL;
    const char *parameters = NULL;

    /* the system URL to redirect to */
    char *target = NULL;

    /* this virtual host's document root */
    const char *document_root = NULL;

    server_config = (urlalias_server_config *) ap_get_module_config(r->server->module_config, &urlalias_module);

    if (server_config->engine_status == ENGINE_DISABLED) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "URLALiasEngine is set to Off");
        return DECLINED;
    }

    regexec_result = ap_regexec(server_config->compiled_regex, r->uri, AP_MAX_REG_MATCH, regmatch, AP_REG_EXTENDED | AP_REG_ICASE | AP_REG_NOSUB);

    /* regex successfully applied */
    if (regexec_result == 0) {
        /* then this request is a binary file which is not relevant for us */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "%s must be ignored, skipping", r->uri);
        return DECLINED;
    }

    /* Extra database connection check */
    if (dbd == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unable to acquire a database connection ");
        return DECLINED;
    }

    /* This is not for us */
    if (!r->uri || strlen(r->uri) == 0) {
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

    if (apr_dbd_get_row(dbd->driver, r->pool, res, &row, 1) == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "no results found");
        return DECLINED;
    }

    /* since the source field is unique there is only one result */
    /* no need for a loop here                                   */
    module     = apr_dbd_get_entry(dbd->driver, row, 1);
    view       = apr_dbd_get_entry(dbd->driver, row, 2);
    parameters = apr_dbd_get_entry(dbd->driver, row, 3);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "module     : %s", module);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "view       : %s", view);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "parameters : %s", parameters);

    /* assembling the module/view URL and creating the absolute path to it */
    document_root = ap_document_root(r);
    target = apr_pstrcat(r->pool,
                         document_root,
                         DIRECTORY_SEPARATOR, module,
                         DIRECTORY_SEPARATOR, view,
                         NULL);

    r->filename = apr_pstrdup(r->pool, ap_os_escape_path(r->pool, target, 1));

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "ap_document_root : %s", ap_document_root(r));
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
    if (r->filename[0] != '/' && !ap_os_is_path_absolute(r->pool, r->filename)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "non absolute path : %s", r->filename);
        return HTTP_BAD_REQUEST;
    }

    /* now we redirect internally to the real filename */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "internal redirect from %s to %s ", r->uri, r->filename);

    return OK;
}

/*
 * Conf : creates and initializes per <VirtualHost> configuration structure
 */
static void *config_server_create(apr_pool_t *p, server_rec *s)
{
    ap_regex_t *compiled_regex = NULL;
    urlalias_server_config *server_config;

    server_config = (urlalias_server_config *) apr_pcalloc(p, sizeof(urlalias_server_config));

    server_config->engine_status  = ENGINE_DISABLED;
    server_config->table_name     = TABLE_NAME;
    server_config->regex          = REGEX_FILE_EXT_EXCLUSION;

    compiled_regex = ap_pregcomp(p, REGEX_FILE_EXT_EXCLUSION, AP_REG_EXTENDED | AP_REG_ICASE | AP_REG_NOSUB);
    server_config->compiled_regex = compiled_regex;

    return (void *)server_config;
}

/*
 * Conf : engine state, On or Off
 */
static const char *cmd_urlaliasengine(cmd_parms *cmd, void *in_directory_config, int flag)
{
    const char *sql_query = NULL;
    urlalias_server_config *server_config;

    server_config    = ap_get_module_config(cmd->server->module_config, &urlalias_module);

    if (cmd->path == NULL) {
        /* <VirtualHost> configuration */
        server_config->engine_status = (flag ? ENGINE_ENABLED : ENGINE_DISABLED);
    }

    /* Fetching needed function pointers */
    if (urlalias_dbd_prepare_fn == NULL) {
        urlalias_dbd_prepare_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_prepare);
        if (urlalias_dbd_prepare_fn == NULL) {
            return "mod_dbd must be enabled in order to get mod_url_alias working";
        }
        urlalias_dbd_acquire_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
    }

    sql_query = apr_pstrcat(cmd->pool, SQL_QUERY_PART_1, server_config->table_name, SQL_QUERY_PART_2, NULL);
    urlalias_dbd_prepare_fn(cmd->server, sql_query, QUERY_LABEL);

    return NULL;
}

/*
 * Conf : table name
 */
static const char *cmd_urlaliastablename(cmd_parms *cmd, void *in_directory_config, const char *table_name)
{
    urlalias_server_config *server_config;

    server_config = ap_get_module_config(cmd->server->module_config, &urlalias_module);

    if (cmd->path == NULL && strlen(table_name) > 0) {
        /* <VirtualHost> configuration */
        server_config->table_name = table_name;
    }

    return NULL;
}

/*
 * Conf : exclude files
 */
static const char *cmd_urlaliasexcludefiles(cmd_parms *cmd, void *in_directory_config, const char *user_regex)
{
    ap_regex_t *compiled_regex = NULL;
    urlalias_server_config *server_config;

    server_config = ap_get_module_config(cmd->server->module_config, &urlalias_module);

    if (cmd->path == NULL && strlen(user_regex) > 0) {
        /* <VirtualHost> configuration */

        /* Is this regular expression valid ? */
        compiled_regex = ap_pregcomp(cmd->pool, user_regex, AP_REG_EXTENDED | AP_REG_ICASE | AP_REG_NOSUB);

        if (!compiled_regex) {
            return "Unable to compile URLAliasExcludeFiles regex, please check that the regular expression is correct";
        }

        server_config->regex          = user_regex;
        server_config->compiled_regex = compiled_regex;
    }

    return NULL;
}
/*
 * Hook : global hook table
 */
static void url_alias_register_hooks(apr_pool_t *p)
{
    ap_hook_translate_name(hook_translate_name, NULL, NULL, APR_HOOK_FIRST);
}

/*
 * Conf : configuration directives declaration
 */
static const command_rec command_table[] = {

    AP_INIT_TAKE1( "URLAliasExcludeFiles",
                   cmd_urlaliasexcludefiles,
                   NULL,
                   OR_FILEINFO,
                   "A regular expression which defines which files to ignore, default : .(?:gif|jp[e]?g|png|ico|css|js|mp3|flv)$"),

    AP_INIT_TAKE1( "URLAliasTableName",
                   cmd_urlaliastablename,
                   NULL,
                   OR_FILEINFO,
                   "The name of the table which stores URL aliases, default 'urlalias'"),

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