/**
 * Copyright 2009 Jérôme Renard jerome.renard@gmail.com
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
 * +----------------+--------------+------+-----+---------+-------+
 * | Field          | Type         | Null | Key | Default | Extra |
 * +----------------+--------------+------+-----+---------+-------+
 * | source         | varchar(200) | NO   | PRI |         |       | 
 * | redirect_to    | varchar(200) | YES  |     | NULL    |       | 
 * | http_code      | char(3)      | NO   |     | 301     |       | 
 * | module         | varchar(30)  | NO   |     |         |       | 
 * | view           | varchar(30)  | NO   |     |         |       | 
 * | parameters     | varchar(200) | NO   |     |         |       | 
 * | generic_route  | tinyint(1)   | NO   |     | 0       |       | 
 * | route_priority | tinyint(4)   | YES  | UNI | NULL    |       | 
 * +----------------+--------------+------+-----+---------+-------+
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

#define SQL_SELECT_URL_ALIAS_QUERY_PART_1 "SELECT * FROM "
#define SQL_SELECT_URL_ALIAS_QUERY_PART_2 " WHERE source = %s"
#define SQL_SELECT_URL_ALIAS_QUERY_PART_3 " WHERE generic_route = 1 ORDER BY route_priority"
#define QUERY_LABEL "urlalias_stmt"
#define QUERY_LABEL_GENERIC_ROUTE "urlalias_generic_route_stmt"

#define DIRECTORY_SEPARATOR "/"

#define REGEX_FILE_EXT_EXCLUSION "\\.(?:gif|jp[e]?g|png|ico|css|js|mp3|flv)$"
#define TABLE_NAME "urlalias"

#define SERVER_VARIABLE_NAME "URL_ALIAS_PARAMS"

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
    int engine_status;            /* URLAliasEngine */
    const char *table_name;       /* URLAliasTableName*/
    const char *regex;            /* URLAliasExcludeFiles */
    const char *installation_key; /* URLAliasInstallationKey */

    ap_regex_t *compiled_regex;   /* Compiled version of URLAliasExcludeFiles */
} urlalias_server_config;

/*
 * Structure : the per-child cache
 */
typedef struct generic_route_cache {
    apr_pool_t         *pool;
    apr_hash_t         *cache_item_list;
#if APR_HAS_THREADS
    apr_thread_mutex_t *mutex;
#endif
    /* Flag 0|1 to know if the cached has already been generated or not */
    int cache_generated;
} generic_route_cache;

/*
 * Structure : cache item for each generic route
 *
 * This structure is a child of the generic_route_cache
 *
 * generic_route_cache
 *      |
 *      + cache_item_list
 *            |
 *            + route_cache_item
 *                   | - generic_route
 *                   | - module
 *                   | - view
 *                   | - parameters
 *
 */
typedef struct {
    const char *generic_route;
    const char *module;
    const char *view;
    const char *parameters;

    /* Compiled version of the generic route */
    ap_regex_t *compiled_gr;
} route_cache_item;

/*
 * Structure : global data structure declaration
 */
module AP_MODULE_DECLARE_DATA urlalias_module;

/*
 * The cache
 */
static generic_route_cache *generic_route_cache_p;

/* {{{ caching support */

/*
 * Helper : creates the per child generic route cache
 */
static int init_cache(apr_pool_t *pchild, server_rec *svr)
{
    apr_status_t rv;
    generic_route_cache_p = apr_palloc(pchild, sizeof(generic_route_cache));

    rv = apr_pool_create(&generic_route_cache_p->pool, pchild);

    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, pchild, "Failed to create subpool, cache is disabled");
        generic_route_cache_p = NULL;
        return 1;
    }

#if APR_HAS_THREADS
    rv = apr_thread_mutex_create(&generic_route_cache_p->mutex, APR_THREAD_MUTEX_DEFAULT, pchild);

    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, rv, pchild, "Failed to create mutex lock, cache is disabled");
        generic_route_cache_p = NULL;
        return 1;
    }
#endif

#ifdef URL_ALIAS_DEBUG_ENABLED
    ap_log_error(APLOG_MARK, APLOG_DEBUG, rv, svr, "Subpool and mutex created successfully");
#endif

    generic_route_cache_p->cache_item_list = apr_hash_make(generic_route_cache_p->pool);
    generic_route_cache_p->cache_generated = 0;

    return APR_SUCCESS;
}

/*
 * Helper : stores a generic route in the per child cache
 */
static int set_cache_value( request_rec *r,
                            const char *key,
                            const char *module,
                            const char *view,
                            const char *parameters)
{
    route_cache_item *cache_item;
    ap_regex_t *compiled_regex = NULL;

    if (generic_route_cache_p) {

#if APR_HAS_THREADS
        apr_thread_mutex_lock(generic_route_cache_p->mutex);
#endif

        cache_item = apr_hash_get(generic_route_cache_p->cache_item_list, key, APR_HASH_KEY_STRING);

        /* This item does not exist */
        if (cache_item == NULL) {

            cache_item = (route_cache_item *) apr_palloc(generic_route_cache_p->pool, sizeof(route_cache_item));

#ifdef URL_ALIAS_DEBUG_ENABLED
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Compiling : %s", key);
#endif
            compiled_regex = ap_pregcomp(generic_route_cache_p->pool, key, AP_REG_EXTENDED | AP_REG_ICASE);

            if (!compiled_regex) {
                /* ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Unable to compile generic route : %s", key); */
                return 1;
            }

            cache_item->generic_route = apr_pstrdup(generic_route_cache_p->pool, key);
            cache_item->module        = apr_pstrdup(generic_route_cache_p->pool, module);
            cache_item->view          = apr_pstrdup(generic_route_cache_p->pool, view);
            cache_item->parameters    = apr_pstrdup(generic_route_cache_p->pool, parameters);
            cache_item->compiled_gr   = compiled_regex;

            apr_hash_set(generic_route_cache_p->cache_item_list,
                         apr_pstrdup(generic_route_cache_p->pool, key),
                         APR_HASH_KEY_STRING,
                         cache_item);

        }

#if APR_HAS_THREADS
        apr_thread_mutex_unlock(generic_route_cache_p->mutex);
#endif
    }

    return APR_SUCCESS;
}

#ifdef URL_ALIAS_DEBUG_ENABLED
/*
 * Helper : Dumps route map cache contents
 */
static void dump_cache_contents(request_rec *r)
{
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Current cache contents : ");

    apr_hash_index_t *hi;

    for (hi = apr_hash_first(generic_route_cache_p->pool, generic_route_cache_p->cache_item_list);
         hi;
         hi = apr_hash_next(hi)){
        const char *key;
        void *val;
        route_cache_item *cache_item;

        apr_hash_this(hi, (void*) &key, NULL, &val);
        cache_item = val;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "key : %s", key);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cache_item->generic_route : %s", cache_item->generic_route);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cache_item->module        : %s", cache_item->module);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cache_item->view          : %s", cache_item->view);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "cache_item->parameters    : %s", cache_item->parameters);
    }

    return;
}
#endif

/* }}} */

/* {{{ SQL query support */

/*
 * Helper : generates the SQL query depending on
 *          the context : generic route or not
 */
static const char *gen_sql_query(apr_pool_t *p, urlalias_server_config *server_config, char *query_type)
{
    if (strcmp(query_type, "generic_routes") == 0) {
        return apr_pstrcat(p, SQL_SELECT_URL_ALIAS_QUERY_PART_1, server_config->table_name, SQL_SELECT_URL_ALIAS_QUERY_PART_3, NULL);
    }

    return apr_pstrcat(p, SQL_SELECT_URL_ALIAS_QUERY_PART_1, server_config->table_name, SQL_SELECT_URL_ALIAS_QUERY_PART_2, NULL);
}

/* }}} */

/* {{{ Misc helpers */

/*
 * Helper : checks if a redirection is needed for the current URI
 *
 */
static int must_redirect(request_rec *r, const char *redirect_to)
{
    if (redirect_to != NULL) {
#ifdef URL_ALIAS_DEBUG_ENABLED
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Must redirect to : %s", redirect_to);
#endif
        r->filename = apr_pstrdup(r->pool, redirect_to);
        apr_table_setn(r->headers_out, "Location", r->filename);
        return 1;
    }

    return 0;
}

/*
 * Helper : checks if we must exclude this URI as configured
 *          in URLAliasExcludeFiles
 */
static int must_ignore_uri(request_rec *r, urlalias_server_config *server_config)
{
    /* The regex execution result */
    int regexec_result = AP_REG_NOMATCH;

    /* The list of regex captures */
    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];

    regexec_result = ap_regexec(server_config->compiled_regex, r->uri, AP_MAX_REG_MATCH, regmatch, AP_REG_EXTENDED | AP_REG_ICASE | AP_REG_NOSUB);

    /* regex successfully applied */
    if (regexec_result == 0) {
#ifdef URL_ALIAS_DEBUG_ENABLED
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "%s must be ignored, skipping", r->uri);
#endif
        return 1;
    }

    return 0;
}

/*
 * Helper : creates the absolute path of the target
 */
static const char *gen_target_path(request_rec *r, const char *module, const char *view)
{
    /* this virtual host's document root */
    const char *document_root = NULL;

    /* the system URL to redirect to */
    char *target = NULL;

    document_root = ap_document_root(r);
    target = apr_pstrcat(r->pool,
                         document_root,
                         DIRECTORY_SEPARATOR, module,
                         DIRECTORY_SEPARATOR, view,
                         NULL);

    return target;
}

static int check_deadloop_and_absolute_path(request_rec *r, const char *target)
{
    /* avoid deadlooping */
    if (strcmp(r->uri, target) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "deadlooping URI : %s on target : %s ", r->uri, target);
        return 1;
    }

    /* the filename must be either an absolute local path or an
    * absolute local URL.
    */
    if (r->filename[0] != '/' && !ap_os_is_path_absolute(r->pool, r->filename)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "non absolute path : %s", r->filename);
        return 1;
    }

    return APR_SUCCESS;
}

static void inject_server_variable(request_rec *r, const char *name, const char *value)
{
    /* makes it possible to use the http://php.net/apache_note function */
    apr_table_set(r->notes, name, value);

    /* available via $_SERVER as well */
    apr_table_set(r->subprocess_env, name, value);
}
/* }}} */

/*
 * Hook : initializes the per child cache struct
 */
static void hook_child_init(apr_pool_t *pchild, server_rec *svr)
{
    apr_status_t rv;

    rv = init_cache(pchild, svr);

    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_ERR, rv, pchild, "An error occured during child_init");
    }
}

/*
 * Hook : populates the cache with pre compiled generic routes
 *        the cache will be populated only once
 */
static int hook_post_read_request(request_rec *r)
{
    /* The cache has already been generated */
    if (generic_route_cache_p->cache_generated == 1) {
#ifdef URL_ALIAS_DEBUG_ENABLED
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Cache already generated, skipping");

        dump_cache_contents(r);
#endif
        return OK;
    }

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

    /* Table's fields */
    const char *generic_route = NULL;
    const char *module        = NULL;
    const char *view          = NULL;
    const char *parameters    = NULL;

    apr_status_t rv;

    server_config = (urlalias_server_config *) ap_get_module_config(r->server->module_config, &urlalias_module);

    if (server_config->engine_status == ENGINE_DISABLED) {
#ifdef URL_ALIAS_DEBUG_ENABLED
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "URLALiasEngine is set to Off");
#endif
        return DECLINED;
    }

    /* Extra database connection check */
    if (dbd == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unable to acquire a database connection ");
        return DECLINED;
    }

    prepared_stmt = apr_hash_get(dbd->prepared, QUERY_LABEL_GENERIC_ROUTE, APR_HASH_KEY_STRING);

    /* the prepared statement disapearred */
    if (prepared_stmt == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "A prepared statement could not be found");
        return DECLINED;
    }

#ifdef URL_ALIAS_DEBUG_ENABLED
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Populating cache with generic routes");
#endif

    select_error_code = apr_dbd_pvselect(dbd->driver, r->pool, dbd->handle, &res,
                                         prepared_stmt, 0, NULL);

    if (select_error_code != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Query execution error looking up '%s' in database", r->uri);
        return DECLINED;
    }

    while (apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1) == 0) {
        /* a generic route is a "source" field with the generic_route flag set to 1 */
        generic_route = apr_dbd_get_entry(dbd->driver, row, 0);

        /* TODO : escape the '&' char */
        module     = apr_dbd_get_entry(dbd->driver, row, 3);
        view       = apr_dbd_get_entry(dbd->driver, row, 4);
        parameters = apr_dbd_get_entry(dbd->driver, row, 5);

#ifdef URL_ALIAS_DEBUG_ENABLED
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "generic route : %s", generic_route);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "parameters : %s", parameters);
#endif

        /*
         * Storing the generic route in the cache for future use
         * This should avoid fetching all the generic routes for each request
         * and thus save a few SQL queries.
         */
        rv = set_cache_value(r, generic_route, module, view, parameters);

        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Unable to store generic route '%s' in the cache", generic_route);
            continue;
        }
    }

    generic_route_cache_p->cache_generated = 1;

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
    /* const char *generic_route = NULL; */
    const char *redirect_to   = NULL;
    const char *http_code     = NULL;
    const char *module        = NULL;
    const char *view          = NULL;
    const char *parameters    = NULL;

    /* the system URL to redirect to */
    const char *target = NULL;

    apr_status_t rv;

    /* the cached generic routes */
    apr_hash_index_t *hi_first = apr_hash_first(generic_route_cache_p->pool, generic_route_cache_p->cache_item_list);
    apr_hash_index_t *hi;

    server_config = (urlalias_server_config *) ap_get_module_config(r->server->module_config, &urlalias_module);

    if (server_config->engine_status == ENGINE_DISABLED) {
#ifdef URL_ALIAS_DEBUG_ENABLED
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "URLALiasEngine is set to Off");
#endif
        return DECLINED;
    }

    /* This is not for us */
    if (!r->uri || strlen(r->uri) == 0) {
        return DECLINED;
    }

    if (must_ignore_uri(r, server_config)) {
        return DECLINED;
    }

    /* Extra database connection check */
    if (dbd == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unable to acquire a database connection ");
        return DECLINED;
    }

#ifdef URL_ALIAS_DEBUG_ENABLED
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "r->uri : %s", r->uri);
#endif

    /* ap_regex_t *compiled_regex = NULL; */

    for (hi = hi_first; hi; hi = apr_hash_next(hi)) {
        const char *key;
        void *val;
        route_cache_item *cache_item;

        apr_hash_this(hi, (void*) &key, NULL, &val);
        cache_item = val;

        regexec_result = ap_regexec(cache_item->compiled_gr, r->uri, AP_MAX_REG_MATCH, regmatch, AP_REG_EXTENDED | AP_REG_ICASE);

        if (regexec_result == 0) {
#ifdef URL_ALIAS_DEBUG_ENABLED
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "%s succesfully applied on %s", cache_item->generic_route, r->uri);
#endif

            const char *subs;
            subs = ap_pregsub(r->pool, cache_item->parameters, r->uri, AP_MAX_REG_MATCH, regmatch);
#ifdef URL_ALIAS_DEBUG_ENABLED
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "subs : %s", subs);
#endif

            /* assembling the module/view URL and creating the absolute path to it */
            target = gen_target_path(r, cache_item->module, cache_item->view);
            r->filename = apr_pstrdup(r->pool, ap_os_escape_path(r->pool, target, 1));

#ifdef URL_ALIAS_DEBUG_ENABLED
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "ap_document_root : %s", ap_document_root(r));
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "target : %s", target);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "r->filename : %s", r->filename);
#endif

            /* adding parameters to our request */
            r->args = apr_pstrdup(r->pool, subs);

#ifdef URL_ALIAS_DEBUG_ENABLED
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "r->args : %s", r->args);
#endif

            rv = check_deadloop_and_absolute_path(r, target);

            if (rv != APR_SUCCESS) {
                return HTTP_BAD_REQUEST;
            }

            /* adds $_SERVER variable to the script */
            inject_server_variable(r, SERVER_VARIABLE_NAME, subs);

#ifdef URL_ALIAS_DEBUG_ENABLED
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "internal redirect from %s to %s ", r->uri, r->filename);
#endif

            return OK;
        }
    }

    prepared_stmt = apr_hash_get(dbd->prepared, QUERY_LABEL, APR_HASH_KEY_STRING);

    /* the prepared statement disapearred */
    if (prepared_stmt == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "A prepared statement could not be found");
        return DECLINED;
    }

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
#ifdef URL_ALIAS_DEBUG_ENABLED
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "no results found");
#endif
        return DECLINED;
    }

    /* since the source field is unique there is only one result */
    /* no need for a loop here                                   */
    redirect_to = apr_dbd_get_entry(dbd->driver, row, 1);
    http_code   = apr_dbd_get_entry(dbd->driver, row, 2);
    module      = apr_dbd_get_entry(dbd->driver, row, 3);
    view        = apr_dbd_get_entry(dbd->driver, row, 4);
    parameters  = apr_dbd_get_entry(dbd->driver, row, 5);

#ifdef URL_ALIAS_DEBUG_ENABLED
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "redirect_to : %s", redirect_to);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "http_code   : %s", http_code);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "module      : %s", module);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "view        : %s", view);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "parameters  : %s", parameters);
#endif

    /* If a redirection must be done, let's do it now */
    if (must_redirect(r, redirect_to)) {
        /* all the redirection work is done in must_redirect */
        return atoi(http_code);
    }

    /* assembling the module/view URL and creating the absolute path to it */
    target = gen_target_path(r, module, view);
    r->filename = apr_pstrdup(r->pool, ap_os_escape_path(r->pool, target, 1));

#ifdef URL_ALIAS_DEBUG_ENABLED
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "ap_document_root : %s", ap_document_root(r));
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "target : %s", target);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "r->filename : %s", r->filename);
#endif

    /* adding parameters to our request */
    r->args = apr_pstrdup(r->pool, parameters);

#ifdef URL_ALIAS_DEBUG_ENABLED
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "r->args : %s", r->args);
#endif

    rv = check_deadloop_and_absolute_path(r, target);

    if (rv != APR_SUCCESS) {
        return HTTP_BAD_REQUEST;
    }

    /* adds $_SERVER variable to the script */
    inject_server_variable(r, SERVER_VARIABLE_NAME, parameters);

#ifdef URL_ALIAS_DEBUG_ENABLED
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "internal redirect from %s to %s ", r->uri, r->filename);
#endif

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

    server_config->engine_status    = ENGINE_DISABLED;
    server_config->table_name       = TABLE_NAME;
    server_config->regex            = REGEX_FILE_EXT_EXCLUSION;
    server_config->installation_key = NULL;

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

    /* The sstandard SQL query */
    sql_query = gen_sql_query(cmd->pool, server_config, "standard_query");
    urlalias_dbd_prepare_fn(cmd->server, sql_query, QUERY_LABEL);

    /* The generic routes SQL query */
    sql_query = gen_sql_query(cmd->pool, server_config, "generic_routes");
    urlalias_dbd_prepare_fn(cmd->server, sql_query, QUERY_LABEL_GENERIC_ROUTE);

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
 * Conf : installation key
 */
static const char *cmd_urlaliasinstallationkey(cmd_parms *cmd, void *in_directory_config, const char *user_installation_key)
{
    urlalias_server_config *server_config;

    server_config = ap_get_module_config(cmd->server->module_config, &urlalias_module);

    if (cmd->path == NULL && strlen(user_installation_key) > 0) {
        /* <VirtualHost> configuration */
        server_config->installation_key = user_installation_key;
    }

    return NULL;
}

/*
 * Hook : global hook table
 */
static void url_alias_register_hooks(apr_pool_t *p)
{
    ap_hook_child_init(hook_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(hook_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_translate_name(hook_translate_name, NULL, NULL, APR_HOOK_MIDDLE);
}

/*
 * Conf : configuration directives declaration
 */
static const command_rec command_table[] = {

    AP_INIT_TAKE1( "URLAliasInstallationKey",
                   cmd_urlaliasinstallationkey,
                   NULL,
                   RSRC_CONF,
                   "A unique string which is used as an installation key"),

    AP_INIT_TAKE1( "URLAliasExcludeFiles",
                   cmd_urlaliasexcludefiles,
                   NULL,
                   RSRC_CONF,
                   "A regular expression which defines which files to ignore, default : .(?:gif|jp[e]?g|png|ico|css|js|mp3|flv)$"),

    AP_INIT_TAKE1( "URLAliasTableName",
                   cmd_urlaliastablename,
                   NULL,
                   RSRC_CONF,
                   "The name of the table which stores URL aliases, default 'urlalias'"),

    AP_INIT_FLAG( "URLAliasEngine",
                  cmd_urlaliasengine,
                  NULL,
                  RSRC_CONF,
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

/*
 * vim: sw=4 ts=4 fdm=marker
 */