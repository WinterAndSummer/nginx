
#include <ngx_config.h>  
#include <ngx_core.h>  
#include <ngx_http.h>  
  
  
static char *  
ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);  
static void* ngx_http_mytest_create_loc_conf(ngx_conf_t *cf);
static char* ngx_conf_set_new_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char* mgx_http_mytset_merge_loc_conf(ngx_conf_t* cf, void * parent, void* child);
static void mytest_upstream_finalize_request(ngx_http_request_t*, ngx_int_t);
static ngx_int_t mytest_upstream_process_header(ngx_http_request_t*);
static ngx_int_t mytest_process_status_line(ngx_http_request_t*);
static ngx_int_t mytest_upstream_create_request(ngx_http_request_t*);

  
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r);  
/*
struct ngx_command_s {
    ngx_str_t             name;
    ngx_uint_t            type;//type是指定配置项可以出现的位置，比如出现在server{}
    //location{}中，以及其携带的参数的个数
    char               *(*set)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
	//出现了name指定的配置项时，将会调用set方法来处理配置项的参数。
    ngx_uint_t            conf;//在配置文件中的偏移量
    ngx_uint_t            offset;
    void                 *post;//配置项读取后的处理方法，必须是ngx_conf_post_t结构指针
};
*/

typedef struct {
	ngx_str_t my_config_str;
	ngx_int_t my_config_num;
} ngx_http_new_conf_t;

typedef struct{
	ngx_str_t my_str;
	ngx_int_t my_num;
	ngx_flag_t my_flag;
	size_t my_size;
	ngx_array_t* my_str_array;
	ngx_array_t* my_keyval;
	off_t my_off;
	ngx_msec_t my_msec;
	time_t my_sec;
	ngx_bufs_t my_bufs;
	ngx_uint_t my_enum_seq;
	ngx_uint_t mybitmask;
	ngx_uint_t my_access;
	ngx_path_t* my_path;
	ngx_http_new_conf_t my_new_conf;
	ngx_http_upstream_conf_t upstream;
}ngx_http_mytest_conf_t;

static ngx_conf_enum_t test_enums[] = {
	{ngx_string("apple"), 1},
	{ngx_string("banana"), 2},
	{ngx_string("orange"), 3},
	{ngx_null_string, 0}
};

//处理配置项 
//遍历模块的ngx_command_t数组，直到ngx_null_command
static ngx_command_t  ngx_http_mytest_commands[] =  
{  
  
    {  
        ngx_string("mytest"),  
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS,  
        //可以放在http{},server{}，location{},limit_except{}中，NGX_CONF_NOARGS就是没有参数
        ngx_http_mytest,  
        NGX_HTTP_LOC_CONF_OFFSET,  
        0,  
        NULL  
    },  
    {
		ngx_string("test_flag"),
		NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,//用来设置是哪个结构体来存储解析的配置参数。
		offsetof(ngx_http_mytest_conf_t, my_flag),
		NULL,
	},
	{
		ngx_string("test_str"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,//用来设置是哪个结构体来存储解析的配置参数。
		offsetof(ngx_http_mytest_conf_t, my_str),
		NULL,
	},
	{
		ngx_string("test_str_array"), //配置方式，test_str_array Content-Lenght;test_str_array Content-Encoding;
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_array_slot,
		NGX_HTTP_LOC_CONF_OFFSET,//用来设置是哪个结构体来存储解析的配置参数。
		offsetof(ngx_http_mytest_conf_t, my_str_array), 
		NULL,
	},
	{
		ngx_string("test_keyval"), //配置方式，test_keyval Content-Type image/png;test_keyval Content-Type image/gif;
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
		ngx_conf_set_keyval_slot,
		NGX_HTTP_LOC_CONF_OFFSET,//用来设置是哪个结构体来存储解析的配置参数。
		offsetof(ngx_http_mytest_conf_t, my_keyval), 
		NULL,
	},
	{
		ngx_string("test_num"), //配置方式，test_num 10;
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		NGX_HTTP_LOC_CONF_OFFSET,//用来设置是哪个结构体来存储解析的配置参数。
		offsetof(ngx_http_mytest_conf_t, my_num), 
		NULL,
	},
	{
		ngx_string("test_size"), //配置方式，test_size 10k;那么my_size就是10240字节
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_size_slot,
		NGX_HTTP_LOC_CONF_OFFSET,//用来设置是哪个结构体来存储解析的配置参数。
		offsetof(ngx_http_mytest_conf_t, my_size), 
		NULL,
	},
	{
		ngx_string("test_off"), //配置方式，test_off 10k;那么my_size就是10240字节,支持g
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_off_slot,
		NGX_HTTP_LOC_CONF_OFFSET,//用来设置是哪个结构体来存储解析的配置参数。
		offsetof(ngx_http_mytest_conf_t, my_off), 
		NULL,
	},
	{
		ngx_string("test_msec"), //配置方式，test_msec 1d;那么my_msec就是86400000毫秒
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_msec_slot,//ngx_conf_set_sec_slot代表的是s
		NGX_HTTP_LOC_CONF_OFFSET,//用来设置是哪个结构体来存储解析的配置参数。
		offsetof(ngx_http_mytest_conf_t, my_msec), 
		NULL,
	},
	{
		ngx_string("test_bufs"), //配置方式，test_bufs 4 1K;就是4个1K的缓冲区
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_bufs_slot,
		NGX_HTTP_LOC_CONF_OFFSET,//用来设置是哪个结构体来存储解析的配置参数。
		offsetof(ngx_http_mytest_conf_t, my_bufs), 
		NULL,
	},
	{
		ngx_string("test_enum"), //配置方式，test_bufs 4 1K;就是4个1K的缓冲区
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_enum_slot,
		NGX_HTTP_LOC_CONF_OFFSET,//用来设置是哪个结构体来存储解析的配置参数。
		offsetof(ngx_http_mytest_conf_t, my_enum_seq), 
		test_enums,
	},
	{
		ngx_string("test_access"), //配置方式，test_access user:rw group:rw all:r
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE123,
		ngx_conf_set_access_slot,
		NGX_HTTP_LOC_CONF_OFFSET,//用来设置是哪个结构体来存储解析的配置参数。
		offsetof(ngx_http_mytest_conf_t, my_access), 
		NULL,
	},
	{
		ngx_string("test_new_conf"), //配置方式，test_access user:rw group:rw all:r
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
		ngx_conf_set_new_conf,
		NGX_HTTP_LOC_CONF_OFFSET,//用来设置是哪个结构体来存储解析的配置参数。
		offsetof(ngx_http_mytest_conf_t, my_new_conf), 
		NULL,
	},
    ngx_null_command  
};  

typedef struct {
	ngx_uint_t my_step;
	ngx_http_status_t status;
	struct {
        u_char* data;
        ngx_uint_t len;
    } backendServer;
} ngx_http_mytest_ctx_t;

//模块上下文  
static ngx_http_module_t  ngx_http_mytest_module_ctx =  
{  
    NULL,//解析前                              /* preconfiguration */  
    NULL,//解析后                       /* postconfiguration */  
  
    NULL,//                              /* create main configuration */  
    NULL,                              /* init main configuration */  
  
    NULL,                              /* create server configuration */  
    NULL,                              /* merge server configuration */  
  
    ngx_http_mytest_create_loc_conf,   /* create location configuration */  
    mgx_http_mytset_merge_loc_conf     /* merge location configuration */  
};  
//新模块定义    
ngx_module_t  ngx_http_mytest_module =  
{  
    NGX_MODULE_V1,  
    &ngx_http_mytest_module_ctx,           /* module context */  
    ngx_http_mytest_commands,              /* module directives */  
    NGX_HTTP_MODULE,                       /* module type */  
    NULL,                                  /* init master */  
    NULL,                                  /* init module */  
    NULL,                                  /* init process */  
    NULL,                                  /* init thread */  
    NULL,                                  /* exit thread */  
    NULL,                                  /* exit process */  
    NULL,                                  /* exit master */  
    NGX_MODULE_V1_PADDING  
};  

static char* ngx_conf_set_new_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_mytest_conf_t* mycf = conf;
	ngx_str_t* value = cf->args->elts;
	if (cf->args->nelts > 1)
	{
		mycf->my_new_conf.my_config_str = value[1];
	}
	if (cf->args->nelts > 2)
	{
		mycf->my_new_conf.my_config_num = ngx_atoi(value[2].data, value[2].len);
		if (mycf->my_new_conf.my_config_num == NGX_ERROR)
		{
			return "invalid number";
		}
	}
	//可以设置ngx_errno
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, cf->log, 0, "my_config_str = %V, my_config_num = %d", 
		&mycf->my_new_conf.my_config_str, mycf->my_new_conf.my_config_num);
	return NGX_CONF_OK;
}

static void* ngx_http_mytest_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_mytest_conf_t *mycf;
	mycf = (ngx_http_mytest_conf_t*)ngx_palloc(cf->pool, sizeof(ngx_http_mytest_conf_t));
	if (mycf == NULL)
	{
		return NULL;
	}
	mycf->my_flag = NGX_CONF_UNSET;//使用这个函数必须设置
	mycf->my_num = NGX_CONF_UNSET;
	mycf->my_str_array = NGX_CONF_UNSET_PTR;
	mycf->my_keyval = NULL;
	mycf->my_off = NGX_CONF_UNSET;
	mycf->my_msec = NGX_CONF_UNSET_MSEC;
	mycf->my_sec = NGX_CONF_UNSET;
	mycf->my_size = NGX_CONF_UNSET_SIZE;

	//设置upstream相关的字段
	mycf->upstream.connect_timeout = 6000;
	mycf->upstream.send_timeout = 6000;
	mycf->upstream.read_timeout = 6000;
	mycf->upstream.store_access = 0600;
	mycf->upstream.buffering = 0;
	mycf->upstream.bufs.num = 8;
	mycf->upstream.bufs.size = ngx_pagesize;
	mycf->upstream.buffer_size = ngx_pagesize;
	mycf->upstream.busy_buffers_size = 2 * ngx_pagesize;
	mycf->upstream.temp_file_write_size = 2 * ngx_pagesize;
	mycf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
	mycf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
	mycf->upstream.pass_headers = NGX_CONF_UNSET_PTR;
	return mycf;
}

static char* mgx_http_mytset_merge_loc_conf(ngx_conf_t* cf, void * parent, void* child)
{
	ngx_http_mytest_conf_t* prev = (ngx_http_mytest_conf_t*)parent;
	ngx_http_mytest_conf_t* conf = (ngx_http_mytest_conf_t*)child;
	ngx_conf_merge_str_value(conf->my_str, prev->my_str, "defaultstr");
	return NGX_CONF_OK;
}

static ngx_int_t 
mytest_upstream_create_request(ngx_http_request_t* r)
{
	static ngx_str_t backendQueryLine = ngx_string("GET /%V HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n");
	ngx_int_t queryLineLen = backendQueryLine.len + r->args.len - 2;
	ngx_buf_t *b = ngx_create_temp_buf(r->pool, queryLineLen);
	if (b == NULL)
		return NGX_ERROR;
	b->last = b->pos + queryLineLen;
	ngx_snprintf(b->pos, queryLineLen, (char*)backendQueryLine.data, &r->args);
	r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
	if (r->upstream->request_bufs == NULL)
		return NGX_ERROR;
	r->upstream->request_bufs->buf = b;
	r->upstream->request_bufs->next = NULL;
	r->upstream->request_sent = 0;
	r->upstream->header_sent = 0;
	r->header_hash = 1;
	return NGX_OK;
}

static void
mytest_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "mytest_upstream_finalize_request");
}


static ngx_int_t
mytest_process_status_line(ngx_http_request_t *r)
{
	size_t len;
	ngx_int_t rc;
	ngx_http_upstream_t *u;
	ngx_http_mytest_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
	if (ctx == NULL) {
		return NGX_ERROR;
	}
	u = r->upstream;
	rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);
	if (rc == NGX_AGAIN) {
		return rc;
	}
	if (rc == NGX_ERROR) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent no valid HTTP/1.0 header");
		r->http_version = NGX_HTTP_VERSION_9;
		u->state->status = NGX_HTTP_OK;
		return NGX_OK;
	}
	if (u->state) {
		u->state->status = ctx->status.code;
	}
	u->headers_in.status_n = ctx->status.code;
	len = ctx->status.end - ctx->status.start;
	u->headers_in.status_line.len = len;
	u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
	if (u->headers_in.status_line.data == NULL) {
		return NGX_ERROR;
	}
	ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);
	u->process_header = mytest_upstream_process_header;
	return mytest_upstream_process_header(r);	
}

static ngx_int_t
mytest_upstream_process_header(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_table_elt_t                *h;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;
    /*这里将upstream模块配置项ngx_http_upstream_main_conf_t取出来, 目的只有一个, 就是对将要转发给下游客户端的HTTP响应头部进行统一处理。该结构体中存储了需要进行统一处理的HTTP头部名称和回调方法*/
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    // 循环地解析所有的HTTP头部
    for ( ;; ) {
        /* HTTP框架提供了基础性的ngx_http_parse_header_line方法, 它用于解析HTTP头部*/
        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
        // 返回NGX_OK时, 表示解析出一行HTTP头部
        if (rc == NGX_OK) {
            // 向headers_in.headers这个ngx_list_t链表中添加HTTP头部
            h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }
            // 下面开始构造刚刚添加到headers链表中的HTTP头部
            h->hash = r->header_hash;
            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;
            // 必须在内存池中分配存放HTTP头部的内存空间
            h->key.data = ngx_pnalloc(r->pool,
            h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                return NGX_ERROR;
            }
            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;
            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';
            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }
            // upstream模块会对一些HTTP头部做特殊处理
            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);
            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return NGX_ERROR;
            }
            continue;
        }
    /*返回NGX_HTTP_PARSE_HEADER_DONE时, 表示响应中所有的HTTP头部都解析完毕, 接下来再接收到的都将是HTTP包体*/
        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            /*如果之前解析HTTP头部时没有发现server和date头部, 那么下面会根据HTTP协议规范添加这两个头部*/
            if (r->upstream->headers_in.server == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }
                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                    ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');
                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "server";
            }
            if (r->upstream->headers_in.date == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }
                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');
                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "date";
            }
            return NGX_OK;
        }
        /*如果返回NGX_AGAIN, 则表示状态机还没有解析到完整的HTTP头部, 此时要求upstream模块继续接收新的字符流, 然后交由process_header回调方法解析*/
        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }
        // 其他返回值都是非法的
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header");
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

//配置项对应的回调函数   
static char *  
ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)  
{  
    ngx_http_core_loc_conf_t  *clcf;  
  
    //首先找到mytest配置项所属的配置块，clcf貌似是location块内的数据  
//结构，其实不然，它可以是main、srv或者loc级别配置项，也就是说在每个  
//http{}和server{}内也都有一个ngx_http_core_loc_conf_t结构体  
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);  
  
    //http框架在处理用户请求进行到NGX_HTTP_CONTENT_PHASE阶段时，如果  
//请求的主机域名、URI与mytest配置项所在的配置块相匹配，就将调用我们  
//实现的ngx_http_mytest_handler方法处理这个请求  
    clcf->handler = ngx_http_mytest_handler;  
  
    return NGX_CONF_OK;  
}  
  
//实际完成处理的回调函数 
//这里的返回值其实就是状态码，在ngx_http_request.h中定义，还包括nginx自己定义的一些值，比如NGX_HTTP_CLOSE
//（表示nginx直接关闭用户的连接）还可能是全局的错误码，NGX_OK等
//请求的所有的信息都可以在r中得到
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r)  
{  
	// 首先建立HTTP上下文结构体ngx_http_mytest_ctx_t
	ngx_http_mytest_ctx_t* myctx = ngx_http_get_module_ctx(r,ngx_http_mytest_module);
	if (myctx == NULL) {
		myctx = ngx_palloc(r->pool, sizeof(ngx_http_mytest_ctx_t));
		if (myctx == NULL) {
			return NGX_ERROR;
		}
		// 将新建的上下文与请求关联起来
		ngx_http_set_ctx(r,myctx,ngx_http_mytest_module);
	}
	/*对每1个要使用upstream的请求, 必须调用且只能调用1次ngx_http_upstream_create方法, 它会初始化r->upstream成员*/
	if (ngx_http_upstream_create(r) != NGX_OK) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"ngx_http_upstream_create() failed");
		return NGX_ERROR;
	}
	// 得到配置结构体ngx_http_mytest_conf_t
	ngx_http_mytest_conf_t	*mycf = (ngx_http_mytest_conf_t  *) ngx_http_get_module_loc_conf(r, ngx_http_mytest_module);
	ngx_http_upstream_t *u = r->upstream;
	// 这里用配置文件中的结构体来赋给r->upstream->conf成员
	u->conf = &mycf->upstream;
	// 决定转发包体时使用的缓冲区
	u->buffering = mycf->upstream.buffering;
	// 以下代码开始初始化resolved结构体, 用来保存上游服务器的地址
	u->resolved = (ngx_http_upstream_resolved_t*) ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
	if (u->resolved == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
		"ngx_pcalloc resolved error. %s.", strerror(errno));
		return NGX_ERROR;
	}
	// 这里的上游服务器就是www.google.com
	static struct sockaddr_in backendSockAddr;
	struct hostent *pHost = gethostbyname((char*) "www.google.com");
	if (pHost == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gethostbyname fail. %s", strerror(errno));
		return NGX_ERROR;
	}
	// 访问上游服务器的80端口
	backendSockAddr.sin_family = AF_INET;
	backendSockAddr.sin_port = htons((in_port_t) 8080);
	//char* pDmsIP = inet_ntoa(*(struct in_addr*) (pHost->h_addr_list[0]));
	char* pDmsIP = "127.0.0.1";
	backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
	myctx->backendServer.data = (u_char*)pDmsIP;
	myctx->backendServer.len = strlen(pDmsIP);
	// 将地址设置到resolved成员中
	u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
	u->resolved->socklen = sizeof(struct sockaddr_in);
	u->resolved->naddrs = 1;
	u->resolved->port = 80;
	// 设置3个必须实现的回调方法, 也就是5.3.3节~5.3.5节中实现的3个方法
	u->create_request = mytest_upstream_create_request;
	u->process_header = mytest_process_status_line;
	u->finalize_request = mytest_upstream_finalize_request;
	// 这里必须将count成员加1, 参见5.1.5节
	r->main->count++;
	// 启动upstream
	ngx_http_upstream_init(r);
	// 必须返回NGX_DONE
	return NGX_DONE;
}  


