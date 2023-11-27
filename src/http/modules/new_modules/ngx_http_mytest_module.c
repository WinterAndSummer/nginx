#include <ngx_config.h>  
#include <ngx_core.h>  
#include <ngx_http.h>  
  
  
static char *  
ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);  
static void* ngx_http_mytest_create_loc_conf(ngx_conf_t *cf);

  
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
	ngx_uint_t my_enum_seg;
	ngx_uint_t mybitmask;
	ngx_uint_t my_access;
	ngx_path_t* my_path;
}ngx_http_mytest_conf_t;


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
    ngx_null_command  
};  
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
    NULL                    /* merge location configuration */  
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
	return mycf;
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
    //必须是GET或者HEAD方法，否则返回405 Not Allowed  
    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))  
    {  
        return NGX_HTTP_NOT_ALLOWED;  
    }  
	//遍历头部然后将test:test
	ngx_list_part_t *part = &r->headers_in.headers.part;
	ngx_table_elt_t *header = part->elts;
	ngx_uint_t i = 0;
	for (i = 0;/*void*/; i++)
	{
		if (i >= part->nelts)
		{
			if (part->next == NULL)
			{
				break;
			}
			part = part->next;
			header = part->elts;
			i = 0;
		}
		//hash为0表示不合法的头部
		if (header[i].hash == 0)
		{
			continue;
		}
		if (ngx_strncmp(header[i].key.data , (u_char*)"test", header[i].key.len) == 0)
		{
			//判断这个值是否是test
			if (ngx_strncmp(header[i].value.data, (u_char*)"test", header[i].value.len) == 0)
			{
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
		}
	}
	
  
    //丢弃请求中的包体  
    ngx_int_t rc = ngx_http_discard_request_body(r);  
    if (rc != NGX_OK)  
    {  
        return rc;  
    }  
  
    //设置返回的Content-Type。注意，ngx_str_t有一个很方便的初始化宏  
//ngx_string，它可以把ngx_str_t的data和len成员都设置好  
    ngx_str_t type = ngx_string("text/plain");  
    //返回的包体内容  
    //ngx_str_t response = ngx_string("Hello World Hello World!");  
    //设置返回状态码  
    r->headers_out.status = NGX_HTTP_OK;  
    //响应包是有包体内容的，所以需要设置Content-Length长度  
    //r->headers_out.content_length_n = response.len;  
    //设置Content-Type  
    r->headers_out.content_type = type;  

	ngx_table_elt_t* h = ngx_list_push(&r->headers_out.headers);
	if (h == NULL)
	{
		return NGX_ERROR;
	}
	h->hash = 1;
	h->key.len = sizeof("testhead") - 1;
	h->key.data = (u_char*)"testhead";
	h->value.len = sizeof("testvalue") - 1;
	h->value.data = (u_char*)"testvalue";
	
    //构造ngx_buf_t结构准备发送包体  
//    ngx_buf_t                 *b;  
//    b = ngx_create_temp_buf(r->pool, response.len);  
//    if (b == NULL)  
//    {  
//        return NGX_HTTP_INTERNAL_SERVER_ERROR;  
//    }  
//    //将Hello World拷贝到ngx_buf_t指向的内存中  
//    ngx_memcpy(b->pos, response.data, response.len);  
//    //注意，一定要设置好last指针  
//    b->last = b->pos + response.len;  
//    //声明这是最后一块缓冲区  
//    b->last_buf = 1;  
// 
//    //构造发送时的ngx_chain_t结构体  


	//测试发送文件
	ngx_buf_t *b = ngx_palloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL)
	{
		return NGX_ERROR;
	}
	u_char* filename = (u_char*)"/tmp/test.txt";
	b->in_file = 1;
	b->file = ngx_palloc(r->pool, sizeof(ngx_file_t));
	b->file->fd = ngx_open_file(filename, NGX_FILE_RDONLY|NGX_FILE_NONBLOCK,
		NGX_FILE_OPEN, 0);
	b->file->log = r->connection->log;
	b->file->name.data = filename;
	b->file->name.len = strlen((char*)filename);
	if (b->file->fd <= 0)
	{
		return NGX_HTTP_NOT_FOUND;
	}
	if (ngx_file_info(filename, &b->file->info) == NGX_FILE_ERROR)
	{
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	r->headers_out.content_length_n = b->file->info.st_size;
	//nginx支持断点续传
	r->allow_ranges = 1;
	//发送http头部  
    rc = ngx_http_send_header(r);  
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)  
    {  
        return rc;  
    }  
	b->file_pos = 0;
	b->file_last = b->file->info.st_size;


	//下面清理句柄
	ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
	if (cln == NULL)
	{
		return NGX_ERROR;
	}
	cln->handler = ngx_pool_cleanup_file;
	ngx_pool_cleanup_file_t* clnf = cln->data;
	clnf->fd = b->file->fd;
	clnf->name = b->file->name.data;
	clnf->log = r->pool->log;

	//构造发送时的ngx_chain_t结构体  
    ngx_chain_t     out;  
    //赋值ngx_buf_t  
    out.buf = b;  
    //设置next为NULL  
    out.next = NULL; 

    //最后一步发送包体，http框架会调用ngx_http_finalize_request方法  
//结束请求  
    return ngx_http_output_filter(r, &out);  
}  


