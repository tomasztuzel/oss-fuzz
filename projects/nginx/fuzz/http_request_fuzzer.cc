// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "http_request_proto.pb.h"
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"

static char configuration[] =
"error_log error-log-main emerg;\n"
"events {\n"
"    use epoll;\n"
"    worker_connections 2;\n"
"    multi_accept off;\n"
"    accept_mutex off;\n"
"}\n"
"http {\n"
"    server_tokens off;\n"
"    default_type application/octet-stream;\n"
"    map $http_upgrade $connection_upgrade {\n"
"      default upgrade;\n"
"      '' close;\n"
"    }\n"
"    error_log error-log-http emerg;\n"
"    access_log off;\n"
"    map $subdomain $nss {\n"
"      default local_upstream;\n"
"    }\n"
"    upstream local_upstream {\n"
"      server 127.0.0.1:1010 max_fails=0;\n"
"      server 127.0.0.1:1011 max_fails=0;\n"
"      server 127.0.0.1:1012 max_fails=0;\n"
"      server 127.0.0.1:1013 max_fails=0;\n"
"      server 127.0.0.1:1014 max_fails=0;\n"
"      server 127.0.0.1:1015 max_fails=0;\n"
"      server 127.0.0.1:1016 max_fails=0;\n"
"      server 127.0.0.1:1017 max_fails=0;\n"
"      server 127.0.0.1:1018 max_fails=0;\n"
"      server 127.0.0.1:1019 max_fails=0;\n"
"    }\n"
"    client_max_body_size 256M;\n"
"    client_body_temp_path /tmp/;\n"
"    proxy_temp_path /tmp/;\n"
"    proxy_buffer_size 24K;\n"
"    proxy_max_temp_file_size 0;\n"
"    proxy_buffers 8 4K;\n"
"    proxy_busy_buffers_size 28K;\n"
"    proxy_buffering off;\n"
"    server {\n"
"      listen unix:nginx.sock;\n"
"      server_name ~^(?<subdomain>.+)\\.url.com$;\n"
"      proxy_next_upstream off;\n"
"      proxy_read_timeout 5m;\n"
"      proxy_http_version 1.1;\n"
"      proxy_set_header Host $http_host;\n"
"      proxy_set_header X-Real-IP $remote_addr;\n"
"      proxy_set_header X-Real-Port $remote_port;\n"
"      location / {\n"
"        proxy_pass http://$nss;\n"
"        proxy_set_header Host $http_host;\n"
"        proxy_set_header X-Real-IP $remote_addr;\n"
"        proxy_set_header X-Real-Port $remote_port;\n"
"        proxy_set_header Connection '';\n"
"        chunked_transfer_encoding off;\n"
"        proxy_buffering off;\n"
"        proxy_cache off;\n"
"      }\n"
"    }\n"
"}\n"
"\n";


static ngx_cycle_t *cycle;
static ngx_log_t ngx_log;
static ngx_open_file_t ngx_log_file;
static char *my_argv[2];
static char arg1[] = {0, 0xA, 0};

extern char **environ;
static char **ngx_os_environ;

static const char *config_file = "http_config.conf";

struct fuzzing_data {
  const uint8_t *data;
  size_t data_len;
};

static struct fuzzing_data request;
static struct fuzzing_data reply;

static ngx_http_upstream_t *upstream;
static ngx_http_request_t *req_reply;
static ngx_http_cleanup_t cln_new = {};
static int cln_added;

static std::string slash_to_string(int slash) {
  if (slash == HttpProto::NONE)
    return "";
  if (slash == HttpProto::FORWARD)
    return "/";
  if (slash == HttpProto::BACKWARD) {
    return "\\";
  }
  assert(false && "Received unexpected value for slash");

  // Silence compiler warning about not returning in non-void function.
  return "";
}

static std::string method_to_string(uint32_t method) {
  switch (method) {
    case 0:
      return "GET"; // Space at end in ngx_http_parse.c
    case 1:
      return "PUT"; // Space at end in ngx_http_parse.c
    case 2:
      return "POST";
    case 3:
      return "COPY";
    case 4:
      return "MOVE";
    case 5:
      return "LOCK";
    case 6:
      return "HEAD";
    case 7:
      return "MKCOL";
    case 8:
      return "PATCH";
    case 9:
      return "TRACE";
    case 10:
      return "DELETE";
    case 11:
      return "UNLOCK";
    case 12:
      return "OPTIONS"; // Space at end in ngx_http_parse.c
    case 13:
      return "PROPFIND";
    case 14:
      return "PROPPATCH";
    default:
      assert(false && "Received unexpected value for slash");
  }

  // Silence compiler warning about not returning in non-void function.
  return "";
}

// Converts a URL in Protocol Buffer format to a url in string format.
// Since protobuf is a relatively simple format, fuzzing targets that do not
// accept protobufs (such as this one) will require code to convert from
// protobuf to the accepted format (string in this case).
static std::string url_protobuf_to_string(const Url& url) {
  // Build url_string piece by piece from url and then return it.
  std::string url_string = std::string("");

  if (url.has_scheme()) {  // Get the scheme if Url has it.
    // Append the scheme to the url. This may be empty. Then append a colon
    // which is mandatory if there is a scheme.
    url_string += url.scheme() + ":";
  }

  // Just append the slashes without doing validation, since it would be too
  // complex. libFuzzer will hopefully figure out good values.
  for (const int slash : url.slashes())
    url_string += slash_to_string(slash);

  // Get host. This is simple since hosts are simply strings according to our
  // definition.
  if (url.has_host()) {
    // Get userinfo if libFuzzer set it. Ensure that user is seperated
    // from the password by ":" (if a password is included) and that userinfo is
    // separated from the host by "@".
    if (url.has_userinfo()) {
      url_string += url.userinfo().user();
      if (url.userinfo().has_password()) {
        url_string += ":";
        url_string += url.userinfo().password();
      }
      url_string += "@";
    }
    url_string += url.host();

    // As explained in url.proto, if libFuzzer included a port in url ensure
    // that it is preceded by the host and then ":".
    if (url.has_port())
      // Convert url.port() from an unsigned 32 bit int before appending it.
      url_string += ":" + std::to_string(url.port());
  }

  // Append the path segments to the url, with each segment separated by
  // the path_separator.
  bool first_segment = true;
  std::string path_separator = slash_to_string(url.path_separator());
  for (const std::string& path_segment : url.path()) {
    // There does not need to be a path, but if there is a path and a host,
    // ensure the path begins with "/".
    if (url.has_host() && first_segment) {
      url_string += "/" + path_segment;
      first_segment = false;
    } else
      url_string += path_separator + path_segment;
  }

  // Queries must be started by "?". If libFuzzer included a query in url,
  // ensure that it is preceded by "?". Also Seperate query components with
  // ampersands as is the convention.
  bool first_component = true;
  for (const std::string& query_component : url.query()) {
    if (first_component) {
      url_string += "?" + query_component;
      first_component = false;
    } else
      url_string += "&" + query_component;
  }

  // Fragments must be started by "#". If libFuzzer included a fragment
  // in url, ensure that it is preceded by "#".
  if (url.has_fragment())
    url_string += "#" + url.fragment();

  return url_string;
}

static void request_protobuf_to_string(const HttpRequest& httprequest, std::string * req) {
  *req += method_to_string(httprequest.method());
  *req += " "; // XXX XXX CRLF
  *req += url_protobuf_to_string(httprequest.url());
  *req += " HTTP/";
  *req += std::to_string(httprequest.version());
  *req += "\\r\\n";

  for (const std::string& i : httprequest.field()) {
    *req += i;
    *req += "\\r\\n";
  }

  if (httprequest.has_body()) {
    *req += httprequest.body();
    *req += "\\r\\n";
  }
}

static void reply_protobuf_to_string(const HttpReply& httpreply, std::string * rep) {
  *rep += "HTTP/";
  *rep += std::to_string(httpreply.version());
  *rep += " ";
  *rep += httpreply.statusstr();
  *rep += "\\r\\n";

  for (const std::string& i : httpreply.field()) {
    *rep += i;
    *rep += "\\r\\n";
  }

  if (httpreply.has_body()) {
    *rep += httpreply.body();
    *rep += "\\r\\n";
  }
}

// Called when finalizing the request to upstream
// Do not need to clean the request pool
static void cleanup_reply(void *data) { req_reply = NULL; }

// Called by the http parser to read the buffer
static ssize_t request_recv_handler(ngx_connection_t *c, u_char *buf,
                                    size_t size) {
  if (request.data_len < size)
    size = request.data_len;
  memcpy(buf, request.data, size);
  request.data += size;
  request.data_len -= size;
  c->read->ready = 0;
  c->read->eof = 1;
  return size;
}

// Feed fuzzing input for the reply from upstream
static ssize_t reply_recv_handler(ngx_connection_t *c, u_char *buf,
                                  size_t size) {
  req_reply = (ngx_http_request_t *)(c->data);
  if (!cln_added) { // add cleanup so that we know whether everything is cleanup
                    // correctly
    cln_added = 1;
    cln_new.handler = cleanup_reply;
    cln_new.next = req_reply->cleanup;
    cln_new.data = NULL;
    req_reply->cleanup = &cln_new;
  }
  upstream = req_reply->upstream;

  if (reply.data_len < size)
    size = reply.data_len;
  memcpy(buf, reply.data, size);
  reply.data += size;
  reply.data_len -= size;
  if (size == 0)
    c->read->ready = 0;
  return size;
}

static ngx_int_t add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags) {
  return NGX_OK;
}

static ngx_int_t init_event(ngx_cycle_t *cycle, ngx_msec_t timer) {
  return NGX_OK;
}

// Used when sending data, do nothing
static ngx_chain_t *send_chain(ngx_connection_t *c, ngx_chain_t *in,
                               off_t limit) {
  c->read->ready = 1;
  c->recv = reply_recv_handler;
  return in->next;
}

// Create a base state for Nginx without starting the server
extern "C" int InitializeNginx(void) {
  ngx_log_t *log;
  ngx_cycle_t init_cycle;
  ngx_core_conf_t *ccf;

  if (access("nginx.sock", F_OK) != -1) {
    remove("nginx.sock");
  }

  ngx_debug_init();
  ngx_strerror_init();
  ngx_time_init();
  ngx_regex_init();

  // Just output logs to stderr
  ngx_log.file = &ngx_log_file;
  ngx_log.log_level = NGX_LOG_EMERG;
  ngx_log_file.fd = ngx_stderr;
  log = &ngx_log;

  ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
  init_cycle.log = log;
  ngx_cycle = &init_cycle;

  init_cycle.pool = ngx_create_pool(1024, log);

  // Set custom argv/argc
  my_argv[0] = arg1;
  my_argv[1] = NULL;
  ngx_argv = ngx_os_argv = my_argv;
  ngx_argc = 0;

  // Weird trick to free a leaking buffer always caught by ASAN
  // We basically let ngx overwrite the environment variable, free the leak and
  // restore the environment as before.
  char *env_before = environ[0];
  environ[0] = my_argv[0] + 1;
  ngx_os_init(log);
  //free(environ[0]);
  environ[0] = env_before;
  ngx_os_environ = environ;

  ngx_crc32_table_init();
  ngx_preinit_modules();

  FILE *fptr = fopen(config_file, "w");
  fprintf(fptr, "%s", configuration);
  fclose(fptr);
  init_cycle.conf_file.len = strlen(config_file);
  init_cycle.conf_file.data = (unsigned char *) config_file;

  cycle = ngx_init_cycle(&init_cycle);

  ngx_os_status(cycle->log);
  ngx_cycle = cycle;

//  ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
//  if (ccf->master && ngx_process == NGX_PROCESS_SINGLE) {
//    ngx_process = NGX_PROCESS_MASTER;
//  }
//
//  if (ngx_process == NGX_PROCESS_SINGLE) {
//    ngx_single_process_cycle(cycle);
//  } else {
//    ngx_master_process_cycle(cycle);
//  }

  ngx_event_actions.add = add_event;
  ngx_event_actions.init = init_event;
  ngx_io.send_chain = send_chain;
  ngx_event_flags = 1;
  ngx_queue_init(&ngx_posted_accept_events);
  ngx_queue_init(&ngx_posted_events);
  ngx_event_timer_init(cycle->log);

  return 0;
}

extern "C" long int invalid_call(ngx_connection_s *a, ngx_chain_s *b,
                                 long int c) {
  return 0;
}

DEFINE_PROTO_FUZZER(const HttpProtocol &httpprocotol) {
  static int init = InitializeNginx();
  assert(init == 0);

  // have two free connections, one for client, one for upstream
  ngx_event_t read_event1 = {};
  ngx_event_t write_event1 = {};
  ngx_connection_t local1 = {};
  ngx_event_t read_event2 = {};
  ngx_event_t write_event2 = {};
  ngx_connection_t local2 = {};
  ngx_connection_t *c;
  ngx_listening_t *ls;

  req_reply = NULL;
  upstream = NULL;
  cln_added = 0;

  std::string req_string = std::string("");
  std::string rep_string = std::string("");
  request_protobuf_to_string(httpprocotol.request(), &req_string);
  reply_protobuf_to_string(httpprocotol.reply(), &rep_string);
  request.data = (const uint8_t *)req_string.c_str();
  request.data_len = req_string.length();
  reply.data = (const uint8_t *)rep_string.c_str();
  reply.data_len = rep_string.length();

  // Use listening entry created from configuration
  ls = (ngx_listening_t *)ngx_cycle->listening.elts;

  // Fake event ready for dispatch on read
  local1.read = &read_event1;
  local1.write = &write_event1;
  local2.read = &read_event2;
  local2.write = &write_event2;
  local2.send_chain = send_chain;

  // Create fake free connection to feed the http handler
  ngx_cycle->free_connections = &local1;
  local1.data = &local2;
  ngx_cycle->free_connection_n = 2;

  // Initialize connection
  c = ngx_get_connection(
      255, &ngx_log); // 255 - (hopefully unused) socket descriptor

  c->shared = 1;
  c->type = SOCK_STREAM;
  c->pool = ngx_create_pool(256, ngx_cycle->log);
  c->sockaddr = ls->sockaddr;
  c->listening = ls;
  c->recv = request_recv_handler; // Where the input will be read
  c->send_chain = send_chain;
  c->send = (ngx_send_pt)invalid_call;
  c->recv_chain = (ngx_recv_chain_pt)invalid_call;
  c->log = &ngx_log;
  c->pool->log = &ngx_log;
  c->read->log = &ngx_log;
  c->write->log = &ngx_log;
  c->socklen = ls->socklen;
  c->local_sockaddr = ls->sockaddr;
  c->local_socklen = ls->socklen;

  read_event1.ready = 1;
  write_event1.ready = write_event1.delayed = 1;

  // Will redirect to http parser
  ngx_http_init_connection(c);

  // Clean-up in case of error
  if (req_reply && upstream && upstream->cleanup) {
    (*(upstream->cleanup))(req_reply);
    if (!c->destroyed)
      ngx_http_close_connection(c);
  } else if (!c->destroyed) {
    ngx_http_request_t *r = (ngx_http_request_t *)(c->data);
    ngx_http_free_request(r, 0);
    ngx_http_close_connection(c);
  }
}
