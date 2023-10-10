#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <stdlib.h>
#include "mongoose.h"
#include "mruby.h"
#include "mruby/class.h"
#include "mruby/data.h"
#include "mruby/hash.h"
#include "mruby/string.h"
#include "mruby/variable.h"

static mbedtls_entropy_context  entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

#define mrb_cServer(mrb)     mrb_class_get_under(mrb, mrb_class_get(mrb, "Mongoose"), "Server")
#define mrb_cConnection(mrb) mrb_class_get_under(mrb, mrb_class_get(mrb, "Mongoose"), "Connection")

struct mrb_mg_context {
  mrb_state *mrb;
  mrb_value mongoose;
  mrb_value ssl_cert;
  mrb_value ssl_key;
  struct mg_connection *conn;
};

struct mrb_mg_mgr_wrapper {
  struct mg_mgr mgr;
  struct mrb_mg_context http_context;
  struct mrb_mg_context https_context;
};

static void mrb_mg_ctx_free(mrb_state *mrb, struct mrb_mg_context *ctx) {
  if (!mrb_nil_p(ctx->ssl_key))   mrb_gc_unregister(mrb, ctx->ssl_key);
  if (!mrb_nil_p(ctx->ssl_cert))  mrb_gc_unregister(mrb, ctx->ssl_cert);
  ctx->ssl_key  = mrb_nil_value();
  ctx->ssl_cert = mrb_nil_value();
}

static void mrb_mg_free(mrb_state *mrb, void *in) {
  struct mrb_mg_mgr_wrapper *mgr = in;
  mg_mgr_free(&mgr->mgr);
  mrb_mg_ctx_free(mrb, &mgr->http_context);
  mrb_mg_ctx_free(mrb, &mgr->https_context);
  mrb_free(mrb, in);
}

static void mrb_free_noop(mrb_state *mrb, void *ctx) {
  (void) mrb;
  (void) ctx;
}

static struct mrb_data_type mrb_mongoose_type   = { "Mongoose",             mrb_mg_free   };
static struct mrb_data_type mrb_connection_type = { "Mongoose::Connection", mrb_free_noop };
static struct mrb_data_type mrb_mg_ctx_type     = { "Mongoose::Server",     mrb_free_noop };

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data, void *userarg) {
  struct mrb_mg_context *context = userarg;
  mrb_state *mrb = context->mrb;
  mrb_value mongoose = context->mongoose;
  int ai = mrb_gc_arena_save(mrb);

  switch (ev) {
    case MG_EV_ACCEPT:
      if (!mrb_nil_p(context->ssl_cert)) {
        struct mg_tls_opts opts = {
          // .ca = s_tls_ca,
          .cert = RSTRING_PTR(context->ssl_cert),
          .certkey = RSTRING_PTR(context->ssl_key)
        };
        mg_tls_init(nc, &opts);
      }
      break;
    case MG_EV_HTTP_MSG: {
      struct mg_http_message *req = (struct mg_http_message *) ev_data;
      mrb_value verb         = mrb_str_new(mrb, req->method.ptr, req->method.len);
      mrb_value body         = mrb_str_new(mrb, req->body.ptr,   req->body.len);
      mrb_value path         = mrb_str_new(mrb, req->uri.ptr,    req->uri.len);
      mrb_value query_string = mrb_str_new(mrb, req->query.ptr,  req->query.len);
      mrb_value headers      = mrb_hash_new(mrb);

      // construct headers hash
      for (int i = 0; i < MG_MAX_HTTP_HEADERS && req->headers[i].name.len; i++) {
        mrb_value name  = mrb_str_new(mrb, req->headers[i].name.ptr,  req->headers[i].name.len);
        mrb_value value = mrb_str_new(mrb, req->headers[i].value.ptr, req->headers[i].value.len);
        mrb_hash_set(mrb, headers, name, value);
      }

      // body should be an IO-like so that in the future if we want to handle
      // chunked uploads we can do so efficiently without forcing API changes.
      mrb_value StringIO = mrb_const_get(mrb,
                                         mrb_obj_value(mrb->object_class),
                                         mrb_intern_lit(mrb, "StringIO"));
      body = mrb_funcall(mrb, StringIO, "new", 1, body);

      // add special "remote_addr" header, which isn't really a header.
      // HACK because we don't support typical CGI env vars. Yet?
      char addr_header_value[100];
      memset(addr_header_value, 0, sizeof(addr_header_value));
      mg_snprintf(addr_header_value, sizeof(addr_header_value), "%M", mg_print_ip, &nc->rem);
      mrb_hash_set(mrb, headers, mrb_str_new_lit(mrb, "remote_addr"), mrb_str_new_cstr(mrb, addr_header_value));
      struct RData *conn = mrb_data_object_alloc(mrb, mrb_cConnection(mrb), nc, &mrb_connection_type);
      mrb_funcall(mrb, mongoose, "process_http_request", 6, mrb_obj_value(conn), headers, verb, path, query_string, body);
      break;
    }
    default:
      break;
  }

  mrb_gc_arena_restore(mrb, ai);
}

static mrb_value mrb_mg_initialize(mrb_state *mrb, mrb_value self) {
  struct mrb_mg_mgr_wrapper *mgr = DATA_PTR(self);
  if (mgr) mrb_mg_free(mrb, &mgr->mgr);

  mgr = mrb_malloc(mrb, sizeof(struct mrb_mg_mgr_wrapper));
  memset(mgr, 0, sizeof(struct mrb_mg_mgr_wrapper));
  mg_mgr_init(&mgr->mgr);
  DATA_TYPE(self) = &mrb_mongoose_type;
  DATA_PTR(self) = mgr;
  return self;
}

static mrb_value mrb_mg_start_https(mrb_state *mrb, mrb_value self) {
  struct mrb_mg_mgr_wrapper *mgr = DATA_PTR(self);
  mrb_value ssl_key = mrb_nil_value(), ssl_cert = mrb_nil_value();
  mrb_int port;
  mrb_get_args(mrb, "SSi", &ssl_key, &ssl_cert, &port);
  mrb_value url = mrb_str_new_lit(mrb, "https://0.0.0.0");
  mrb_str_cat_lit(mrb, url, ":");
  mrb_str_cat_str(mrb, url, mrb_funcall(mrb, mrb_fixnum_value(port), "to_s", 0));

  if (!mrb_nil_p(mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@https")))) {
    // TODO multiple servers across different ports??
    mrb_raise(mrb, E_ARGUMENT_ERROR, "an HTTPS server is already running");
  }

  // don't gc these until we are done with them (see mrb_mg_ctx_free()).
  mrb_gc_register(mrb, ssl_key);
  mrb_gc_register(mrb, ssl_cert);

  mgr->https_context.mrb = mrb;
  mgr->https_context.mongoose = self;
  mgr->https_context.ssl_key  = ssl_key;
  mgr->https_context.ssl_cert = ssl_cert;
  mgr->https_context.conn = mg_http_listen(&mgr->mgr, RSTRING_PTR(url), ev_handler, &mgr->https_context);
  if (!mgr->https_context.conn)
    mrb_raisef(mrb, E_RUNTIME_ERROR, "could not bind HTTPS server to port %d", port);

  struct RData *rconn = mrb_data_object_alloc(mrb, mrb_cServer(mrb), &mgr->https_context, &mrb_mg_ctx_type);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@https"), mrb_obj_value(rconn));
  return self;
}

static mrb_value mrb_mg_start_http(mrb_state *mrb, mrb_value self) {
  struct mrb_mg_mgr_wrapper *mgr = DATA_PTR(self);
  mrb_int port;
  mrb_get_args(mrb, "i", &port);
  mrb_value url = mrb_str_new_lit(mrb, "http://0.0.0.0");
  mrb_str_cat_lit(mrb, url, ":");
  mrb_str_cat_str(mrb, url, mrb_funcall(mrb, mrb_fixnum_value(port), "to_s", 0));

  if (!mrb_nil_p(mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@http")))) {
    // TODO multiple servers across different ports??
    mrb_raise(mrb, E_ARGUMENT_ERROR, "an HTTP server is already running");
  }
  mgr->http_context.mrb = mrb;
  mgr->http_context.mongoose = self;
  mgr->http_context.ssl_key  = mrb_nil_value();
  mgr->http_context.ssl_cert = mrb_nil_value();
  mgr->http_context.conn = mg_http_listen(&mgr->mgr, RSTRING_PTR(url), ev_handler, &mgr->http_context);
  if (!mgr->http_context.conn)
    mrb_raisef(mrb, E_RUNTIME_ERROR, "could not bind HTTP server to port %d", port);
 
  struct RData *rconn = mrb_data_object_alloc(mrb, mrb_cServer(mrb), &mgr->http_context, &mrb_mg_ctx_type);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@http"), mrb_obj_value(rconn));
  return self;
}

static mrb_value mrb_mg_stop_common(mrb_state *mrb, mrb_value self, const char *ivar_name) {
  mrb_sym ivar_sym = mrb_intern_cstr(mrb, ivar_name);
  mrb_value server = mrb_iv_get(mrb, self, ivar_sym);
  if (!mrb_nil_p(server)) {
    mrb_funcall(mrb, server, "stop", 0);
    mrb_iv_set(mrb, self, ivar_sym, mrb_nil_value());
    mrb_funcall(mrb, self, "poll", 1, mrb_fixnum_value(0)); // trigger close conn
    mrb_mg_ctx_free(mrb, DATA_PTR(server));
    mrb_iv_set(mrb, self, ivar_sym, mrb_nil_value());
  }
  return self;
}

static mrb_value mrb_mg_stop_https(mrb_state *mrb, mrb_value self) {
  return mrb_mg_stop_common(mrb, self, "@https");
}

static mrb_value mrb_mg_stop_http(mrb_state *mrb, mrb_value self) {
  return mrb_mg_stop_common(mrb, self, "@http");
}

static mrb_value mrb_mg_poll(mrb_state *mrb, mrb_value self) {
  struct mrb_mg_mgr_wrapper *mgr = DATA_PTR(self);
  mrb_int timeout_ms;
  mrb_get_args(mrb, "i", &timeout_ms);
  mg_mgr_poll(&mgr->mgr, (int) timeout_ms);
  return self;
}

static mrb_value mrb_mg_server_stop(mrb_state *mrb, mrb_value self) {
  (void) mrb;
  struct mrb_mg_context *ctx = DATA_PTR(self);
  ctx->conn->is_closing = 1;
  return mrb_nil_value();
}

static mrb_value mrb_mg_conn_write(mrb_state *mrb, mrb_value self) {
  struct mg_connection *nc = DATA_PTR(self);
  if (!nc) mrb_raisef(mrb, E_RUNTIME_ERROR, "BUG: Connection is nil");
  const char *data;
  mrb_int size;
  mrb_get_args(mrb, "s", &data, &size);
  int rc = mg_send(nc, data, size); // mg_printf(nc, "%.*s", (int) size, data);
  return mrb_fixnum_value((mrb_int) rc);
}

static mrb_value mrb_mg_conn_close(mrb_state *mrb, mrb_value self) {
  struct mg_connection *nc = DATA_PTR(self);
  if (!nc) mrb_raisef(mrb, E_RUNTIME_ERROR, "BUG: Connection is nil");
  nc->is_draining = 1;
  return mrb_nil_value();
}

int mg_ssl_if_mbed_random(void *ctx, unsigned char *buf, size_t len) {
  (void) ctx;
  return mbedtls_ctr_drbg_random(&ctr_drbg, buf, len);
}

void mrb_mruby_mongoose_gem_init(mrb_state *mrb) {
  const char *personalization = "9f43d69df72b68d3459c0b01dfde2df6001dda42d5196ced879bfa57fd2874c2";
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg , mbedtls_entropy_func, &entropy,
                                  (const unsigned char *) personalization,
                                  strlen(personalization));
  if (ret) {
    char errbuf[200];
    mbedtls_strerror(ret, errbuf, sizeof(errbuf));
    mrb_raisef(mrb, E_RUNTIME_ERROR, "entropy initialization failed: %s (%d)", errbuf, ret);
  }

  struct RClass *Mongoose = mrb_define_class(mrb, "Mongoose", mrb->object_class);
  MRB_SET_INSTANCE_TT(Mongoose, MRB_TT_DATA);
  mrb_define_method(mrb, Mongoose, "initialize",  mrb_mg_initialize,  MRB_ARGS_NONE());
  mrb_define_method(mrb, Mongoose, "start_http",  mrb_mg_start_http,  MRB_ARGS_REQ(1));
  mrb_define_method(mrb, Mongoose, "start_https", mrb_mg_start_https, MRB_ARGS_REQ(3));
  mrb_define_method(mrb, Mongoose, "stop_http",   mrb_mg_stop_http,   MRB_ARGS_NONE());
  mrb_define_method(mrb, Mongoose, "stop_https",  mrb_mg_stop_https,  MRB_ARGS_NONE());
  mrb_define_method(mrb, Mongoose, "poll",        mrb_mg_poll,        MRB_ARGS_REQ(1));

  struct RClass *Server = mrb_define_class_under(mrb, Mongoose, "Server", mrb->object_class);
  MRB_SET_INSTANCE_TT(Server, MRB_TT_DATA);
  mrb_define_method(mrb, Server,   "stop",        mrb_mg_server_stop, MRB_ARGS_NONE());

  struct RClass *Connection = mrb_define_class_under(mrb, Mongoose, "Connection", mrb->object_class);
  MRB_SET_INSTANCE_TT(Connection, MRB_TT_DATA);
  mrb_define_method(mrb, Connection, "write",     mrb_mg_conn_write,  MRB_ARGS_REQ(1));
  mrb_define_method(mrb, Connection, "close",     mrb_mg_conn_close,  MRB_ARGS_NONE());
}

void mrb_mruby_mongoose_gem_final(mrb_state *mrb) {
  (void) mrb;
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}
