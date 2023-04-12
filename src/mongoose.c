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
static struct RClass *Connection = NULL;

// During shutdown, mongoose may still have requests
// to process, so we need to signal to ev_handler that it should terminate
// requests because otherwise allocation of new objects on the stack can
// lead to crashes.
struct mgr_wrapper { struct mg_mgr mgr; int terminating; };

struct mrb_mg_context {
  mrb_state *mrb;
  mrb_value self;
};

static void mrb_mg_free(mrb_state *mrb, void *in) {
  struct mgr_wrapper *wrapper = in;
  wrapper->terminating = true;
  mg_mgr_free(&wrapper->mgr);
  mrb_free(mrb, in);
}

static void mrb_mg_conn_free(mrb_state *mrb, void *conn) {
  (void) mrb;
  (void) conn;
}

static struct mrb_data_type mrb_mongoose_type = { "Mongoose", mrb_mg_free };
static struct mrb_data_type mrb_connection_type = { "Mongoose::Connection", mrb_mg_conn_free };

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data, void *userarg) {
  struct mrb_mg_context *context = userarg;
  mrb_state *mrb = context->mrb;
  mrb_value self = context->self;
  int ai = mrb_gc_arena_save(mrb);

  switch (ev) {
    case MG_EV_HTTP_REQUEST: {
      struct mgr_wrapper *wrapper = DATA_PTR(self);
      // shutting down, don't talk to ruby
      if (wrapper->terminating) {
        mg_printf(nc, "HTTP/1.1 503 Gateway Unavailable\r\n\r\n503 Gateway Unavailable");
        nc->flags |= MG_F_SEND_AND_CLOSE;
        break;
      }

      if (Connection == NULL) mrb_raise(mrb, E_RUNTIME_ERROR, "BUG: Connection is NULL");
      struct http_message *req = (struct http_message *) ev_data;
      mrb_value verb         = mrb_str_new(mrb, req->method.p,       req->method.len);
      mrb_value body         = mrb_str_new(mrb, req->body.p,         req->body.len);
      mrb_value path         = mrb_str_new(mrb, req->uri.p,          req->uri.len);
      mrb_value query_string = mrb_str_new(mrb, req->query_string.p, req->query_string.len);
      mrb_value headers      = mrb_hash_new(mrb);

      // construct headers hash
      for (int i = 0; i < MG_MAX_HTTP_HEADERS; i++) {
        if (req->header_names[i].len > 0) {
          mrb_value name  = mrb_str_new(mrb, req->header_names[i].p,  req->header_names[i].len);
          mrb_value value = mrb_str_new(mrb, req->header_values[i].p, req->header_values[i].len);
          mrb_hash_set(mrb, headers, name, value);
        }
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
      mg_conn_addr_to_str(nc, addr_header_value, sizeof(addr_header_value),
                          MG_SOCK_STRINGIFY_REMOTE | MG_SOCK_STRINGIFY_IP);
      mrb_hash_set(mrb, headers, mrb_str_new_lit(mrb, "remote_addr"), mrb_str_new_cstr(mrb, addr_header_value));
      struct RData *conn = mrb_data_object_alloc(mrb, Connection, nc, &mrb_connection_type);
      mrb_funcall(mrb, self, "process_http_request", 6, mrb_obj_value(conn), headers, verb, path, query_string, body);
      break;
    }
    default:
      break;
  }

  mrb_gc_arena_restore(mrb, ai);
}

static mrb_value mrb_mg_initialize(mrb_state *mrb, mrb_value self) {
  struct mgr_wrapper *wrapper = DATA_PTR(self);
  if (wrapper) {
    mrb_mg_free(mrb, wrapper);
  }

  wrapper = mrb_malloc(mrb, sizeof(struct mgr_wrapper));
  memset(wrapper, 0, sizeof(struct mgr_wrapper));
  mg_mgr_init(&wrapper->mgr, NULL);
  DATA_TYPE(self) = &mrb_mongoose_type;
  DATA_PTR(self) = wrapper;
  return self;
}

static mrb_value mrb_mg_start_common(mrb_state *mrb, mrb_value self, mrb_int port, struct mg_bind_opts bind_opts) {
  char port_str[6];
  // FIXME free context on shutdown
  struct mrb_mg_context *context = malloc(sizeof(struct mrb_mg_context));
  sprintf(port_str, "%hu", (unsigned short) port);
  context->mrb = mrb;
  context->self = self;
  struct mg_connection *conn = mg_bind_opt(&((struct mgr_wrapper *)DATA_PTR(self))->mgr, port_str, ev_handler, context, bind_opts);
  struct RData *rconn = mrb_data_object_alloc(mrb, Connection, conn, &mrb_connection_type);
  if (conn) {
    mg_set_protocol_http_websocket(conn);
  } else {
    if (bind_opts.error_string) {
      mrb_raisef(mrb, E_RUNTIME_ERROR, "could not bind server to port %s: %s", port_str, *(bind_opts.error_string));
    } else {
      mrb_raisef(mrb, E_RUNTIME_ERROR, "could not bind server to port %s: no reason given", port_str);
    }
  }
  return mrb_obj_value(rconn);
}

static mrb_value mrb_mg_start_https(mrb_state *mrb, mrb_value self) {
  const char *ssl_key_file, *ssl_cert_file;
  mrb_int port;
  struct mg_bind_opts bind_opts;
  mrb_get_args(mrb, "zzi", &ssl_key_file, &ssl_cert_file, &port);
  memset(&bind_opts, 0, sizeof(bind_opts));
  bind_opts.ssl_cert = ssl_cert_file;
  bind_opts.ssl_key  = ssl_key_file;
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@https"), mrb_mg_start_common(mrb, self, port, bind_opts));
  return self;
}

static mrb_value mrb_mg_start_http(mrb_state *mrb, mrb_value self) {
  mrb_int port;
  struct mg_bind_opts bind_opts;
  mrb_get_args(mrb, "i", &port);
  memset(&bind_opts, 0, sizeof(bind_opts));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@http"), mrb_mg_start_common(mrb, self, port, bind_opts));
  return self;
}

static mrb_value mrb_mg_stop_common(mrb_state *mrb, mrb_value self, const char *ivar_name) {
  mrb_sym ivar_sym = mrb_intern_cstr(mrb, ivar_name);
  mrb_value conn = mrb_iv_get(mrb, self, ivar_sym);
  if (!mrb_nil_p(conn)) {
    if (DATA_PTR(conn)) {
      ((struct mg_connection *) DATA_PTR(conn))->flags |= MG_F_CLOSE_IMMEDIATELY;
      DATA_PTR(conn) = NULL;
    }
    mrb_iv_set(mrb, self, ivar_sym, mrb_nil_value());
    mrb_funcall(mrb, self, "poll", 1, mrb_fixnum_value(0)); // trigger close conn
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
  mrb_int timeout_ms;
  mrb_get_args(mrb, "i", &timeout_ms);
  mg_mgr_poll(DATA_PTR(self), (int) timeout_ms);
  return self;
}

static mrb_value mrb_mg_conn_write(mrb_state *mrb, mrb_value self) {
  struct mg_connection *nc = DATA_PTR(self);
  if (!nc) mrb_raisef(mrb, E_RUNTIME_ERROR, "BUG: Connection is nil");
  const char *data;
  mrb_int size;
  mrb_get_args(mrb, "s", &data, &size);
  int rc = mg_printf(nc, "%.*s", (int) size, data);
  return mrb_fixnum_value((mrb_int) rc);
}

static mrb_value mrb_mg_conn_close(mrb_state *mrb, mrb_value self) {
  struct mg_connection *nc = DATA_PTR(self);
  if (!nc) mrb_raisef(mrb, E_RUNTIME_ERROR, "BUG: Connection is nil");
  nc->flags |= MG_F_SEND_AND_CLOSE;
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

  Connection = mrb_define_class_under(mrb, Mongoose, "Connection", mrb->object_class);
  MRB_SET_INSTANCE_TT(Connection, MRB_TT_DATA);
  mrb_define_method(mrb, Connection, "write",       mrb_mg_conn_write,       MRB_ARGS_REQ(1));
  mrb_define_method(mrb, Connection, "close",       mrb_mg_conn_close,       MRB_ARGS_NONE());
}

void mrb_mruby_mongoose_gem_final(mrb_state *mrb) {
  (void) mrb;
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}
