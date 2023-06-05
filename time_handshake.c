#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <time.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <err.h>

enum { TIMES = 10000 };

static struct timespec elapsed[TIMES] = { 0 };

static int
set_iso15118_20_defaults(SSL_CTX *ctx)
{
  long opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION |
              SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2;
  SSL_CTX_set_options(ctx, opts);
  SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
  return 0;
}

static int
set_iso15518_2_defaults(SSL_CTX *ctx)
{
  long opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION |
              SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_3;
  SSL_CTX_set_options(ctx, opts);
  return 0;
}

int
timespec_subtract(struct timespec *result, struct timespec x, struct timespec y)
{
  enum { NSEC = 1000L*1000*1000 };

  if (y.tv_nsec > x.tv_nsec)
  {
    int sec = (y.tv_nsec - x.tv_nsec) / NSEC + 1;
    y.tv_nsec -= NSEC * sec;
    y.tv_sec += sec;
  }

  if (x.tv_nsec - y.tv_nsec > NSEC)
  {
    int sec = (x.tv_nsec - y.tv_nsec) / NSEC;
    y.tv_nsec += NSEC * sec;
    y.tv_sec -= sec;
  }

  result->tv_sec = x.tv_sec - y.tv_sec;
  result->tv_nsec = x.tv_nsec - y.tv_nsec;

  return x.tv_sec < y.tv_sec;
}

static int
do_handshake(void)
{
  SSL_CTX *sctx, *cctx;
  SSL *ss, *cs;
  BIO *io1, *io2;
  int sret, cret;
  struct timespec atim, btim;

  sctx = SSL_CTX_new(TLS_server_method());
  if (!SSL_CTX_use_certificate_chain_file(sctx, "CA/servercert.pem"))
    errx(EXIT_FAILURE, "Can't read certificate file.");
  if (!SSL_CTX_use_PrivateKey_file(sctx, "CA/private/serverkey.pem", SSL_FILETYPE_PEM))
    errx(EXIT_FAILURE, "Can't read key file.");
  if (!SSL_CTX_check_private_key(sctx))
    errx(EXIT_FAILURE, "private key doesn't match.");
  SSL_CTX_set_verify(sctx, SSL_VERIFY_NONE, NULL);

  cctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify_depth(cctx, 4);
  SSL_CTX_load_verify_locations(cctx, "CA/cacert.pem", NULL);

  set_iso15118_20_defaults(sctx);
  set_iso15118_20_defaults(cctx);

  io1 = BIO_new(BIO_s_mem());
  io2 = BIO_new(BIO_s_mem());

  for (int i = 0; i < TIMES; i++) {
    BIO_reset(io1);
    BIO_reset(io2);
    BIO_up_ref(io1); BIO_up_ref(io1);
    BIO_up_ref(io2); BIO_up_ref(io2);

    ss = SSL_new(sctx);
    SSL_set_bio(ss, io1, io2);
    SSL_set_accept_state(ss);

    cs = SSL_new(cctx);
    SSL_set_bio(cs, io2, io1);
    SSL_set_connect_state(cs);

    clock_gettime(CLOCK_MONOTONIC, &atim);

    /* Client HELO */
    cret = SSL_do_handshake(cs);

    /* Server HELO */
    sret = SSL_do_handshake(ss);

    cret = SSL_do_handshake(cs);

    sret = SSL_do_handshake(ss);

    if (cret < 0)
      cret = SSL_do_handshake(cs);

    (void) clock_gettime(CLOCK_MONOTONIC, &btim);
    timespec_subtract(&elapsed[i], btim, atim);


    if (!SSL_is_init_finished(cs) || !SSL_is_init_finished(ss))
      printf("SSL_do_handshake() did not complete\n");

    if (cret != 1 || sret != 1)
      printf("Something wrong with handshake\n");

    SSL_free(cs);
    SSL_free(ss);
  }

  BIO_free(io2);
  BIO_free(io1);

  SSL_CTX_free(cctx);
  SSL_CTX_free(sctx);

  for (int i = 0; i < TIMES; i++)
  {
    printf("%jd.%.09ld\n", (intmax_t) elapsed[i].tv_sec, elapsed[i].tv_nsec);
  }

  return 0;
}

int
main(void)
{
  do_handshake();
  return 0;
}
