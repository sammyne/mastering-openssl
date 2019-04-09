#include <iostream>

#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

using namespace std;

const int FAIL = -1;

// Create the SSL socket and intialize the socket address structure
//int OpenListener(int port)
int dial(const int port)
{
  //int sd;
  struct sockaddr_in addr;

  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;

  auto sd = socket(PF_INET, SOCK_STREAM, 0);
  if (bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
  {
    perror("can't bind port");
    abort();
  }
  if (listen(sd, 10) != 0)
  {
    perror("Can't configure listening port");
    abort();
  }

  return sd;
}

SSL_CTX *newCtx()
{
  OpenSSL_add_all_algorithms(); /* load & register all cryptos, etc. */
  SSL_load_error_strings();     /* load all error messages */

  auto method = TLS_server_method(); /* create new server-method instance */
  auto ctx = SSL_CTX_new(method);    /* create new context from method */
  if (ctx == NULL)
  {
    ERR_print_errors_fp(stderr);
    abort();
  }

  return ctx;
}

void loadCerts(SSL_CTX *ctx, const string cert, const string prv)
{
  /* set the local certificate from CertFile */
  if (SSL_CTX_use_certificate_file(ctx, cert.c_str(), SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp(stderr);
    abort();
  }
  /* set the private key from KeyFile (may be the same as CertFile) */
  if (SSL_CTX_use_PrivateKey_file(ctx, prv.c_str(), SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp(stderr);
    abort();
  }
  /* verify private key */
  if (!SSL_CTX_check_private_key(ctx))
  {
    cerr << "private key does not match the public certificate" << endl;
    abort();
  }
}

void showCert(const SSL *ssl)
{
  /* Get certificates (if available) */
  auto cert = SSL_get_peer_certificate(ssl);
  if (nullptr == cert)
  {
    cout << "no cert" << endl;
    return;
  }

  cout << "server cert:" << endl;

  auto line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
  cout << "Subject: " << line << endl;
  free(line);

  line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
  cout << "Issuer: " << line << endl;
  free(line);

  X509_free(cert);
}

void decode(SSL *ssl) /* Serve the connection -- threadable */
{
  const string response = "hello world";
  const string EXPECT_TOKEN = "I'm sammy";

  if (SSL_accept(ssl) == FAIL) /* do SSL-protocol accept */
  {
    ERR_print_errors_fp(stderr);
    return;
  }

  /* get any certificates */
  showCert(ssl);

  char req[1024] = {0};
  auto ell = SSL_read(ssl, req, sizeof(req)); /* get request */
  req[ell] = '\0';

  cout << "request msg: " << req << endl;

  if (ell > 0)
  {
    string reply = (strcmp(EXPECT_TOKEN.c_str(), req) == 0 ? response : "invalid msg");

    SSL_write(ssl, reply.c_str(), reply.size());
  }
  else
  {
    ERR_print_errors_fp(stderr);
  }

  auto sd = SSL_get_fd(ssl); /* get socket connection */
  SSL_free(ssl);             /* release SSL state */
  close(sd);                 /* close connection */
}

int main(int argc, char *argv[])
{
  // non-zero gid means non-root-user
  // who has no permission for run the server
  if (getgid())
  {
    cout << "sudo user permission is needed" << endl;
    exit(0);
  }

  const int PORT = 8081;

  // Initialize the SSL library
  SSL_library_init();

  auto ctx = newCtx();                      /* initialize SSL */
  loadCerts(ctx, "hello.pem", "hello.pem"); /* load certs */

  auto server = dial(PORT); /* create server socket */
  while (1)
  {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    /* accept connection as usual */
    auto conn = accept(server, (struct sockaddr *)&addr, &len);
    cout << "Connection: " << inet_ntoa(addr.sin_addr) << ":"
         << ntohs(addr.sin_port) << endl;

    auto ssl = SSL_new(ctx); /* get new SSL state with context */
    SSL_set_fd(ssl, conn);   /* set connection socket to SSL state */
    decode(ssl);             /* service connection */
  }

  close(server);     /* close server socket */
  SSL_CTX_free(ctx); /* release context */

  return 0;
}