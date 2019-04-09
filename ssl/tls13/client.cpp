#include <iostream>

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

const int FAIL = -1;

using namespace std;

int dial(const string hostURL, int port)
{
  struct hostent *host;
  if ((host = gethostbyname(hostURL.c_str())) == NULL)
  {
    perror(hostURL.c_str());
    abort();
  }

  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long *)(host->h_addr);

  auto sd = socket(PF_INET, SOCK_STREAM, 0);
  if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
  {
    close(sd);
    perror(hostURL.c_str());
    abort();
  }

  return sd;
}

SSL_CTX *newCtx()
{
  OpenSSL_add_all_algorithms(); /* Load cryptos, et.al. */
  SSL_load_error_strings();     /* Bring in and register error messages */

  auto method = TLS_client_method(); /* Create new client-method instance */
  auto ctx = SSL_CTX_new(method);    /* Create new context */
  if (ctx == NULL)
  {
    ERR_print_errors_fp(stderr);
    abort();
  }

  return ctx;
}

void showCert(SSL *ssl)
{
  auto cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
  if (nullptr == cert)
  {
    cout << "info: No client certificates configured" << endl;
    return;
  }

  cout << "server cert" << endl;

  auto line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
  cout << "Subject: " << line << endl;
  free(line); /* free the malloc'ed string */

  line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
  cout << "Issuer: " << line << endl;
  free(line); /* free the malloc'ed string */

  X509_free(cert); /* free the malloc'ed certificate copy */
}

int main(int argc, char *strings[])
{
  const string HOST = "localhost";
  const int PORT = 8081;

  SSL_library_init();

  auto ctx = newCtx();
  auto server = dial(HOST, PORT);
  auto ssl = SSL_new(ctx);      /* create new SSL connection state */
  SSL_set_fd(ssl, server);      /* attach the socket descriptor */
  if (SSL_connect(ssl) == FAIL) /* perform the connection */
  {
    ERR_print_errors_fp(stderr);
    return FAIL;
  }

  const string req = "I'm sammy";

  cout << "Connected with " << SSL_get_cipher(ssl) << " encryption" << endl;

  /* get any certs */
  showCert(ssl);

  /* encrypt & send message */
  SSL_write(ssl, req.c_str(), req.size());

  /* get reply & decrypt */
  char reply[1024];
  auto ell = SSL_read(ssl, reply, sizeof(reply));
  reply[ell] = 0;
  cout << "received: " << reply << endl;
  SSL_free(ssl); /* release connection state */

  close(server);     /* close socket */
  SSL_CTX_free(ctx); /* release context */

  return 0;
}