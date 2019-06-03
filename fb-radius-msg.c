// RADIUS message client
// © 2009 Andrews & Arnold Ltd Adrian Kennard

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <signal.h>
#include <syslog.h>
#include <openssl/md5.h>
#include <err.h>
#include <popt.h>
#include <time.h>
#include "radius-defs.h"

typedef unsigned char ui8;
typedef unsigned short ui16;
typedef unsigned int ui32;
typedef unsigned long long ui64;

#define xquoted(x)      #x
#define quoted(x)       xquoted(x)
const char *lns = NULL;
#ifdef  SECRET
const char *secret = quoted(SECRET);    // RADIUS secret
#else
const char *secret = NULL;
#endif
#ifdef  AUTHPORT
const char *authport = quoted(AUTHPORT);
#else
const char *authport = "radius";
#endif
#ifdef  DYNAUTHPORT
const char *dynauthport = quoted(DYNAUTHPORT);
#else
const char *dynauthport = "radius-dynauth";
#endif
const char *circuit = NULL;
const char *session = NULL;
const char *connectinfo = NULL;
const char *filterid = NULL;
int statusserver = 0;
int disconnect = 0;
int debug = 0;
int sessiontimeout = -1;
int terminateaction = -1;

void
HMAC_MD5 (void *output, int key_len, const ui8 * key, int text_len, const void *text)
{				// RFC2104
  MD5_CTX ctx;
  ui8 k_ipad[64];
  ui8 k_opad[64];
  ui8 tk[16];
  int i;
  if (key_len > 64)
    {				// keys over 64 bytes use an MD5 of the key instead
      MD5_Init (&ctx);
      MD5_Update (&ctx, key, key_len);
      MD5_Final (tk, &ctx);
      key = tk;
      key_len = 16;
    }
  for (i = 0; i < key_len; i++)
    {
      k_ipad[i] = key[i] ^ 0x36;
      k_opad[i] = key[i] ^ 0x5C;
    }
  for (; i < 64; i++)
    {
      k_ipad[i] = 0x36;
      k_opad[i] = 0x5C;
    }
  MD5_Init (&ctx);
  MD5_Update (&ctx, k_ipad, 64);
  MD5_Update (&ctx, text, text_len);
  MD5_Final (tk, &ctx);
  MD5_Init (&ctx);
  MD5_Update (&ctx, k_opad, 64);
  MD5_Update (&ctx, tk, 16);
  MD5_Final (output, &ctx);
}

int
main (int argc, const char *argv[])
{
  char c;

  poptContext optCon;		// context for parsing command-line options
  const struct poptOption optionsTable[] = {
    {"secret", 's', POPT_ARG_STRING, &secret, 0, "Secret", "shared secret"},
    {"lns", 'l', POPT_ARG_STRING, &lns, 0, "LNS", "hostname/ip"},
    {"session", 'a', POPT_ARG_STRING, &session, 0, "Accounting Session ID", "id"},
    {"cui", 'c', POPT_ARG_STRING, &circuit, 0, "Chargeable User Identity ID", "id"},
    {"circuit", 0,POPT_ARGFLAG_DOC_HIDDEN| POPT_ARG_STRING, &circuit, 0, "Circuit ID", "id"},
    {"auth-port", 0, POPT_ARG_STRING|(authport?POPT_ARGFLAG_SHOW_DEFAULT:0), &authport, 0, "Auth port", "name/port"},
    {"dyn-auth-port", 0, POPT_ARG_STRING|(dynauthport?POPT_ARGFLAG_SHOW_DEFAULT:0), &dynauthport, 0, "Dyn-Auth port", "name/port"},
    {"disconnect", 'd', POPT_ARG_NONE, &disconnect, 0, "Disconnect", NULL},
    {"status-server", 's', POPT_ARG_NONE, &statusserver, 0, "Status-Server", NULL},
    {"connect-info", 'i', POPT_ARG_STRING, &connectinfo, 0, "Connect info to send", "tx/rx"},
    {"filter-id", 'f', POPT_ARG_STRING, &filterid, 0, "Filter id to send", "text"},
    {"session-timeout", 't', POPT_ARG_INT, &sessiontimeout, 0, "Session timeout", "seconds"},
    {"terminate-action", 'A', POPT_ARG_INT, &terminateaction, 0, "Terminate action", "0/1"},
    {"debug", 'v', POPT_ARG_NONE, &debug, 0, "Debug", NULL},
    POPT_AUTOHELP {NULL, 0, 0, NULL, 0}
  };

  optCon = poptGetContext (NULL, argc, argv, optionsTable, 0);
  //poptSetOtherOptionHelp (optCon, "");

  if ((c = poptGetNextOpt (optCon)) < -1)
    errx (1, "%s: %s\n", poptBadOption (optCon, POPT_BADOPTION_NOALIAS), poptStrerror (c));

  if (!lns && !poptPeekArg (optCon))
    lns = poptGetArg (optCon);

  if (poptPeekArg (optCon))
    {
      poptPrintUsage (optCon, stderr, 0);
      return -1;
    }
  if (!lns)
    errx (1, "Must specify lns");
  if (!secret)
    errx (1, "Must specify secret");
  if ((disconnect || connectinfo) && !circuit && !session)
    errx (1, "Must specify session or circuit");
  if (connectinfo || filterid || sessiontimeout >= 0 || terminateaction >= 0)
    {
      if (disconnect)
	errx (1, "Cannot send data with a disconnect");
    }
  else if (!session&&!circuit&&(disconnect || connectinfo))
    errx (1, "CoA with no session/circuit, specify what you want sent");

  ui8 tx[1500];
  ui8 *txp = tx + 20;
  void add_string (ui8 code, const char *s)
  {
    ui32 l = strlen (s);
    *txp++ = code;
    *txp++ = l + 2;
    memmove (txp, s, l);
    txp += l;
  }
  void add_int (ui8 code, int n)
  {
    *txp++ = code;
    *txp++ = 6;
    *txp++ = (n >> 24);
    *txp++ = (n >> 16);
    *txp++ = (n >> 8);
    *txp++ = n;
  }

  if (session)
    add_string (RADIUS_AVP_ACCT_SESSION_ID, session);
  if (circuit)
    add_string (RADIUS_AVP_CHARGEABLE_USER_IDENTITY, circuit);
  if (filterid)
    add_string (RADIUS_AVP_FILTER_ID, filterid);
  if (connectinfo)
    add_string (RADIUS_AVP_CONNECT_INFO, connectinfo);
  if (sessiontimeout >= 0)
    add_int (RADIUS_AVP_SESSION_TIMEOUT, sessiontimeout);
  if (terminateaction >= 0)
    add_int (RADIUS_AVP_TERMINATE_ACTION, terminateaction);

  // Last bit - add authenticator
  if (statusserver)
    {
      if (txp > tx + 20)
	errx (1, "Cannot send any data with a status-server");
      *txp++ = RADIUS_AVP_MESSAGE_AUTHENTICATOR;
      *txp++ = 18;
      memset (txp, 0, 16);
      txp += 16;
    }

  // send
  tx[0] = (statusserver ? RADIUS_STATUS_SERVER : disconnect ? RADIUS_DISCONNECT_REQUEST : RADIUS_COA_REQUEST);
  tx[1] = 0;
  ui32 txl = txp - tx;
  tx[2] = (txl >> 8);
  tx[3] = txl;
  if (statusserver)
    {				// authenticator
      int p = open ("/dev/urandom", O_RDONLY);
      if (p < 0)
	errx (1, "No random");
      if (read (p, tx + 4, 16) != 16)
	errx (1, "Bad random");
      close (p);
      HMAC_MD5 (txp - 16, strlen (secret), (unsigned char *) secret, txp - tx, tx);
    }
  else
    {
      memset (tx + 4, 0, 16);
      MD5_CTX context;
      MD5_Init (&context);
      MD5_Update (&context, tx, txl);
      MD5_Update (&context, secret, strlen (secret));
      MD5_Final (tx + 4, &context);
    }

  int s = -1;
  {				// send
    //const struct addrinfo hints = { ai_flags: AI_PASSIVE, ai_family: AF_UNSPEC, ai_socktype:SOCK_DGRAM };
  const struct addrinfo hints = { ai_flags: AI_PASSIVE, ai_family: AF_INET, ai_socktype:SOCK_DGRAM };
    int e;
    struct addrinfo *res = NULL;
    if ((e = getaddrinfo (lns, statusserver ? authport : dynauthport, &hints, &res)))
      errx (1, "getaddrinfo: %s", gai_strerror (e));
    if (!res)
      errx (1, "Cannot find address for %s", lns);
    s = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0)
      err (1, "socket");
    if (sendto (s, tx, txl, 0, res->ai_addr, res->ai_addrlen) < 0)
      err (1, "Send failed");
    freeaddrinfo (res);
  }
  // wait for reply
  fd_set set;
  FD_ZERO (&set);
  FD_SET (s, &set);
  struct timeval timeval = { 1, 0 };
  if (select (s + 1, &set, NULL, NULL, &timeval) > 0)
    {
      ui8 rx[1500];
      int rxl = recv (s, rx, sizeof (rx), MSG_DONTWAIT);
      if (rxl >= 20)
	{
	  if (!rx[1])
	    {
	      if (rxl == (rx[2] << 8) + rx[3])
		{
		  ui8 hash[16];
		  MD5_CTX context;
		  MD5_Init (&context);
		  MD5_Update (&context, rx, 4);
		  MD5_Update (&context, tx + 4, 16);
		  MD5_Update (&context, rx + 20, rxl - 20);
		  MD5_Update (&context, secret, strlen (secret));
		  MD5_Final (hash, &context);
		  if (!memcmp (hash, rx + 4, 16))
		    {
		      ui8 *e = rx + rxl, *p = rx + 20;
		      while (p < e && p[1] >= 2 && p + p[1] <= e && *p != RADIUS_AVP_REPLY_MESSAGE)
			p += p[1];
		      if (p < e && *p == RADIUS_AVP_REPLY_MESSAGE)
			fprintf (stderr, "[%.*s]\n", p[1] - 2, p + 2);
		      if (*rx == RADIUS_DISCONNECT_ACK || *rx == RADIUS_COA_ACK || *rx == RADIUS_ACCESS_ACCEPT)
			{
			  if (debug)
			    fprintf (stderr, "ACK reply\n");
			  return 0;
			}
		      if (*rx == RADIUS_DISCONNECT_NAK || *rx == RADIUS_COA_NAK)
			{
			  if (debug)
			    fprintf (stderr, "NAK reply\n");
			  return 1;
			}
		      if (debug)
			fprintf (stderr, "Reply code %d\n", *rx);
		    }
		  else if (debug)
		    fprintf (stderr, "Bad reply hash\n");
		}
	      else if (debug)
		fprintf (stderr, "Bad reply len in msg %u/%u\n", rxl, (rx[2] << 8) + rx[3]);
	    }
	  else if (debug)
	    fprintf (stderr, "Bad reply ID %u\n", rx[1]);
	}
      else if (rxl >= 0 && debug)
	fprintf (stderr, "Bad reply len %u\n", rxl);
    }
  else if (debug)
    fprintf (stderr, "No reply\n");
  return 2;
}
