// RADIUS authentication server
// © 2015-2018 FireBrick Ltd Adrian Kennard
//
// Auth table access is read only
//
// The Auth entry is selected by trying a sequence of checks in order until one is found
// These are only tried if we have the non empty data to check and the field exists in the auth table
// This way, the exact method used can be determined by which fields you create in the auth table
//
// 1. carrier_circuit_id checked against calling ID
// 2. login_prefix checked against initial alphanumeric part of login
//    login_suffix (if field present) checked against part after hyphen after prefix (if present)
//    realm (if field present) checked against realm part of login (after @) (if present)
// 3. username checked against username part of login (before @)
//    realm (if field present) checked against realm part of login (after @) (if present)
// 4. login checked against whole login
//    realm (if field present) checked against realm part of login (after @) (if present)
// In all cases, carrier (if field present) against carrier (if present and not empty)
//
// Typically a table may use carrier_circuit_id (and carrier) as a primary check, and one of
// either login_prefix/login_suffix (perhaps with realm), username (perhaps with realm) or login
//
// In any case, if above fields also exist and do not match, e.g. carrier_circuit_id matches
// and username does not, then the discrepancy is syslogged
//
// Fields checked once selection made
//
// password, if present and not null, is checked against password (CHAPS or PAP)
// A password failure causes T100 return, the same as an unknown login
//
// Fields in auth table used for reply if present and not NULL
//
// ID           Used if assign CUI is set, the CUI prefix is appended with ID to make a CUI
// table_number If set, sent as table to use
// speed        If set, sent as new speed (tx or tx/rx), else default speed setting is used if defined
// relay        If set, is IP/host to L2TP relay to (* prefix for RADIUS server to steer via)
//      relay_hostname   Relay hostname to use
//      relay_graph      Relay graph to use
//      relay_password   Relay secret (L2TP or RADIUS) to use
//      login           If set, overrides login, also used for matching
//      calling         If set, overrides calling number
//      called          If set, overrides the called number
// ip4_wan       IPv4 WAN address
// ip4_ppp       IPv4 PPP address
// ip4_dns       IPv4 DNS addresses
// ip6_wan       IPv6 WAN address
// ip4          Blocks of additional IPv4 to route (IP/bits), space separated
// ip6          Blocks of additional IPv6 to route (IP/bits), space separated
// lcp_timeout  LCP timeout
// lcp_rate     LCP rate
// session_timeout      Timeout in seconds
// filter_x     Setting for standard filters, e.g. filter_f for TCP fix.
//              NULL not to send
//              Y or true to send upper case
//              N or false to send lower case
//              digits to send upper case and digits, e.g. for An or Rn

#define authfields    \
	a(carrier,"Carrier name")				\
	a(carrier_circuit_id,"Carrier calling id")		\
	a(login_prefix,"Alphanumeric start of login")		\
	a(login_suffix,"After prefix and hyphen before @")	\
	a(username,"All login before @")			\
	a(realm,"All login after @")				\
	a(login,"All login")					\

#define a(x,t)  char auth_##x=0;
authfields
#undef  a
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <mysql.h>
#include <mysql/errmsg.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <signal.h>
#include <syslog.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <err.h>
#include <popt.h>
#include <time.h>
#include "sqllib.h"
#include "radius-defs.h"
  typedef unsigned char ui8;
typedef unsigned short ui16;
typedef unsigned int ui32;
typedef unsigned long long ui64;

const char *sqlhost = NULL;     // Use sqlconf
const char *sqluser = NULL;     // Use sqlconf
const char *sqlpass = NULL;     // Use sqlconf

#define xquoted(x)      #x
#define quoted(x)       xquoted(x)
#ifdef  SECRET
const char *secret = quoted(SECRET);    // RADIUS secret
#else
const char *secret = NULL;
#endif
#ifdef  SQLCONF
const char *sqlconf = quoted(SQLCONF);
#else
const char *sqlconf = NULL;
#endif
#ifdef  DATABASE
const char *database = quoted(DATABSE);;
#else
const char *database = NULL;
#endif
#ifdef  TABLE
const char *tableauth = quoted(TABLE);;
#else
const char *tableauth = NULL;
#endif
#ifdef  PORT
const char *bindport = quoted(PORT);
#else
const char *bindport = "radius";
#endif
const char *bindhost = NULL;
#ifdef	ASSIGNCUI
const char *assigncui = quoted(ASSIGNCUI);
#else
const char *assigncui = NULL;
#endif
#ifdef	DEFAULTSPEED
int defaultspeed = DEFAULTSPEED;
#else
int defaultspeed = 0;
#endif

typedef struct cache_s cache_t;
struct cache_s
{
  unsigned int rxlen, txlen;
  ui8 *rx, *tx;
};
cache_t cache[256] = { };

SQL sqlr;
int test = 0;

pid_t handler_pid;

void HMAC_MD5(void *output, int key_len, const ui8 *key, int text_len, const void *text)
{                               // RFC2104
  MD5_CTX ctx;
  ui8 k_ipad[64];
  ui8 k_opad[64];
  ui8 tk[16];
  int i;
  if (key_len > 64)
  {                             // keys over 64 bytes use an MD5 of the key instead
    MD5_Init(&ctx);
    MD5_Update(&ctx, key, key_len);
    MD5_Final(tk, &ctx);
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
  MD5_Init(&ctx);
  MD5_Update(&ctx, k_ipad, 64);
  MD5_Update(&ctx, text, text_len);
  MD5_Final(tk, &ctx);
  MD5_Init(&ctx);
  MD5_Update(&ctx, k_opad, 64);
  MD5_Update(&ctx, tk, 16);
  MD5_Final(output, &ctx);
}

int main(int argc, const char *argv[])
{

  //sqlsyslogquery = LOG_INFO;
  void babysit(int s)
  {                             // children of BGP server come and go
    while (waitpid(-1, 0, WNOHANG) > 0) ;
    signal(SIGCHLD, &babysit);
  }
  signal(SIGCHLD, &babysit);
  char c;
  int background = 0;
  int noma = 0;
  poptContext optCon;           // context for parsing command-line options
  const struct poptOption optionsTable[] = {
	  // *INDENT-OFF*
    {"sql-conf", 0, POPT_ARG_STRING | (sqlconf ? POPT_ARGFLAG_SHOW_DEFAULT : 0), &sqlconf, 0, "SQL .my.cnf", "filename"},
    {"sql-host", 0, POPT_ARG_STRING, &sqlhost, 0, "SQL hostname (use .my.cnf)", "hostname"},
    {"sql-user", 'u', POPT_ARG_STRING, &sqluser, 0, "SQL username (use .my.cnf)", "username"},
    {"sql-pass", 'p', POPT_ARG_STRING, &sqlpass, 0, "SQL password (use .my.cnf)", "password"},
    {"sql-database", 'd', POPT_ARG_STRING | (database ? POPT_ARGFLAG_SHOW_DEFAULT : 0), &database, 0, "SQL database", "database"},
    {"sql-table", 0, POPT_ARG_STRING | (tableauth ? POPT_ARGFLAG_SHOW_DEFAULT : 0), &tableauth, 0, "SQL table for auth", "table"},
    {"default-speed", 0, POPT_ARG_INT|(defaultspeed?POPT_ARGFLAG_SHOW_DEFAULT:0), &defaultspeed, 0, "Default speed", "bps"},
    {"secret", 's', POPT_ARG_STRING, &secret, 0, "Secret", "RADIUS shared secret"},
    {"bind", 0, POPT_ARG_STRING, &bindhost, 0, "Host to bind", "name/no"},
    {"port", 0, POPT_ARG_STRING | (bindport ? POPT_ARGFLAG_SHOW_DEFAULT : 0), &bindport, 0, "Port to bind", "name/no"},
#ifndef	ASSIGNCUI
    {"assign-cui", 0, POPT_ARG_STRING, &assigncui, 0, "Make CUI from this prefix and ID from auth table","prefix"},
#endif
    {"background", 'b', POPT_ARG_NONE, &background, 0, "Run in background"},
    {"no-ma", 0, POPT_ARG_NONE, &noma, 0, "Ignore missing message authenticator (for testing)"},
    {"debug", 'v', POPT_ARG_NONE, &sqldebug, 0, "Debug"},
    {"test", 't', POPT_ARG_NONE, &test, 0, "Testing"},
    POPT_AUTOHELP {}
    // *INDENT-ON*
  };

  optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);
  //poptSetOtherOptionHelp (optCon, "");

  if ((c = poptGetNextOpt(optCon)) < -1)
    errx(1, "%s: %s\n", poptBadOption(optCon, POPT_BADOPTION_NOALIAS), poptStrerror(c));

  if (poptPeekArg(optCon) || !secret)
  {
    poptPrintUsage(optCon, stderr, 0);
    return -1;
  }

  if (background)
  {
    pid_t pid = fork();
    if (pid < 0)
      errx(1, "fork");
    if (pid > 0)
      return 0;
    if (daemon(0, 0))
      err(1, "daemon");
  }

  openlog(bindport, LOG_CONS, LOG_LOCAL7);
  syslog(LOG_INFO, "Started");
  sqlsyslogerror = LOG_INFO;

  int s = -1;
  {                             // bind
    struct addrinfo hints = {
    ai_family: AF_UNSPEC, ai_socktype:SOCK_DGRAM
    };
    if (!bindhost)
      hints.ai_flags |= AI_PASSIVE;
    struct addrinfo *res;
    int e = getaddrinfo(bindhost, bindport, &hints, &res);
    if (e)
      errx(1, "getaddrinfo: %s (%s)", gai_strerror(e), bindport);
    if (!res)
      errx(1, "Cannot find bind address");
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0)
      err(1, "socket");
    int on = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
      err(1, "setsockopt");
    if (bind(s, res->ai_addr, res->ai_addrlen))
      err(1, "bind");
    freeaddrinfo(res);
  }

  // SQL connect
  SQL sql;
  sql_real_connect(&sql, sqlhost, sqluser, sqlpass, database, 0, 0, 0, 1, sqlconf);
  {
    SQL_RES *res = sql_query_store_free(&sql, sql_printf("DESCRIBE `%#S`", tableauth));
    if (res)
    {
      while (sql_fetch_row(res))
      {
#define a(x,t)  if(!strcasecmp(sql_colz(res,"Field"),#x))auth_##x=1;
        authfields;
#undef  a
      }
      sql_free_result(res);
    }
  }

  while (1)
  {                             // Main loop
    ui8 rx[1500], tx[1500];
    ui8 *txp = tx + 20;
    int rxl = 0;
    struct sockaddr_in6 from;
    socklen_t fromlen = sizeof(from);
    rxl = recvfrom(s, rx, sizeof(rx), 0, (struct sockaddr *)&from, &fromlen);
    if (rxl < 0)
    {
      syslog(LOG_INFO, "Bad recv");
      continue;
    }
    char addr[INET6_ADDRSTRLEN + 1] = "";
    if (from.sin6_family == AF_INET)
      inet_ntop(from.sin6_family, &((struct sockaddr_in *)&from)->sin_addr, addr, sizeof(addr));
    else
      inet_ntop(from.sin6_family, &from.sin6_addr, addr, sizeof(addr));
    if (!strncmp(addr, "::ffff:", 7))
      strcpy(addr, addr + 7);

    // Check length, etc
    if (rxl < 20)
    {
      syslog(LOG_INFO, "Bad length %u from %s", rxl, addr);
      continue;                 // invalid length
    }

    {                           // check cache
      cache_t *c = &cache[rx[1]];
      if (c->rxlen == rxl && !memcmp(c->rx, rx, rxl))
      {                         // cache match
        syslog(LOG_INFO, "%u Duplicate request from %s (%u)", rx[1], addr, rxl);
        if (sendto(s, c->tx, c->txlen, 0, (struct sockaddr *)&from, fromlen) < 0)
          syslog(LOG_INFO, "Failed reply");
        continue;
      }
    }

    ui8 *e = rx + rxl, *m;

    ui8 *find(ui8 tag)
    {                           // find an AVP by tag
      ui8 *m;
      for (m = rx + 20; m < e && *m != tag && m[1] >= 2; m += m[1]) ;
      if (m < e && *m == tag && m[1] >= 2)
        return m;
      return NULL;
    }
    void send_reply(ui8 code)
    {                           // send a reply
      tx[0] = code;
      tx[1] = rx[1];
      ui32 txl = txp - tx;
      tx[2] = (txl >> 8);
      tx[3] = txl;
      memcpy(tx + 4, rx + 4, 16);
      MD5_CTX context;
      MD5_Init(&context);
      MD5_Update(&context, tx, txl);
      MD5_Update(&context, secret, strlen(secret));
      MD5_Final(tx + 4, &context);
      // add to cache
      cache_t *c = &cache[rx[1]];
      if (c->rxlen)
        free(c->rx);
      if (c->txlen)
        free(c->tx);
      memcpy(c->rx = malloc(c->rxlen = rxl), rx, rxl);
      memcpy(c->tx = malloc(c->txlen = txl), tx, txl);
      if (sendto(s, tx, txl, 0, (struct sockaddr *)&from, fromlen) < 0)
        syslog(LOG_INFO, "Failed reply");
    }
    void add_ui32(ui8 code, ui32 n)
    {                           // add numeric avp
      *txp++ = code;
      *txp++ = 6;
      *txp++ = (n >> 24);
      *txp++ = (n >> 16);
      *txp++ = (n >> 8);
      *txp++ = n;
    }
    void add_string(ui8 code, char *s)
    {                           // add string avp
      ui32 l = strlen(s);
      *txp++ = code;
      *txp++ = l + 2;
      memcpy(txp, s, l);
      txp += l;
    }
    void add_f(ui8 code, const char *fmt, ...)
    {                           // Add formatted string
      *txp++ = code;
      va_list ap;
      va_start(ap, fmt);
      int len = vsprintf((char *)txp + 1, fmt, ap);
      va_end(ap);
      *txp++ = len + 2;
      txp += len;
    }

    char *fail = NULL;          // Failure reason

    if ((rx[2] << 8) + rx[3] != rxl)
    {
      syslog(LOG_INFO, "Bad length %u/%u", rxl, (rx[2] << 8) + rx[3]);
      continue;
    }

    if (*rx == RADIUS_STATUS_SERVER)
    {                           // status server
      tx[0] = 2;
      tx[1] = rx[1];
      ui32 txl = txp - tx;
      tx[2] = (txl >> 8);
      tx[3] = txl;
      memmove(tx + 4, rx + 4, 16);
      {
        MD5_CTX context;
        MD5_Init(&context);
        MD5_Update(&context, tx, txl);
        MD5_Update(&context, secret, strlen(secret));
        MD5_Final(tx + 4, &context);
      }
      if (sendto(s, tx, txl, 0, (struct sockaddr *)&from, fromlen) < 0)
        syslog(LOG_INFO, "Failed reply");
      continue;
    }

    if (*rx != RADIUS_ACCESS_REQUEST)
    {
      if (sqldebug)
        fprintf(stderr, "Unexpected %u?\n", *rx);
      syslog(LOG_INFO, "Not auth %u", *rx);
      continue;
    }

    // process
    int noreply = 0;

    if ((m = find(RADIUS_AVP_MESSAGE_AUTHENTICATOR)) && m[1] == 18 && secret)
    {
      ui8 hash[16], test[16];
      memcpy(hash, m + 2, 16);
      memset(m + 2, 0, 16);
      HMAC_MD5(test, strlen(secret), (ui8 *)secret, rxl, rx);
      if (memcmp(hash, test, 16))
      {
        if (sqldebug)
          fprintf(stderr, "Invalid authenticator\n");
        syslog(LOG_INFO, "Invalid Message authenticator");
        continue;
      }
    }
    else if (!noma)
    {
      if (sqldebug)
        fprintf(stderr, "No authenticator\n");
      syslog(LOG_INFO, "No message authenticator");
      continue;
    }

    char note[1000] = "";
    // Extract key fields
    char ras[40] = { };
    char lns[65] = { };
    char login[65] = { };
    char loginprefix[65] = { };
    char loginsuffix[65] = { };
    char loginusername[65] = { };
    char loginrealm[65] = { };
    char calling[65] = { };
    char called[31] = { };
    char carrier[31] = { };
    ui32 tx_speed = 0;
    ui32 rx_speed = 0;
    if ((m = find(RADIUS_AVP_USER_NAME)))
    {
      ui8 l = m[1] - 2;
      if (l > sizeof(login) - 1)
        l = sizeof(login) - 1;
      memcpy(login, m + 2, l);
      login[l] = 0;
      strcpy(loginprefix, login);
      char *p = loginprefix;
      while (*p && isalnum(*p))
        p++;
      if (*p && *p == '-')
      {
        *p++ = 0;
        strcpy(loginsuffix, p);
        p = loginsuffix;
        while (*p != '@')
          p++;
      }
      *p = 0;
      strcpy(loginusername, login);
      p = loginusername;
      while (*p && *p != '@')
        p++;
      if (*p)
      {
        *p++ = 0;
        strcpy(loginrealm, p);
      }
    }
    if ((m = find(RADIUS_AVP_CONNECT_INFO)))
    {
      ui8 *p = m + 2, *e = m + m[1];
      while (p < e && isdigit(*p))
        tx_speed = tx_speed * 10 + *p++ - '0';
      if (p < e && *p == '/')
      {
        p++;
        while (p < e && isdigit(*p))
          rx_speed = rx_speed * 10 + *p++ - '0';
      }
      sprintf(note + strlen(note), " linerate=%.*s", m[1] - 2, (char *)m + 2);
    }
    if ((m = find(RADIUS_AVP_NAS_IP_ADDRESS)) && m[1] == 6)
      inet_ntop(AF_INET, m + 2, (void *)ras, sizeof(ras));
    else if ((m = find(RADIUS_AVP_NAS_IPV6_ADDRESS)) && m[1] == 18)
      inet_ntop(AF_INET6, m + 2, (void *)ras, sizeof(ras));
    if ((m = find(RADIUS_AVP_TUNNEL_CLIENT_ENDPOINT)))
    {
      ui8 l = m[1] - 2;
      if (l > sizeof(carrier) - 1)
        l = sizeof(carrier) - 1;
      memcpy(carrier, m + 2, l);
      carrier[l] = 0;
    }
    if ((m = find(RADIUS_AVP_CALLED_STATION_ID)))
    {
      ui8 l = m[1] - 2;
      if (l > sizeof(called) - 1)
        l = sizeof(called) - 1;
      memcpy(called, m + 2, l);
      called[l] = 0;
    }
    if ((m = find(RADIUS_AVP_CALLING_STATION_ID)))
    {
      ui8 l = m[1] - 2;
      if (l > sizeof(calling) - 1)
        l = sizeof(calling) - 1;
      m += 2;
      if (l && *m == '+')
      {                         // Allow for full int format
        m++;
        l--;
      }
      memcpy(calling, m, l);
      calling[l] = 0;
    }
    else
      fail = "No calling number";
    if ((m = find(RADIUS_AVP_NAS_IDENTIFIER)))
    {
      ui8 l = m[1] - 2;
      if (l > sizeof(lns) - 1)
        l = sizeof(lns) - 1;
      memcpy(lns, m + 2, l);
      lns[l] = 0;
    }

    {
      SQL_RES *res = NULL;
      // Multiple stage checks
      if (!res && auth_carrier_circuit_id)
      {                         // carrier related
        sql_string_t q = { };
        sql_sprintf(&q, "SELECT * FROM `%#S` WHERE `carrier_circuit_id`=%#s", tableauth, calling);
        if (auth_carrier && *carrier)
          sql_sprintf(&q, " AND `carrier`=%#s", carrier);
        res = sql_query_store_s(&sql, &q);
        if (res && !sql_fetch_row(res))
        {
          sql_free_result(res);
          res = NULL;
        }
      }
      if (!res && auth_login_prefix)
      {                         // login prefix
        sql_string_t q = { };
        sql_sprintf(&q, "SELECT * FROM `%#S` WHERE `login_prefix`=%#s", tableauth, loginprefix);
        if (auth_login_suffix && *loginsuffix)
          sql_sprintf(&q, " AND `login_suffix`=%#s", loginsuffix);
        if (auth_realm && *loginrealm)
          sql_sprintf(&q, " AND `realm`=%#s", loginrealm);
        if (auth_carrier && *carrier)
          sql_sprintf(&q, " AND `carrier`=%#s", carrier);
        res = sql_query_store_s(&sql, &q);
        if (res && !sql_fetch_row(res))
        {
          sql_free_result(res);
          res = NULL;
        }
      }
      if (!res && auth_username)
      {                         // login username
        sql_string_t q = { };
        sql_sprintf(&q, "SELECT * FROM `%#S` WHERE `username`=%#s", tableauth, loginusername);
        if (auth_realm && *loginrealm)
          sql_sprintf(&q, " AND `realm`=%#s", loginrealm);
        if (auth_carrier && *carrier)
          sql_sprintf(&q, " AND `carrier`=%#s", carrier);
        res = sql_query_store_s(&sql, &q);
        if (res && !sql_fetch_row(res))
        {
          sql_free_result(res);
          res = NULL;
        }
      }
      if (!res && auth_login)
      {                         // login login
        sql_string_t q = { };
        sql_sprintf(&q, "SELECT * FROM `%#S` WHERE `login`=%#s", tableauth, login);
        if (auth_carrier && *carrier)
          sql_sprintf(&q, " AND `carrier`=%#s", carrier);
        res = sql_query_store_s(&sql, &q);
        if (res && !sql_fetch_row(res))
        {
          sql_free_result(res);
          res = NULL;
        }
      }
      if (!res)
        fail = "Login/circuit not found";
      else
      {                         // Attributes for connection
        char *temp;
        if (*carrier && (temp = sql_col(res, "carrier")) && strcmp(temp, carrier))
          snprintf(note, sizeof(note), "Carrier mismatch [%s/%s]", temp, carrier);
        if (*calling && (temp = sql_col(res, "carrier_circuit_id")) && strcmp(temp, calling))
          snprintf(note, sizeof(note), "Carrier circuit ID mismatch [%s/%s]", temp, calling);
        if (*loginprefix && (temp = sql_col(res, "login_prefix")) && strcmp(temp, loginprefix))
          snprintf(note, sizeof(note), "Login prefix mismatch [%s/%s]", temp, loginprefix);
        if (*loginsuffix && (temp = sql_col(res, "login_suffix")) && strcmp(temp, loginsuffix))
          snprintf(note, sizeof(note), "Login suffix mismatch [%s/%s]", temp, loginsuffix);
        if (*loginusername && (temp = sql_col(res, "username")) && strcmp(temp, loginusername))
          snprintf(note, sizeof(note), "Login username mismatch [%s/%s]", temp, loginusername);
        if (*loginrealm && (temp = sql_col(res, "realm")) && strcmp(temp, loginrealm))
          snprintf(note, sizeof(note), "Login realm mismatch [%s/%s]", temp, loginrealm);
        if (*login && (temp = sql_col(res, "login")) && strcmp(temp, login))
          snprintf(note, sizeof(note), "Login mismatch [%s/%s]", temp, login);
        if ((temp = sql_col(res, "password")))
        {                       // password check (unless NULL)
          char l = 16;
          unsigned char *h = rx + 4;
          unsigned char *c = find(60);
          if (c)
          {
            l = c[1] - 2;
            h = c + 2;
          }
          if ((c = find(3)) && c[1] == 19)
          {                     // CHAP
            char hash[16];
            MD5_CTX context;
            MD5_Init(&context);
            MD5_Update(&context, c + 2, 1);
            MD5_Update(&context, temp, strlen((char *)temp));
            MD5_Update(&context, h, l);
            MD5_Final((unsigned char *)hash, &context);
            if (memcmp(hash, c + 3, 16))
              fail = "Bad credentials";
          }
          else if ((c = find(2)) && c[1] >= 18)
          {                     // PAP
            char hash[16];
            MD5_CTX context;
            MD5_Init(&context);
            MD5_Update(&context, secret, strlen(secret));
            MD5_Update(&context, rx + 4, 16);
            MD5_Final((unsigned char *)hash, &context);
            unsigned char *p = c + 2;
            unsigned char *e = c + c[1];
            while (p < e)
            {
              if (p + 16 < e)
              {
                MD5_Init(&context);
                MD5_Update(&context, secret, strlen(secret));
                MD5_Update(&context, p, 16);
              }
              int n;
              for (n = 0; n < 16 && p < e; n++)
                *p++ ^= hash[n];
              if (p < e)
                MD5_Final((unsigned char *)hash, &context);
            }
            while (p > c + 2 && !p[-1])
              p--;
            if (p - c - 2 != strlen((char *)temp) || strncmp((char *)c + 2, (char *)temp, p - c - 2))
              fail = "Wrong credentials";
          }
          else
            fail = "No password";
        }
        if (!fail)
        {
          if ((temp = sql_col(res, "cui")) && *temp)
            add_string(RADIUS_AVP_CHARGEABLE_USER_IDENTITY, temp);      // Override CUI (graph)
          else if (assigncui && (temp = sql_col(res, "ID")))
          {                     // Assigned CUI from ID and prefix
            char *c;
            if (asprintf(&c, "%s%s", assigncui, temp) < 0)
              errx(1, "malloc");
            add_string(RADIUS_AVP_CHARGEABLE_USER_IDENTITY, c);
            free(c);
          }
          {                     // General filter controls - see firebrick manual
            char f;
            for (f = 'a'; f <= 'z'; f++)
            {
              char field[20];
              sprintf(field, "filter_%c", f);
              if (*(temp = sql_colz(res, field)))
              {                 // Field exists and has a value
                if (!strcasecmp(temp, "Y") || !strcasecmp(temp, "true"))
                {               // Set filter (upper case)
                  *field = toupper(f);
                  field[1] = 0;
                  add_string(RADIUS_AVP_FILTER_ID, field);
                }
                else if (!strcasecmp(temp, "N") || !strcasecmp(temp, "false"))
                {               // Unset filter (lower case)
                  *field = tolower(f);
                  *field = toupper(f);
                  field[1] = 0;
                  add_string(RADIUS_AVP_FILTER_ID, field);
                }
                else if (isdigit(*temp))
                {               // Upper case filter value
                  snprintf(field, sizeof(field), "%c%d", toupper(f), atoi(temp));
                  add_string(RADIUS_AVP_FILTER_ID, field);
                }
              }
            }
          }
          if (*(temp = sql_colz(res, "session_timeout")))
            add_ui32(RADIUS_AVP_SESSION_TIMEOUT, atoi(temp));
          if (*(temp = sql_colz(res, "lcp_rate")))
            add_f(RADIUS_AVP_FILTER_ID, "S%d", atoi(temp));
          if (*(temp = sql_colz(res, "lcp_timeout")))
            add_f(RADIUS_AVP_FILTER_ID, "s%d", atoi(temp));
          if (*(temp = sql_colz(res, "class")))
            add_string(RADIUS_AVP_CLASS, temp); // Additional graph, e.g. account level grouping
          if (*(temp = sql_col(res, "table_number")))
            add_f(RADIUS_AVP_FILTER_ID, "T%d", atoi(temp));     // Routing table
          else if (*(temp = sql_colz(res, "table")))
            add_f(RADIUS_AVP_FILTER_ID, "T%d", atoi(temp));     // Routing table
          if ((temp = sql_col(res, "speed")))
            add_string(RADIUS_AVP_CONNECT_INFO, temp);
          if (tx_speed && tx_speed < 1000000000 && (temp = sql_col(res, "speed_adjust")) && atoi(temp))
          {
            tx_speed = (long long)tx_speed *atoi(temp) / 100;
            add_f(RADIUS_AVP_CONNECT_INFO, "%u", tx_speed);
          }
          else if (defaultspeed)
            add_f(RADIUS_AVP_CONNECT_INFO, "%u", defaultspeed); // Tx speed
          if (*(temp = sql_colz(res, "relay"))) // Relay to L2TP (hostname or IP
          {                     // L2TP relay details
            if ((temp = sql_col(res, "login")))
              add_string(RADIUS_AVP_USER_NAME, temp);   // Override username
            if ((temp = sql_col(res, "calling")))
              add_string(RADIUS_AVP_CALLING_STATION_ID, temp);  // Override calling ID
            if ((temp = sql_col(res, "called")))
              add_string(RADIUS_AVP_CALLED_STATION_ID, temp);   // Override called ID
            if (*temp == '*')
            {                   // Relay session steering rather than L2TP
              add_string(RADIUS_AVP_TUNNEL_SERVER_ENDPOINT, temp + 1);
              add_ui32(RADIUS_AVP_TUNNEL_TYPE, 'S');
            }
            else
              add_string(RADIUS_AVP_TUNNEL_SERVER_ENDPOINT, temp);
            if (*(temp = sql_colz(res, "relay_hostname")))
              add_string(RADIUS_AVP_TUNNEL_CLIENT_AUTH_ID, temp);       // Hostname (login)
            if (*(temp = sql_colz(res, "relay_graph")))
              add_string(RADIUS_AVP_TUNNEL_PRIVATE_GROUP_ID, temp);     // Graph for relay
            if (*(temp = sql_colz(res, "relay_password")))
            {                   // Encode password
              ui8 buf[257], l, q = 0, mix[16];
              memset(buf, 0, sizeof(buf));
              l = strlen(temp);
              buf[0] = l;
              memmove(buf + 1, temp, l);
              l++;
              if (l & 15)
                l = (l | 15) + 1;
              txp[0] = RADIUS_AVP_TUNNEL_PASSWORD;
              txp[2] = 0;
              txp[3] = rand();
              txp[4] = rand();
              MD5_CTX context;
              MD5_Init(&context);
              MD5_Update(&context, secret, strlen(secret));
              MD5_Update(&context, rx + 4, 16);
              MD5_Update(&context, txp + 3, 2);
              MD5_Final(mix, &context);
              while (q < l)
              {
                int z;
                for (z = 0; z < 16; z++)
                  txp[5 + q + z] = (buf[q + z] ^ mix[z]);
                q += 16;
                if (q == l)
                  break;
                MD5_Init(&context);
                MD5_Update(&context, secret, strlen(secret));
                MD5_Update(&context, txp + 5 + q - 16, 16);
                MD5_Final(mix, &context);
              }
              txp[1] = l + 5;
              txp += l + 5;
            }
          }
          else
          {                     // Non tunnel stuff like IPs
            unsigned char ip4[4];
            if ((temp = sql_col(res, "ip4_dns")))
            {
              temp = strdupa(temp);
              char *s = strchr(temp, ' ');
              if (s)
                *s++ = 0;
              if (inet_pton(AF_INET, temp, ip4) > 0)
              {                 // Primary DNS
                *txp++ = RADIUS_AVP_VENDOR_SPECIFIC;
                *txp++ = 12;
                *txp++ = (RADIUS_VENDOR_MICROSOFT >> 24);
                *txp++ = (RADIUS_VENDOR_MICROSOFT >> 16);
                *txp++ = (RADIUS_VENDOR_MICROSOFT >> 8);
                *txp++ = (RADIUS_VENDOR_MICROSOFT & 0xFF);
                *txp++ = 28;
                *txp++ = 6;
                memcpy(txp, ip4, 4);
                txp += 4;
              }
              if (s && inet_pton(AF_INET, s, ip4) > 0)
              {                 // Secondary DNS
                *txp++ = RADIUS_AVP_VENDOR_SPECIFIC;
                *txp++ = 12;
                *txp++ = (RADIUS_VENDOR_MICROSOFT >> 24);
                *txp++ = (RADIUS_VENDOR_MICROSOFT >> 16);
                *txp++ = (RADIUS_VENDOR_MICROSOFT >> 8);
                *txp++ = (RADIUS_VENDOR_MICROSOFT & 0xFF);
                *txp++ = 29;
                *txp++ = 6;
                memcpy(txp, ip4, 4);
                txp += 4;
              }
            }
            if (inet_pton(AF_INET, sql_colz(res, "ip4_ppp"), ip4) > 0)
            {                   // Change our PPP IP address
              *txp++ = RADIUS_AVP_NAS_IP_ADDRESS;
              *txp++ = 6;
              memcpy(txp, ip4, 4);
              txp += 4;
            }
            if (inet_pton(AF_INET, sql_colz(res, "ip4_wan"), ip4) <= 0)
            {                   // Dynamic or don't care
              unsigned int v = atoi(sql_colz(res, "ID"));
              ip4[0] = 10;
              ip4[1] = v >> 16;
              ip4[2] = v >> 8;
              ip4[3] = v;
              snprintf(note, sizeof(note), "No IPv4 WAN defined");
            }
            *txp++ = RADIUS_AVP_FRAMED_IP_ADDRESS;
            *txp++ = 6;
            memcpy(txp, ip4, 4);
            txp += 4;
            unsigned char ip6[16];
            if (inet_pton(AF_INET6, sql_colz(res, "ip6wan"), ip6) > 0)
            {
              *txp++ = RADIUS_AVP_FRAMED_IPV6_ADDRESS;
              *txp++ = 18;
              memcpy(txp, ip6, 16);
              txp += 16;
            }
            char *i = sql_col(res, "ip4");
            if (i)
              i = strdupa(i);
            while (i && *i)
            {
              char *m = " 0.0.0.0 100";
              char *s = strchr(i, ' ');
              if (s)
                *s++ = 0;
              if (txp + 2 + strlen(i) + strlen(m) >= tx + sizeof(tx))
                break;
              *txp++ = RADIUS_AVP_FRAMED_ROUTE;
              *txp++ = 2 + strlen(i) + strlen(m);
              strcpy((char *)txp, i);
              txp += strlen(i);
              strcpy((char *)txp, m);
              txp += strlen(m);
              i = s;
            }
            i = sql_col(res, "ip6");
            if (i)
              i = strdupa(i);
            while (i && *i)
            {
              char *m = " :: 100";
              char *s = strchr(i, ' ');
              if (s)
                *s++ = 0;
              if (txp + 2 + strlen(i) + strlen(m) >= tx + sizeof(tx))
                break;
              *txp++ = RADIUS_AVP_FRAMED_IPV6_ROUTE;
              *txp++ = strlen(i) + strlen(m);
              strcpy((char *)txp, i);
              txp += strlen(i);
              strcpy((char *)txp, m);
              txp += strlen(m);
              i = s;
            }
            // Note, metrics would be nice
          }
        }
      }
      sql_free_result(res);
    }

    if (fail)
    {
      if (sqldebug)
        fprintf(stderr, "%s/%s Failed %s [%s] via %s %s %s\n", carrier, calling, fail, login, lns, called, note);
      syslog(LOG_INFO, "%s/%s Failed %s [%s] via %s %s %s", carrier, calling, fail, login, lns, called, note);
      add_string(RADIUS_AVP_REPLY_MESSAGE, (char *)fail);
#ifdef	REJECTTABLE
      add_ui32(RADIUS_AVP_SESSION_TIMEOUT, 3600);       // Timeout
      add_string(RADIUS_AVP_FILTER_ID, "T" quoted(REJECTTABLE));        // Special dead end table
      add_string(RADIUS_AVP_FILTER_ID, "I");    // Isolated from other L2TP
      *txp++ = RADIUS_AVP_FRAMED_IP_ADDRESS;
      *txp++ = 6;
      *txp++ = 10;
      *txp++ = 10;
      *txp++ = 10;
      *txp++ = 10;
      send_reply(RADIUS_ACCESS_ACCEPT);
#else
      send_reply(RADIUS_ACCESS_REJECT);
#endif
      continue;
    }

    if (!noreply)
    {
      if (sqldebug)
        fprintf(stderr, "%s/%s Accept %s %s %s\n", carrier, calling, lns, called, note);
      syslog(LOG_INFO, "%s/%s Accept %s %s %s", carrier, calling, lns, called, note);
      send_reply(RADIUS_ACCESS_ACCEPT);
      continue;
    }
  }
  return 0;
}
