// RADIUS accounting server - based on ChargeableUserId
// © 2009-2018 FireBrick Ltd Adrian Kennard
//
// Tables (apart from Session) are optional, and can be defined on command line or compile time -D settings
// Session      Current live sessions, auto cleared out if sessions lost (LNS reboot, etc)
// History      Completed sessions (recommend archive/pruning periodically)
// Daily        Daily totals per CUI with hourly counters (recommend archive/pruning periodically)
// Blip         Per minute during day totals for login/logout, auto cleared out 5 mins ahead
// Status       Write back for info about CUI (typically this is auth table)
//
// Note that all but Status are created if missing
// Status is checked at start for fields that are present, so those not present are not written to
// Status fields :-

#define	statusfields	\
	s(ID,"If assign-cui is set, this is assumed to be after defined prefix as main key")	\
	s(CUI,"If assign-cui not set, this is assumed to be the CUI to use to key the update")	\
	s(last_login,"Last login")								\
	s(last_logout,"Last logout")								\
	s(last_cause,"Last logout cause")							\
	s(last_tx_speed,"Tx speed")								\
	s(last_rx_speed,"Rx speed")								\
	s(last_lac,"Last LAC IP")								\
	s(last_lns,"Last LNS IP")								\
	s(last_nas,"Last NAS name")								\
	s(last_table_number,"Last table number")						\
	s(last_tunnel,"Last tunnel")								\
	s(last_tunnel_graph,"Last tunnel graph")						\
	s(last_mru,"Last MRU")									\
	s(last_cug,"Last CUG")									\
	s(last_username,"Last username used")							\

#define	s(x,t)	char status_##x=0;
statusfields
#undef	s
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
#include <mysql.h>
#include <mysql/errmsg.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <signal.h>
#include <syslog.h>
#include <openssl/md5.h>
#include <err.h>
#include <popt.h>
#include <time.h>
#include "sqllib.h"
#include "radius-defs.h"
typedef struct cache_s cache_t;
struct cache_s
{
  unsigned int rxlen;
  unsigned char *rx;
};
cache_t cache[256] = { };

SQL sql;
SQL_RES *res;
SQL_ROW row;

typedef unsigned char ui8;
typedef unsigned short ui16;
typedef unsigned int ui32;
typedef unsigned long long ui64;

#ifndef	BLIPLAG
#  define	BLIPLAG 300     // How far ahead to clear out blip table
#endif
#ifndef	SESSIONTIMEOUT
#  define	SESSIONTIMEOUT	10800
                                // Sessions deemed old, and so lost
#endif

const char *sqlhost = NULL;     // Use sqlconf
const char *sqluser = NULL;     // Use sqlconf
const char *sqlpass = NULL;     // Use sqlconf

#define	xquoted(x)	#x
#define	quoted(x)	xquoted(x)
#ifdef	SECRET
const char *secret = quoted(SECRET);
#else
const char *secret = NULL;
#endif
#ifdef	SQLCONF
const char *sqlconf = quoted(SQLCONF);
#else
const char *sqlconf = NULL;
#endif
#ifdef	DATABASE
const char *database = quoted(DATABSE);;
#else
const char *database = NULL;
#endif
#ifdef	SESSION
const char *tablesession = quoted(SESSION);
#else
const char *tablesession = "Session";
#endif
#ifdef	HISTORY
const char *tablehistory = quoted(HISTORY);
#else
const char *tablehistory = "History";
#endif
#ifdef	DAILY
const char *tabledaily = quoted(DAILY);
#else
const char *tabledaily = "Daily";
#endif
#ifdef	BLIP
const char *tableblip = quoted(BLIP);
#else
const char *tableblip = NULL;
#endif
#ifdef	STATUS
const char *tablestatus = quoted(STATUS);
#else
const char *tablestatus = NULL;
#endif
#ifdef	PORT
const char *bindport = quoted(PORT);
#else
const char *bindport = "radius-acct";
#endif
const char *bindhost = NULL;
#ifdef  ASSIGNCUI
const char *assigncui = quoted(ASSIGNCUI);
#else
const char *assigncui = NULL;
#endif
pid_t handler_pid;

void babysit(int s)
{
  pid_t pid;
  while ((pid = waitpid(-1, 0, WNOHANG)) > 0)
    if (pid == handler_pid)
    {
      syslog(LOG_INFO, "Child terminated %u", pid);
      fprintf(stderr, "Child terminated %u\n", pid);
      killpg(0, SIGINT);
    }
  signal(SIGCHLD, &babysit);
}

int handler(int s)
{
  // SQL connect
  sql_real_connect(&sql, sqlhost, sqluser, sqlpass, database, 0, 0, 0, 1, sqlconf);

  // Create tables if missing
  if (tablesession)
  {
    res = sql_query_store_free(&sql, sql_printf("DESCRIBE `%#S`", tablesession));
    if (res)
      sql_free_result(res);
    else
    {
      sql_query_string q = { };
      sql_sprintf(&q, "CREATE TABLE `%#S` (`id` varchar(30) not null primary key comment 'Unique session ID',"  //
                  "`cui` varchar(20) not null comment 'Chargeable User Identity',"      //
                  "`carrier` varchar(30) comment 'Carrier name',"       //
                  "`calling` varchar(30) comment 'Calling ID'," //
                  "`called` varchar(30) comment 'Called ID',"   //
                  "`login` varchar(64) comment 'Login used',"   //
                  "`tunnel` varchar(39) comment 'Tunnel ID',"   //
                  "`tunnel_graph` varchar(20) comment 'Graph name for tunnel'," //
                  "`nas` varchar(128) comment 'NAS name',"      //
                  "`lac` varchar(39) comment 'LAC IP'," //
                  "`lns` varchar(39) comment 'LNS IP'," //
                  "`start` datetime comment 'Start of session',"        //
                  "`last` datetime not null comment 'Last update on session',"  //
                  "`mru` int comment 'Max Rx unit',"    //
                  "`tx_speed` int comment 'Tx speed',"  //
                  "`rx_speed` int comment 'Rx speed',"  //
                  "`table_number` int comment 'Table number',"  //
                  "`cug` varchar(6) comment 'Closed User Group ID',"    //
                  "`U` bigint not null comment 'Upload bytes so far',"  //
                  "`D` bigint not null comment 'Download bytes so far',"        //
                  "`UP` bigint not null comment 'Upload packets so far',"       //
                  "`DP` bigint not null comment 'Download packets so far',"     //
                  "unique key `cui` (`cui`))", tablesession);
      sql_safe_query_s(&sql, &q);
    }
  }
  if (tablehistory)
  {
    res = sql_query_store_free(&sql, sql_printf("DESCRIBE `%#S`", tablehistory));
    if (res)
      sql_free_result(res);
    else
    {
      sql_query_string q = { };
      sql_sprintf(&q, "CREATE TABLE `%#S` (`id` varchar(30) not null primary key comment 'Unique session ID',"  //
                  "`cui` varchar(20) not null comment 'Chargeable User Identity',"      //
                  "`carrier` varchar(30) comment 'Carrier name',"       //
                  "`calling` varchar(30) comment 'Calling ID'," //
                  "`called` varchar(30) comment 'Called ID',"   //
                  "`login` varchar(64) comment 'Login used',"   //
                  "`tunnel` varchar(39) comment 'Tunnel ID',"   //
                  "`tunnel_graph` varchar(20) comment 'Graph for tunnel',"      //
                  "`nas` varchar(128) comment 'NAS Name',"      //
                  "`lac` varchar(39) comment 'LAC IP'," //
                  "`lns` varchar(39) comment 'LNS IP'," //
                  "`start` datetime comment 'Start of session',"        //
                  "`finish` datetime not null comment 'End of session',"        //
                  "`mru` int comment 'Max Rx Unit',"    //
                  "`tx_speed` int comment 'Tx Speed',"  //
                  "`rx_speed` int comment 'Rx speed',"  //
                  "`table_number` int comment 'Table number',"  //
                  "`cug` varchar(6) comment 'Closed User Group',"       //
                  "`U` bigint not null comment 'Total Upload bytes',"   //
                  "`D` bigint not null comment 'Total Download bytes'," //
                  "`UP` bigint not null comment 'Total Upload packets',"        //
                  "`DP` bigint not null comment 'Total Download packets',"      //
                  "`cause` int not null comment 'Final clear code')", tablehistory);
      sql_safe_query_s(&sql, &q);
    }
  }
  if (tablestatus)
  {
    res = sql_query_store_free(&sql, sql_printf("DESCRIBE `%#S`", tablestatus));
    if (res)
    {
      while (sql_fetch_row(res))
      {
#define s(x,t)	if(!strcasecmp(sql_colz(res,"Field"),#x))status_##x=1;
        statusfields;
#undef	s
      }
      sql_free_result(res);
    }
    // Not created if missing, we are just interested in the fields that exist that we use...
  }
  void blipcatchup(time_t when)
  {                             // Remove old records from yesterday
    static time_t prev = 0;
    while ((when + BLIPLAG) / 60 > prev / 60)
    {
      if (when - prev > 86400)
        prev = when;
      prev += 60;
      char temp[10];
      strftime(temp, sizeof(temp), "%H:%M", localtime(&prev));
      sql_safe_query_free(&sql, sql_printf("DELETE FROM `%#S` WHERE `tod`=%#s", tableblip, temp));
    }
  }
  if (tableblip)
  {
    res = sql_query_store_free(&sql, sql_printf("DESCRIBE `%#S`", tableblip));
    if (res)
    {
      sql_free_result(res);
      blipcatchup(time(0));
    }
    else
      sql_safe_query_free(&sql, sql_printf("CREATE TABLE `%#S` (`logins` int not null comment 'Number of logins',"      //
                                           "`logouts` int not null comment 'Number of logouts',"        //
                                           "`tod` time not null comment 'Time of day to minute' primary key)",
                                           tableblip));
  }
  if (tabledaily)
  {
    res = sql_query_store_free(&sql, sql_printf("DESCRIBE `%#S`", tabledaily));
    if (res)
      sql_free_result(res);
    else
    {
      int h;
      sql_query_string q = { };
      sql_sprintf(&q, "CREATE TABLE `%#S` (`cui` varchar(20) not null comment 'Chargeable User Identity',",     //
                  "`dated` date not null comment 'Date of record',"     //
                  "`dow` varchar(3) not null comment 'Day of week',"    //
                  "`U` bigint not null comment 'Upload bytes for day'," //
                  "`D` bigint not null comment 'Download bytes for day',"       //
                  "`PU` bigint not null comment 'Upload packets for day',"      //
                  "`PD` bigint not null comment 'Download packets for day'", tabledaily);
      for (h = 0; h < 24; h++)
        sql_sprintf(&q, ",`D%02d` bigint not null comment 'Download packets for hour'," //
                    "`U%02d` bigint not null comment 'Upload packets for hour'", h, h);
      sql_sprintf(&q, ",primary key (`dated`,`cui`");
      sql_sprintf(&q, "), key dow (`dow`))");
      sql_safe_query_s(&sql, &q);
    }
  }

  while (1)
  {
    ui8 rx[1500];
    int rxl;
    rxl = recv(s, rx, sizeof(rx), 0);
    if (rxl < 16)
      continue;

    {                           // Clean up
      static time_t last = 0;
      time_t now = time(0);
      if (now > last + 3600)
      {
        last = now;
        sql_safe_query_free(&sql, sql_printf("DELETE FROM `%#S` WHERE `last`<%#T", tablesession, now - SESSIONTIMEOUT));
        // This would be neater if copied to history with a special cause code
      }
    }

    rxl -= 16;
    ui8 *e = rx + rxl, *m;
    ui8 *find(ui8 tag)
    {                           // find a tag
      ui8 *m;
      for (m = rx + 20; m < e && *m != tag && m[1] >= 2; m += m[1]) ;
      if (m < e && *m == tag && m[1] >= 2)
        return m;
      return NULL;
    }
    ui64 val(ui8 *m)
    {
      ui64 v = 0;
      if (m[1] == 6)
      {
        v = m[2];
        v = (v << 8) + m[3];
        v = (v << 8) + m[4];
        v = (v << 8) + m[5];
      }
      return v;
    }
    if (!(m = find(RADIUS_AVP_ACCT_STATUS_TYPE)) || m[1] != 6)
    {
      syslog(LOG_INFO, "No Accounting Status Attribute");
      continue;
    }

    ui32 type = val(m);
    ui8 id[30] = { };
    char cui[51] = { };
    ui8 nas[40] = { };
    ui8 login[65] = { };
    ui8 calling[51] = { };
    ui8 called[51] = { };
    ui8 tunnel[40] = { };
    ui8 tgraph[40] = { };
    ui8 carrier[31] = { };
    ui32 table = 0;
    ui32 tx_speed = 0;
    ui32 rx_speed = 0;
    ui32 mru = 0;
    char cug[10] = { };
    char start[20] = { };
    ui64 i0 = 0, i1 = 0, o0 = 0, o1 = 0;
    ui64 ip0 = 0, ip1 = 0, op0 = 0, op1 = 0;
    time_t when = 0;
    time_t last = 0;
    char lacip[40] = "[unknown-lac]";
    char lnsip[40] = "[unknown-lns]";
    //unsigned int nasport = 0;
    if ((m = find(RADIUS_AVP_NAS_IP_ADDRESS)) && m[1] == 2 + 4)
    {
      inet_ntop(AF_INET, m + 2, lacip, sizeof(lacip));
      do
        m += m[1];
      while (m + 1 < e && m + m[1] <= e && *m != RADIUS_AVP_NAS_IP_ADDRESS && m[1] >= 2);
      if (m + 1 < e && *m == RADIUS_AVP_NAS_IP_ADDRESS && m[1] >= 2 && m + m[1] <= e && m[1] == 2 + 4)
        inet_ntop(AF_INET, m + 2, lnsip, sizeof(lnsip));
    }
    else if ((m = find(RADIUS_AVP_NAS_IPV6_ADDRESS)) && m[1] == 2 + 16)
    {
      inet_ntop(AF_INET6, m + 2, lacip, sizeof(lacip));
      do
        m += m[1];
      while (m + 1 < e && m + m[1] <= e && *m != RADIUS_AVP_NAS_IPV6_ADDRESS && m[1] >= 2);
      if (m + 1 < e && *m == RADIUS_AVP_NAS_IPV6_ADDRESS && m[1] >= 2 && m + m[1] <= e && m[1] == 2 + 16)
        inet_ntop(AF_INET6, m + 2, lnsip, sizeof(lnsip));
    }
    //if ((m = find(RADIUS_AVP_NAS_PORT)) && m[1] == 6)
      //nasport = (m[2] << 24) + (m[3] << 16) + (m[4] << 8) + m[5];
    if (!(m = find(RADIUS_AVP_ACCT_SESSION_ID)) || m[1] - 2 > sizeof(id) - 1)
    {
      syslog(LOG_INFO, "No Accounting Session ID Attribute");
      continue;
    }
    memcpy(id, m + 2, m[1] - 2);
    id[m[1] - 2] = 0;
    if ((m = find(RADIUS_AVP_ACCT_EVENT_TIMESTAMP)) && m[1] == 6)
      when = val(m);
    else if ((m = find(RADIUS_AVP_ACCT_DELAY_TIME)) && m[1] == 6)
      when = time(0) - val(m);
    else
      when = time(0);
    {
      time_t now = time(0);
      if (when > now + 300)
      {
        syslog(LOG_INFO, "%s time +%u\n", cui, (int)(when - now));
        when = now;
      }
    }
    last = when;
    if ((m = find(RADIUS_AVP_NAS_IDENTIFIER)))
    {
      ui8 l = m[1] - 2;
      if (l > sizeof(nas) - 1)
        l = sizeof(nas) - 1;
      memcpy(nas, m + 2, l);
      nas[l] = 0;
    }
    if ((m = find(RADIUS_AVP_TUNNEL_CLIENT_ENDPOINT)))
    {
      ui8 l = m[1] - 2;
      if (l > sizeof(carrier) - 1)
        l = sizeof(carrier) - 1;
      memcpy(carrier, m + 2, l);
      carrier[l] = 0;
    }
    if ((m = find(RADIUS_AVP_USER_NAME)))
    {
      ui8 l = m[1] - 2;
      if (l > sizeof(login) - 1)
        l = sizeof(login) - 1;
      memcpy(login, m + 2, l);
      login[l] = 0;
    }
    if ((m = find(RADIUS_AVP_CHARGEABLE_USER_IDENTITY)))
    {
      ui8 l = m[1] - 2;
      if (l > sizeof(cui) - 2)
        l = sizeof(cui) - 2;
      memcpy(cui, m + 2, l);
      cui[l] = 0;
    }
    char note[1000] = { };

    for (m = rx + 20; m < e && m[1] >= 2; m += m[1])
      if (*m == 11 && m[1] > 2)
      {                         // Filter-Id
        long long v = 0, s = 1;
        ui8 *p = m + 3, *e = m + m[1];
        if (p < e && *p == '-')
        {
          s = -1;
          p++;
        }
        while (p < e && isdigit(*p))
          v = v * 10 + *p++ - '0';
        v *= s;
        if (m[2] == 'T')
          table = v;
        if (m[2] == 'R')
          sprintf(cug, "R%llu", v);
        if (m[2] == 'A')
          sprintf(cug, "A%llu", v);
      }
    if (table)
      sprintf(note + strlen(note), " table=%u", table);

    if (type == 1)
    {                           // start
      if (!*cui)
      {
        syslog(LOG_INFO, "No cui in start message %s", id);
        continue;
      }

      if ((m = find(RADIUS_AVP_FRAMED_MTU)) && m[1] == 6)
      {
        mru = val(m);
        sprintf(note + strlen(note), " MRU=%u", mru);
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
      if ((m = find(RADIUS_AVP_TUNNEL_PRIVATE_GROUP_ID)))
      {
        ui8 l = m[1] - 2;
        if (l > sizeof(tgraph) - 2)
          l = sizeof(tgraph) - 2;
        memcpy(tgraph, m + 2, l);
        tgraph[l] = 0;
      }
      if ((m = find(RADIUS_AVP_TUNNEL_SERVER_ENDPOINT)))
      {
        ui8 l = m[1] - 2;
        if (l > sizeof(tunnel) - 2)
          l = sizeof(tunnel) - 2;
        memcpy(tunnel, m + 2, l);
        tunnel[l] = 0;
      }
      if ((m = find(RADIUS_AVP_CALLING_STATION_ID)))
      {
        ui8 l = m[1] - 2;
        if (l > sizeof(calling) - 2)
          l = sizeof(calling) - 2;
        memcpy(calling, m + 2, l);
        calling[l] = 0;
      }
      if ((m = find(RADIUS_AVP_CALLED_STATION_ID)))
      {
        ui8 l = m[1] - 2;
        if (l > sizeof(called) - 2)
          l = sizeof(called) - 2;
        memcpy(called, m + 2, l);
        called[l] = 0;
      }
      if (*cug)
        sprintf(note + strlen(note), " cug=%s", cug);

      if ((m = find(RADIUS_AVP_FRAMED_INTERFACE_ID)) && m[1] == 10)
        sprintf(note + strlen(note), " I/F=%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", m[2], m[3], m[4], m[5], m[6], m[7],
                m[8], m[9]);

      if (tableblip)
      {
        blipcatchup(when);
        char temp[10];
        strftime(temp, sizeof(temp), "%H:%M", localtime(&when));
        sql_query_free(&sql,
                       sql_printf
                       ("INSERT INTO `%#S` SET `logins`=1,`tod`=%#s ON DUPLICATE KEY UPDATE `logins`=`logins`+1",
                        tableblip, temp));
      }

      syslog(LOG_INFO, "%s Start %s %s%s via %s", cui, login, lacip, note, tunnel);
      // create session record
      sql_query_string q = {
      };
      sql_sprintf(&q, "REPLACE INTO `%#S` SET `id`=%#s,`cui`=%#s,`carrier`=%#s,`calling`=%#s,`called`=%#s,",
                  tablesession, id, cui, carrier, calling, called);
      sql_sprintf(&q, "`tunnel`=%#s,`tunnel_graph`=%#s,`login`=%#s,`nas`=%#s,`lac`=%#s,`lns`=%#s,", tunnel, tgraph, login, nas,
                  lacip,lnsip);
      sql_sprintf(&q, "`start`=%#T,`last`=%#T,`mru`=%u,`tx_speed`=%u,`rx_speed`=%u,`table_number`=%u,`cug`=%#s", when,
                  when, mru, tx_speed, rx_speed, table, cug);
      sql_query_s(&sql, &q);
      if (tablestatus)
      {                         // Update status at start
        sql_query_string q = {
        };
        sql_sprintf(&q, "UPDATE `%#S` SET ", tablestatus);
        if (status_last_login)
          sql_sprintf(&q, "`last_login`=%#T,", when);
        if (status_last_tx_speed)
          sql_sprintf(&q, "`last_tx_speed`=%u,", tx_speed);
        if (status_last_rx_speed)
          sql_sprintf(&q, "`last_rx_speed`=%u,", rx_speed);
        if (status_last_nas)
          sql_sprintf(&q, "`last_nas`=%#s,", nas);
        if (status_last_lac)
          sql_sprintf(&q, "`last_lac`=%#s,", lacip);
        if (status_last_lns)
          sql_sprintf(&q, "`last_lns`=%#s,", lnsip);
        if (status_last_table_number)
          sql_sprintf(&q, "`last_table_number`=%u,", table);
        if (status_last_tunnel)
          sql_sprintf(&q, "`last_tunnel`=%#s,", tunnel);
        if (status_last_tunnel_graph)
          sql_sprintf(&q, "`last_tunnel_graph`=%#s,", tgraph);
        if (status_last_mru)
          sql_sprintf(&q, "`last_mru`=%u,", mru);
        if (status_last_cug)
          sql_sprintf(&q, "`last_cug`=%#s,", cug);
        if (status_last_username)
          sql_sprintf(&q, "`last_username`=%#s,", login);
        if (q.query[q.ptr - 1] != ',')
          sql_free_s(&q);
        else
        {
          q.ptr--;
          if (status_ID && assigncui && !strncmp(cui, assigncui, strlen(assigncui)))
            sql_sprintf(&q, " WHERE `ID`=%#s", cui + strlen(assigncui));
          else if (status_CUI)
            sql_sprintf(&q, " WHERE `CUI`=%#s", cui);
          else
            sql_free_s(&q);
        }
        if (q.ptr)
        {
          sql_query_s(&sql, &q);
          if (sql_affected_rows(&sql))
            syslog(LOG_INFO, "Update to %s did not have any impact", cui);
        }
      }
    }
    if (type == 2 || type == 3)
    {                           // stop or interim

      if ((m = find(RADIUS_AVP_ACCT_INPUT_OCTETS)) && m[1] == 6)
        i1 = val(m);
      if ((m = find(RADIUS_AVP_ACCT_OUTPUT_OCTETS)) && m[1] == 6)
        o1 = val(m);
      if ((m = find(RADIUS_AVP_ACCT_INPUT_PACKETS)) && m[1] == 6)
        ip1 = val(m);
      if ((m = find(RADIUS_AVP_ACCT_OUTPUT_PACKETS)) && m[1] == 6)
        op1 = val(m);
      if ((m = find(RADIUS_AVP_ACCT_INPUT_GIGAWORDS)) && m[1] == 6)
        i1 += (val(m) << 32);
      else
      {
        i1 += ((i0 >> 32) << 32);
        if (i1 < i0)
          i1 += (1ULL << 32);
      }
      if ((m = find(RADIUS_AVP_ACCT_OUTPUT_GIGAWORDS)) && m[1] == 6)
        o1 += (val(m) << 32);
      else
      {
        o1 += ((o0 >> 32) << 32);
        if (o1 < o0)
          o1 += (1ULL << 32);
      }

      res = sql_query_store_free(&sql, sql_printf("SELECT * FROM `%#S` WHERE `id`=%#s", tablesession, id));
      if (!res)
        continue;
      row = sql_fetch_row(res);
      if (!row)
      {
        if (type == 3)
        {
          sql_query_free(&sql,
                         sql_printf
                         ("REPLACE INTO `%#S` SET `id`=%#s,`cui`=%#s,`last`=%#T,`U`=%llu,`D`=%llu,`UP`=%llu,`DP`=%llu",
                          tablesession, id, cui, when, i1, o1, ip1, op1));
          syslog(LOG_INFO, "%s Was not in session table", cui);
        }
        else
          syslog(LOG_INFO, "%s Was not in session table (stop)", cui);
        sql_free_result(res);
        continue;
      }
      if ((m = (ui8 *)sql_col(res, "login")))
        strncpy((char *)login, (char *)m, sizeof(login) - 1);
      if ((m = (ui8 *)sql_col(res, "tunnel")))
        strncpy((char *)tunnel, (char *)m, sizeof(tunnel) - 1);
      if ((m = (ui8 *)sql_col(res, "tunnel_graph")))
        strncpy((char *)tgraph, (char *)m, sizeof(tgraph) - 1);
      if ((m = (ui8 *)sql_col(res, "carrier")))
        strncpy((char *)carrier, (char *)m, sizeof(carrier) - 1);
      if ((m = (ui8 *)sql_col(res, "calling")))
        strncpy((char *)calling, (char *)m, sizeof(calling) - 1);
      if ((m = (ui8 *)sql_col(res, "called")))
        strncpy((char *)called, (char *)m, sizeof(called) - 1);
      if ((m = (ui8 *)sql_col(res, "cui")))
        strncpy(cui, (char *)m, sizeof(cui) - 2);
      if ((m = (ui8 *)sql_col(res, "cug")))
        strncpy(cug, (char *)m, sizeof(cug));
      if ((m = (ui8 *)sql_col(res, "lac")))
        strncpy((char *)lacip, (char *)m, sizeof(lacip));
      if ((m = (ui8 *)sql_col(res, "lns")))
        strncpy((char *)lnsip, (char *)m, sizeof(lnsip));
      if ((m = (ui8 *)sql_col(res, "table")))
        table = atoi((char *)m);
      if ((m = (ui8 *)sql_col(res, "mru")))
        mru = atoi((char *)m);
      if ((m = (ui8 *)sql_col(res, "tx_speed")))
        tx_speed = atoi((char *)m);
      if ((m = (ui8 *)sql_col(res, "rx_speed")))
        rx_speed = atoi((char *)m);
      if ((m = (ui8 *)sql_col(res, "start")))
        strncpy((char *)start, (char *)m, sizeof(start) - 1);
      if ((m = (ui8 *)sql_col(res, "U")))
        i0 = strtoull((char *)m, NULL, 10);
      if ((m = (ui8 *)sql_col(res, "D")))
        o0 = strtoull((char *)m, NULL, 10);
      if ((m = (ui8 *)sql_col(res, "UP")))
        ip0 = strtoul((char *)m, NULL, 10);
      if ((m = (ui8 *)sql_col(res, "DP")))
        op0 = strtoul((char *)m, NULL, 10);
      if ((m = (ui8 *)sql_col(res, "last")))
      {
        int ty, tm, td, tH, tM, tS;
        struct tm t = {
        };
        if (sscanf((char *)m, "%u-%u-%u %u:%u:%u", &ty, &tm, &td, &tH, &tM, &tS) == 6)
        {
          t.tm_year = ty - 1900;
          t.tm_mon = tm - 1;
          t.tm_mday = td;
          t.tm_hour = tH;
          t.tm_min = tM;
          t.tm_sec = tS;
          t.tm_isdst = -1;
          last = mktime(&t);
        }
      }
      sql_free_result(res);
#define MAX	(1ULL<<40)
      if (i1 < i0 || i1 - i0 > MAX || o1 < o0 || o1 - o0 > MAX || ip1 < ip0 || op1 < op0)
      {                         // something wrong
        if (i1 < i0)
          syslog(LOG_INFO, "%s i1=%llu i0=%llu DEBUG", cui, i1, i0);
        if (i1 - i0 > MAX)
          syslog(LOG_INFO, "%s i1=%llu i0=%llu diff=%llu DEBUG", cui, i1, i0, i1 - i0);
        if (o1 < o0)
          syslog(LOG_INFO, "%s o1=%llu o0=%llu DEBUG", cui, o1, o0);
        if (o1 - o0 > MAX)
          syslog(LOG_INFO, "%s o1=%llu o0=%llu diff=%llu DEBUG", cui, o1, o0, o1 - o0);
        if (ip1 < ip0)
          syslog(LOG_INFO, "%s ip1=%llu ip0=%llu DEBUG", cui, ip1, ip0);
        if (op1 < op0)
          syslog(LOG_INFO, "%s op1=%llu op0=%llu DEBUG", cui, op1, op0);
        if ((m = find(RADIUS_AVP_ACCT_INPUT_OCTETS)))
          syslog(LOG_INFO, "%s Record 42=%llu DEBUG\n", cui, val(m));
        if ((m = find(RADIUS_AVP_ACCT_OUTPUT_OCTETS)))
          syslog(LOG_INFO, "%s Record 43=%llu DEBUG\n", cui, val(m));
        if ((m = find(RADIUS_AVP_ACCT_INPUT_GIGAWORDS)))
          syslog(LOG_INFO, "%s Record 52=%llu DEBUG\n", cui, val(m));
        if ((m = find(RADIUS_AVP_ACCT_OUTPUT_GIGAWORDS)))
          syslog(LOG_INFO, "%s Record 53=%llu DEBUG\n", cui, val(m));
        i1 = i0;
        o1 = o0;
        ip1 = ip0;
        op1 = op0;
      }
      if (when > last)
      {
        // update counters
        sql_query_free(&sql,
                       sql_printf
                       ("UPDATE `%#S` SET `U`=%llu,`D`=%llu,`UP`=%llu,`DP`=%llu,`last`=%#T WHERE `id`=%#s",
                        tablesession, i1, o1, ip1, op1, when, id));
        // update actual customer usage
        time_t this = last;
        ui32 total = (ui32)(when - last);
        if (when - last < 86400)
          while (this < when)
          {
            time_t next = this + 3600 - (this % 3600);
            if (next > when)
              next = when;
            struct tm t = *localtime(&this);
            ui32 interval = (ui32)(next - this);
            ui64 i = (i1 - i0) * interval / total;
            ui64 o = (o1 - o0) * interval / total;
            ui64 ip = (ip1 - ip0) * interval / total;
            ui64 op = (op1 - op0) * interval / total;
            {                   // log
              char a[20], b[20];
              strftime(a, sizeof(a), "%H:%M:%S", &t);
              strftime(b, sizeof(b), "%H:%M:%S", localtime(&next));
              syslog(LOG_INFO, "%s Stats %s-%s %14llu %10llu %14llu %10llu%s", cui, a, b, i, ip, o, op, note);
            }

            // stats
            char dated[11];
            char dow[4];
            strftime(dated, sizeof(dated), "%F", &t);
            strftime(dow, sizeof(dated), "%a", &t);
            sql_query_string q = {
            };
            sql_sprintf(&q, "INSERT INTO `%#S` SET `dated`=%#s,`dow`=%#s,`cui`=%#s,", tabledaily, dated, dow, cui);
            sql_sprintf(&q, "`U`=%llu,`D`=%llu,`PU`=%llu,`PD`=%llu,", i, o, ip, op);
            sql_sprintf(&q, "`U%02d`=%llu,`D%02d`=%llu ON DUPLICATE KEY UPDATE ", t.tm_hour, i, t.tm_hour, o);
            sql_sprintf(&q, "`U`=`U`+%llu,`D`=`D`+%llu,`PU`=`PU`+%llu,`PD`=`PD`+%llu,", i, o, ip, op);
            sql_sprintf(&q, "`U%02d`=`U%02d`+%llu,`D%02d`=`D%02d`+%llu", t.tm_hour, t.tm_hour, i, t.tm_hour, t.tm_hour,
                        o);
            sql_query_s(&sql, &q);
            this = next;
          }
      }
    }

    if (type == 2)
    {                           // stop
      static const char *const errs[] = {
        "Unknown", "UserRequest", "LostCarrier", "LostService",
        "IdleTimeout", "SessionTimeout", "AdminReset",
        "AdminReboot", "PortError", "NASError", "NASRequest",
        "NASReboot", "PortUnneeded", "PortPreemted",
        "PortSuspended", "ServiceUnavailable", "Callback", "UserError",
        "HostRequest"
      };
      ui32 cause = 0;
      if ((m = find(RADIUS_AVP_ACCT_TERMINATE_CAUSE)) && m[1] == 6)
        cause = (m[2] << 24) + (m[3] << 16) + (m[4] << 8) + m[5];
      // delete session record
      sql_query_free(&sql, sql_printf("DELETE FROM `%#S` WHERE `id`=%#s", tablesession, id));
      if (tablehistory)
      {                         // create history record
        sql_query_string q = {
        };
        sql_sprintf(&q, "REPLACE INTO `%#S` SET `id`=%#s,`cui`=%#s,`carrier`=%#s,`calling`=%#s,`called`=%#s,",
                    tablehistory, id, cui, carrier, calling, called);
        sql_sprintf(&q, "`tunnel`=%#s,`tunnel_graph`=%#s,`login`=%#s,`nas`=%#s,`lac`=%#s,`lns`=%#s,", tunnel, tgraph, login, nas,
                    lacip,lnsip);
        sql_sprintf(&q, "`start`=%#s,`finish`=%#T,`mru`=%u,`tx_speed`=%u,`rx_speed`=%u,`table_number`=%u,", start, when,
                    mru, tx_speed, rx_speed, table);
        sql_sprintf(&q, "`cug`=%#s,`U`=%llu,`D`=%llu,`UP`=%llu,`DP`=%llu,`cause`=%u", cug, i1, o1, ip1, op1, cause);
        sql_query_s(&sql, &q);
      }
      if (tablestatus && (status_last_logout || status_last_cause))
      {                         // Status update
        sql_query_string q = {
        };
        sql_sprintf(&q, "UPDATE `%#S` SET ", tablestatus);
        if (status_last_logout)
          sql_sprintf(&q, "`last_logout`=%#T,", when);
        if (status_last_cause)
          sql_sprintf(&q, "`last_cause`=%u,", cause);
        if (q.query[q.ptr - 1] != ',')
          sql_free_s(&q);
        else
        {
          q.ptr--;
          if (status_ID && assigncui && !strncmp(cui, assigncui, strlen(assigncui)))
            sql_sprintf(&q, " WHERE `ID`=%#s", cui + strlen(assigncui));
          else if (status_CUI)
            sql_sprintf(&q, " WHERE `CUI`=%#s", cui);
          else
            sql_free_s(&q);
        }
        if (q.ptr)
        {
          sql_query_s(&sql, &q);
          if (sql_affected_rows(&sql))
            syslog(LOG_INFO, "Update to %s did not have any impact", cui);
        }
      }

      if (tableblip)
      {
        blipcatchup(when);
        char temp[10];
        strftime(temp, sizeof(temp), "%H:%M", localtime(&when));
        sql_query_free(&sql,
                       sql_printf
                       ("INSERT INTO `%#S` SET `logouts`=1,`tod`=%#s ON DUPLICATE KEY UPDATE `logouts`=`logouts`+1",
                        tableblip, temp));
      }
      syslog(LOG_INFO, "%s Stopped %s %s\n", cui, login, errs[cause]);
    }
  }
  return 1;
}

typedef struct q_s q_t;
struct q_s
{
  q_t *next;
  int len;
  ui8 buf[];
}  *q = NULL, **last_q = NULL;
int q_l = 0;

int main(int argc, const char *argv[])
{
  //sqlsyslogquery = LOG_INFO;
  char c;
  int background = 0;
  sqlsyslogerror = LOG_INFO;
  poptContext optCon;           // context for parsing command-line options
  const struct poptOption optionsTable[] = {
	  // *INDENT-OFF*
    {"sql-conf", 0, POPT_ARG_STRING|(sqlconf?POPT_ARGFLAG_SHOW_DEFAULT:0), &sqlconf, 0, "SQL .my.cnf", "filename"},
    {"sql-host", 0, POPT_ARG_STRING, &sqlhost, 0, "SQL hostname (use .my.cnf)", "hostname"},
    {"sql-user", 'u', POPT_ARG_STRING, &sqluser, 0, "SQL username (use .my.cnf)", "username"},
    {"sql-pass", 'p', POPT_ARG_STRING, &sqlpass, 0, "SQL password (use .my.cnf)", "password"},
    {"sql-database", 'd', POPT_ARG_STRING|(database?POPT_ARGFLAG_SHOW_DEFAULT:0), &database, 0, "SQL database", "database"},
    {"session", 0, POPT_ARG_STRING | (tablesession?POPT_ARGFLAG_SHOW_DEFAULT:0), &tablesession, 0, "Table name for session", "tablename"},
    {"daily", 0, POPT_ARG_STRING | (tabledaily?POPT_ARGFLAG_SHOW_DEFAULT:0), &tabledaily, 0, "Table name for daily stats", "tablename"},
    {"blip", 0, POPT_ARG_STRING | (tableblip?POPT_ARGFLAG_SHOW_DEFAULT:0), &tableblip, 0, "Table name for blip counters", "tablename"},
    {"status", 0, POPT_ARG_STRING | (tablestatus?POPT_ARGFLAG_SHOW_DEFAULT:0), &tablestatus, 0, "Table name for status", "tablename"},
    {"secret", 's', POPT_ARG_STRING, &secret, 0, "Secret", "RADIUS shared secret"},
    {"bind", 0, POPT_ARG_STRING, &bindhost, 0, "Host to bind", "name/no"},
    {"port", 0, POPT_ARG_STRING | (bindport?POPT_ARGFLAG_SHOW_DEFAULT:0), &bindport, 0, "Port to bind", "name/no"},
#ifndef ASSIGNCUI
    {"assign-cui", 0, POPT_ARG_STRING, &assigncui, 0, "Make CUI from this prefix and ID from auth table","prefix"},
#endif
    {"background", 'b', POPT_ARG_NONE, &background, 0, "Run in background", 0},
    {"debug", 'v', POPT_ARG_NONE, &sqldebug, 0, "Debug", 0},
    POPT_AUTOHELP {NULL, 0, 0, NULL, 0}
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
  //sqlsyslogquery = LOG_INFO;
  int sp[2];
  if (socketpair(AF_LOCAL, SOCK_DGRAM, 0, sp) < 0)
    err(1, "socketpair");
  signal(SIGCHLD, &babysit);
  handler_pid = fork();
  if (!handler_pid)
    return handler(sp[1]);
  fcntl(sp[0], F_SETFL, O_NONBLOCK);
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

  time_t last = 0;
  while (1)
  {
    fd_set f;
    FD_ZERO(&f);
    FD_SET(s, &f);
    struct timeval t = {
      1, 0
    };
    if (select(s + 1, &f, NULL, NULL, &t) > 0)
    {
      ui8 rx[1500], tx[1500];
      ui8 *txp = tx + 20;
      int rxl = 0;
      struct sockaddr_in6 from;
      socklen_t fromlen = sizeof(from);
      rxl = recvfrom(s, rx, sizeof(rx) - 16, 0, (struct sockaddr *)&from, &fromlen);
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
      //syslog(LOG_INFO, "Rx %d (port %s) from %s type %d QL %d", rxl, bindport, addr, *rx, q_l);
      // Check length, etc
      if (rxl < 20)
      {
        syslog(LOG_INFO, "Bad length %u", rxl);
        continue;               // invalid length
      }
      if ((rx[2] << 8) + rx[3] != rxl)
      {
        syslog(LOG_INFO, "Bad length %u/%u", rxl, (rx[2] << 8) + rx[3]);
        continue;
      }
      if (*rx == 4)
      {                         // validate
        ui8 hash[16] = {
        };
        MD5_CTX context;
        MD5_Init(&context);
        MD5_Update(&context, rx, 4);
        MD5_Update(&context, hash, 16);
        MD5_Update(&context, rx + 20, rxl - 20);
        MD5_Update(&context, secret, strlen(secret));
        MD5_Final(hash, &context);
        if (memcmp(hash, rx + 4, 16))
        {
          syslog(LOG_INFO, "Bad auth hash");
          continue;
        }
      }
      else if (*rx != 12)
      {
        syslog(LOG_INFO, "Not acct %u", *rx);
        continue;
      }
      // respond
      tx[0] = 5;
      tx[1] = rx[1];
      ui32 txl = txp - tx;
      tx[2] = (txl >> 8);
      tx[3] = txl;
      memcpy(tx + 4, rx + 4, 16);
      {
        MD5_CTX context;
        MD5_Init(&context);
        MD5_Update(&context, tx, txl);
        MD5_Update(&context, secret, strlen(secret));
        MD5_Final(tx + 4, &context);
      }
      if (sendto(s, tx, txl, 0, (struct sockaddr *)&from, fromlen) < 0)
        syslog(LOG_INFO, "Failed reply");
      if (*rx != 4)
        continue;               // not accounting
      {                         // check cache
        cache_t *c = &cache[rx[1]];
        if (c->rxlen == rxl && !memcmp(c->rx, rx, rxl))
          continue;             // duplicate - don't queue
        if (c->rxlen)
          free(c->rx);
        memcpy(c->rx = malloc(c->rxlen = rxl), rx, rxl);
      }
      // queue
      memcpy(rx + rxl, from.sin6_addr.s6_addr, 16);
      rxl += 16;
      if (!q && send(sp[0], rx, rxl, 0) > 0)
        continue;               // keeping up
      // queue
      q_t *b = malloc(sizeof(q_t) + rxl);
      b->next = NULL;
      b->len = rxl;
      memcpy(b->buf, rx, rxl);
      if (last_q)
        *last_q = b;
      else
        q = b;
      last_q = &b->next;
      q_l++;
    }
    // check queue catch up
    time_t now = time(0);
    if (now == last)
      continue;
    last = now;
    int c = 0;
    while (q && send(sp[0], q->buf, q->len, 0) > 0)
    {
      q_t *was = q;
      q = q->next;
      if (!q)
        last_q = NULL;
      free(was);
      q_l--;
      c++;
    }
    if (c > 1)
      syslog(LOG_INFO, "Sent %d, queue now %d", c, q_l);
  }
  return 0;
}
