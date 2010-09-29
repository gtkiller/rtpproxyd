/*
 * Copyright (c) 2010 Dmitry Goncharov <dgoncharov@users.sf.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "rtpp_netfilter.h"
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h> // DEBUG
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "rtpp_log.h"
#include "rtpp_network.h"
#include "rtpp_session.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

typedef struct rtpp_netfilter rtpp_netfilter;
typedef struct sockaddr sockaddr;
typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr_in6 sockaddr_in6;
typedef struct rtpp_session rtpp_session;

int
rtpp_netfilter_init(rtpp_netfilter *nf)
{
    memset(nf, 0, sizeof(*nf));

    nf->stream = popen("/sbin/iptables-restore -n", "w");
    if (!nf->stream) {
//        rtpp_log_write(RTPP_LOG_ERR, log,
//          "Can't popen iptables-restore, popen(): %s", strerror(errno));
        return -1;
    }
    nf->cth = nfct_open(CONNTRACK, 0);
    if (!nf->cth) {
//        rtpp_log_write(RTPP_LOG_ERR, log,
//          "Can't open nfct handler, nfct_open(): %s", strerror(errno));
        pclose(nf->stream);
        return -1;
    }
    return 0;
}

void
rtpp_netfilter_close(rtpp_netfilter *nf)
{
    if (nf->stream)
        pclose(nf->stream);
    if (nf->cth)
        nfct_close(nf->cth);
}

/*
-A PREROUTING -s 10.10.18.29/32 -d 188.227.5.51/32 -p udp -m udp --sport 2240 --dport 35002 -j DNAT --to-destination 192.168.17.20:16404
-A PREROUTING -s 10.10.18.29/32 -d 188.227.5.51/32 -p udp -m udp --sport 2241 --dport 35003 -j DNAT --to-destination 192.168.17.20:16405
-A PREROUTING -s 192.168.17.20/32 -d 188.227.5.51/32 -p udp -m udp --sport 16404 --dport 35000 -j DNAT --to-destination 10.10.18.29:2240
-A PREROUTING -s 192.168.17.20/32 -d 188.227.5.51/32 -p udp -m udp --sport 16405 --dport 35001 -j DNAT --to-destination 10.10.18.29:2241

-A POSTROUTING -s 10.10.18.29/32 -d 192.168.17.20/32 -p udp -m udp --sport 2240 --dport 16404 -j SNAT --to-source 188.227.5.51:35000
-A POSTROUTING -s 10.10.18.29/32 -d 192.168.17.20/32 -p udp -m udp --sport 2241 --dport 16405 -j SNAT --to-source 188.227.5.51:35001
-A POSTROUTING -s 192.168.17.20/32 -d 10.10.18.29/32 -p udp -m udp --sport 16405 --dport 2241 -j SNAT --to-source 188.227.5.51:35003
-A POSTROUTING -s 192.168.17.20/32 -d 10.10.18.29/32 -p udp -m udp --sport 16404 --dport 2240 -j SNAT --to-source 188.227.5.51:35002
*/

static char *
make_pre_rules(rtpp_netfilter *nf, char *buf, size_t buflen, char action,
  char const *srch, uint16_t srcp, char const *ilh, uint16_t ilp,
  char const *dsth, uint16_t dstp, rtpp_log_t log)
{
    int n1, n2;
    char const fmt[] =
        "-%c PREROUTING -s %s/32 -d %s/32 -p udp -m udp "
        "--sport %u --dport %u -j DNAT --to-destination %s:%u\n";

    n1 = snprintf(buf, buflen, fmt, action,
        srch, ilh, srcp, ilp, dsth, dstp);
    if (n1 >= buflen)
        return NULL;

    n2 = snprintf(buf + n1, buflen - n1, fmt, action,
        srch, ilh, srcp +1, ilp + 1, dsth, dstp + 1);
    if (n2 >= buflen - n1)
        return NULL;

    return buf + n2 + n1;
}

static char *
make_post_rules(rtpp_netfilter *nf, char *buf, size_t buflen, char action,
  char const *srch, uint16_t srcp, char const *olh, uint16_t olp,
  char const *dsth, uint16_t dstp, rtpp_log_t log)
{
    int n1, n2;
    char const fmt[] =
        "-%c POSTROUTING -s %s/32 -d %s/32 -p udp -m udp "
        "--sport %u --dport %u -j SNAT --to-source %s:%u\n";

    n1 = snprintf(buf, buflen, fmt, action,
        srch, dsth, srcp, dstp, olh, olp);
    if (n1 >= buflen)
        return NULL;

    n2 = snprintf(buf + n1, buflen - n1, fmt, action,
        srch, dsth, srcp + 1, dstp + 1, olh, olp + 1);
    if (n2 >= buflen - n1)
        return NULL;

    return buf + n2 + n1;
}

static char *
make_fwd_rules(rtpp_netfilter *nf, char *buf, size_t buflen, char action,
  char const *srch, uint16_t srcp,
  char const *dsth, uint16_t dstp, rtpp_log_t log)
{
    int n;
    char const fmt[] =
        "-%c FORWARD -s %s/32 -d %s/32 -p udp -m udp "
        "--sport %u --dport %u -j ACCEPT\n";

    n = snprintf(buf, buflen, fmt, action, srch, dsth, srcp, dstp);
    if (n >= buflen)
        return NULL;

    return buf + n;
}

static int
commit_rules(rtpp_netfilter *nf, char action,
  char const *srch, uint16_t srcp, char const *ilh, uint16_t ilp,
  char const *olh, uint16_t olp, char const *dsth, uint16_t dstp,
  rtpp_log_t log)
{
    char const commit[] = "COMMIT\n";
    char const filter[] = "*filter\n";
    char buf[2048] = "*nat\n";
    char *cur = buf + sizeof("*nat\n") - 1;
    char *last = buf + sizeof(buf);

    if (!nf->stream)
        return -1;

    if ((cur = make_pre_rules(
      nf, cur, last - cur, action, srch, srcp, ilh, ilp, dsth, dstp, log)) == NULL)
        return -1;

    if ((cur = make_pre_rules(
      nf, cur, last - cur, action, dsth, dstp, olh, olp, srch, srcp, log)) == NULL)
        return -1;
 
    if ((cur = make_post_rules(
      nf, cur, last - cur, action, srch, srcp, olh, olp, dsth, dstp, log)) == NULL)
        return -1;

    if ((cur = make_post_rules(
      nf, cur, last - cur, action, dsth, dstp, ilh, ilp, srch, srcp, log)) == NULL)
        return -1;

    if (last - cur < sizeof(filter))
        return -1;

    if (last - cur < sizeof(commit))
        return -1;
    memcpy(cur, commit, sizeof(commit));
    cur += sizeof(commit) - 1;

    memcpy(cur, filter, sizeof(filter));
    cur += sizeof(filter) - 1;
    if ((cur = make_fwd_rules(
      nf, cur, last - cur, action, srch, srcp, dsth, dstp, log)) == NULL)
        return -1;

    if ((cur = make_fwd_rules(
      nf, cur, last - cur, action, dsth, dstp, srch, srcp, log)) == NULL)
        return -1;

    if (last - cur < sizeof(commit))
        return -1;

    memcpy(cur, commit, sizeof(commit));
    cur += sizeof(commit);

    cur[0] = '\0'; // Only for logging.
    assert(cur - buf < sizeof(buf));

    rtpp_log_write(RTPP_LOG_DBUG, log, "commiting rules\n%s", buf);
    return write(fileno(nf->stream), buf, cur - buf - 1);
}

static int
get_port(sockaddr const *sa)
{
    sa_family_t const f = sa->sa_family;
    assert(AF_INET == f || AF_INET6 == f); //TODO: remove
    if (AF_INET != f && AF_INET6 != f)
        return -1;
    return AF_INET == f ?
      ntohs(((sockaddr_in const *) sa)->sin_port) :
      ntohs(((sockaddr_in6 const *) sa)->sin6_port);
}

static int
modify_rules(rtpp_netfilter *nf, rtpp_session const *sp, char action)
{
    int s;
    uint16_t const srcp = get_port(sp->addr[0]);
    uint16_t const dstp = get_port(sp->addr[1]);
    uint16_t const ilp = sp->ports[0];
    uint16_t const olp = sp->ports[1];

    socklen_t const len = INET6_ADDRSTRLEN;
    char srch[len], dsth[len], ilh[len], olh[len];

    if (addr2char_r((sockaddr *) sp->addr[0], srch, sizeof(srch)) == NULL)
        return -1;
    if (addr2char_r((sockaddr *) sp->addr[1], dsth, sizeof(dsth)) == NULL)
        return -1;
    if (addr2char_r((sockaddr *) sp->laddr[0], ilh, sizeof(ilh)) == NULL)
        return -1;
    if (addr2char_r((sockaddr *) sp->laddr[1], olh, sizeof(olh)) == NULL)
        return -1;

    rtpp_log_write(RTPP_LOG_DBUG, sp->log,
      "s=%s:%u, il=%s:%u, ol=%s:%u, d=%s:%u",
      srch, srcp, ilh, ilp, olh, olp, dsth, dstp);

    s = commit_rules(nf, action, srch, srcp, ilh, ilp, olh, olp, dsth, dstp, sp->log);

    return s;
}

static int
flush_conntrack(rtpp_netfilter *nf, int family, rtpp_log_t log)
{
    int const s = nfct_query(nf->cth, NFCT_Q_FLUSH, &family);
    if (s < 0)
        rtpp_log_write(RTPP_LOG_ERR, log,
          "can't flush conntrack table, nfct_query(): ", strerror(errno));
    return s;
}

int
rtpp_netfilter_add(rtpp_netfilter *nf, rtpp_session const *sp)
{
    modify_rules(nf, sp, 'A');
    return flush_conntrack(nf, AF_INET, sp->log);
}

int
rtpp_netfilter_remove(rtpp_netfilter *nf, rtpp_session const *sp)
{
    return modify_rules(nf, sp, 'D');
}

