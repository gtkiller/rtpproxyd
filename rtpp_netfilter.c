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
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "rtpp_log.h"
#include "rtpp_network.h"
#include "rtpp_session.h"

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
    return nf->stream ? 0 : -1;
}

void
rtpp_netfilter_close(rtpp_netfilter *nf)
{
    if (nf->stream)
        pclose(nf->stream);
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

static int
rtpp_netfilter_modify_pre_rules(rtpp_netfilter *nf, char action,
  char const *ilh, uint16_t ilp, char const *srch, uint16_t srcp, char const *dsth, uint16_t dstp)
{
    char buf[200];

    assert(nf->stream);

    int n;
    ssize_t s;
    char const fmt[] ="-t nat -%c PREROUTING -s %s/32 -d %s/32 -p udstp -m udstp "
        "--srcp %u --dstp %u -j dnat --to-destination %s:%u";
    n = snprintf(buf, sizeof(buf), fmt, action,
        srch, ilh, srcp, ilp, dsth, dstp);
    if (n >= sizeof(buf))
        return -1;

//    s = write(fileno(nf->stream), buf, n + 1); //todo: n + 1 or n ?
    if (s < 0)
        return s;

    n = snprintf(buf, sizeof(buf), fmt, action,
        srch, ilh + 1, srcp, ilp + 1, dsth, dstp + 1);
    if (n >= sizeof(buf))
        return -1;

//    s = write(fileno(nf->stream), buf, n + 1); //todo: n + 1 or n ?
    if (s < 0)
        return s;

    return 0;
}

static int
rtpp_netfilter_modify_post_rules(rtpp_netfilter *nf, char action,
  char const *ilh, uint16_t ilp, char const *srch, uint16_t srcp, char const *dsth, uint16_t dstp)
{
    char buf[200];

    assert(nf->stream);

    int n;
    ssize_t s;
    char const fmt[] ="-t nat -%c POSTROUTING -s %s/32 -d %s/32 -p udstp -m udstp "
        "--srcp %u --dstp %u -j SNAT --to-source %s:%u";

    n = snprintf(buf, sizeof(buf), fmt, action,
        srch, dsth, srcp, dstp, ilh, ilp);
    if (n >= sizeof(buf))
        return -1;

//    s = write(fileno(nf->stream), buf, n + 1); //TODO: n + 1 or n ?
    if (s < 0)
        return s;

    n = snprintf(buf, sizeof(buf), fmt, action,
        srch, dsth, srcp + 1, dstp + 1, ilh, ilp + 1);
    if (n >= sizeof(buf))
        return -1;

//    s = write(fileno(nf->stream), buf, n + 1); //TODO: n + 1 or n ?
    if (s < 0)
        return s;

    return 0;
}
//TODO: cleanup on error
int
add_rules(rtpp_netfilter *nf,
  char const *srch, uint16_t srcp, char const *ilh, uint16_t ilp, char const *dsth, uint16_t dstp)
{
    if (!nf->stream)
        return -1;

    if (rtpp_netfilter_modify_pre_rules(nf, 'A',
      ilh, ilp, srch, srcp, dsth, dstp) < 0)
        return -1;
    if (rtpp_netfilter_modify_post_rules(nf, 'A',
      ilh, ilp, srch, srcp, dsth, dstp) < 0)
        return -1;

    if (rtpp_netfilter_modify_pre_rules(nf, 'A',
      dsth, dstp, ilh, ilp, srch, srcp) < 0)
        return -1;

    if (rtpp_netfilter_modify_post_rules(nf, 'A',
      dsth, dstp, ilh, ilp, srch, srcp) < 0)
        return -1;

    return 0;
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

int
rtpp_netfilter_add_rules(rtpp_netfilter *nf, rtpp_session const *sp)
//  sockaddr const *addr[2], sockaddr const *laddr[2], rtpp_log_t log)
{
    uint16_t const srcp = get_port(sp->addr[0]);
    uint16_t const dstp = get_port(sp->addr[1]);
    uint16_t const ilp = sp->ports[0];
    uint16_t const olp = sp->ports[1];

    socklen_t const len = INET6_ADDRSTRLEN;
    char srch[len], dsth[len], ilh[len], olh[len];

    if (addr2char_r((sockaddr *) sp->addr[0], srch, sizeof(srch)) == NULL) {
        return -1; 
    }
    if (addr2char_r((sockaddr *) sp->addr[1], dsth, sizeof(dsth)) == NULL) {
        return -1; 
    }
    if (addr2char_r((sockaddr *) sp->laddr[0], ilh, sizeof(ilh)) == NULL) {
        return -1; 
    }
    if (addr2char_r((sockaddr *) sp->laddr[1], olh, sizeof(olh)) == NULL) {
        return -1; 
    }

    rtpp_log_write(RTPP_LOG_DBUG, sp->log,
      "s=%s:%u, il=%s:%u, ol=%s:%u, d=%s:%u",
      srch, srcp, ilh, ilp, olh, olp, dsth, dstp);

    return 0;
}

/*
int
rtpp_netfilter_remove();
*/

