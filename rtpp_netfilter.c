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

typedef struct rtpp_netfilter rtpp_netfilter;
typedef struct sockaddr sockaddr;
typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr_in6 sockaddr_in6;

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
-A PREROUTING -s 10.10.18.29/32 -d 188.227.5.51/32 -p udp -m udp --sp 2240 --dp 35002 -j DNAT --to-destination 192.168.17.20:16404
-A PREROUTING -s 10.10.18.29/32 -d 188.227.5.51/32 -p udp -m udp --sp 2241 --dp 35003 -j DNAT --to-destination 192.168.17.20:16405
-A PREROUTING -s 192.168.17.20/32 -d 188.227.5.51/32 -p udp -m udp --sp 16404 --dp 35000 -j DNAT --to-destination 10.10.18.29:2240
-A PREROUTING -s 192.168.17.20/32 -d 188.227.5.51/32 -p udp -m udp --sp 16405 --dp 35001 -j DNAT --to-destination 10.10.18.29:2241

-A POSTROUTING -s 10.10.18.29/32 -d 192.168.17.20/32 -p udp -m udp --sp 2240 --dp 16404 -j SNAT --to-source 188.227.5.51:35000
-A POSTROUTING -s 10.10.18.29/32 -d 192.168.17.20/32 -p udp -m udp --sp 2241 --dp 16405 -j SNAT --to-source 188.227.5.51:35001
-A POSTROUTING -s 192.168.17.20/32 -d 10.10.18.29/32 -p udp -m udp --sp 16405 --dp 2241 -j SNAT --to-source 188.227.5.51:35003
-A POSTROUTING -s 192.168.17.20/32 -d 10.10.18.29/32 -p udp -m udp --sp 16404 --dp 2240 -j SNAT --to-source 188.227.5.51:35002
*/

static int
rtpp_netfilter_modify_pre_rules(rtpp_netfilter *nf, char action,
  lh1, uint16_t lp1, sh, uint16_t sp, dh, uint16_t dp)
{
    char buf[200];

    assert(nf->stream);

    int n;
    ssize_t s;
    char const fmt[] ="-t nat -%c PREROUTING -s %s/32 -d %s/32 -p udp -m udp "
        "--sp %u --dp %u -j dnat --to-destination %s:%u";
    n = snprintf(buf, sizeof(buf), fmt, action,
        sh, lh1, sp, lp1, dh, dp);
    if (n >= sizeof(buf))
        return -1;

    s = write(fileno(nf->stream), buf, n + 1); //todo: n + 1 or n ?
    if (s < 0)
        return s;

    n = snprintf(buf, sizeof(buf), fmt, action,
        sh, lh1 + 1, sp, lp1 + 1, dh, dp + 1);
    if (n >= sizeof(buf))
        return -1;

    s = write(fileno(nf->stream), buf, n + 1); //todo: n + 1 or n ?
    if (s < 0)
        return s;
}

static int
rtpp_netfilter_modify_post_rules(rtpp_netfilter *nf, char action,
  lh1, uint16_t lp1, sh, uint16_t sp, dh, uint16_t dp)
{
    char buf[200];

    assert(nf->stream);

    int n;
    ssize_t s;
    char const fmt[] ="-t nat -%c POSTROUTING -s %s/32 -d %s/32 -p udp -m udp "
        "--sp %u --dp %u -j SNAT --to-source %s:%u";

    n = snprintf(buf, sizeof(buf), fmt, action,
        sh, dh, sp, dp, lh1, lp1);
    if (n >= sizeof(buf))
        return -1;

    s = write(fileno(nf->stream), buf, n + 1); //TODO: n + 1 or n ?
    if (s < 0)
        return s;

    n = snprintf(buf, sizeof(buf), fmt, action,
        sh, dh, sp + 1, dp + 1, lh1, lp1 + 1);
    if (n >= sizeof(buf))
        return -1;

    s = write(fileno(nf->stream), buf, n + 1); //TODO: n + 1 or n ?
    if (s < 0)
        return s;

    return 0;
}
//TODO: cleanup on error
int
add_rules(rtpp_netfilter *nf,
  char const *sh, uint16_t sp, char const *lh1, uint16_t lp1, char const *dh, uint16_t dp)
{
    if (!nf->stream)
        return -1;

    if (rtpp_netfilter_modify_pre_rules(nf, 'A',
      lh1, lp1, sh, sp, dh, dp) < 0)
        return -1;
    if (rtpp_netfilter_modify_post_rules(nf, 'A',
      lh1, lp1, sh, sp, dh, dp) < 0)
        return -1;

    if (rtpp_netfilter_modify_pre_rules(nf, 'A',
      dh, dp, lh1, lp1, sh, sp) < 0)
        return -1;

    if (rtpp_netfilter_modify_post_rules(nf, 'A',
      dh, dp, lh1, lp1, sh, sp) < 0)
        return -1;
}

static int
get_port(sockaddr const *sa)
{
    sa_family_t const f = sa->sa_family;
    if (AF_INET != f && AF_INET6 != f)
        return -1;
    return AF_INET == f ?
      ((sockaddr_in const *) sa)->sin_port :
      ((sockaddr_in6 const *) sa)->sin6_port;
}

int
rtpp_netfilter_add_rules(rtpp_netfilter *nf,
  sockaddr const *addr[2], sockaddr const *laddr[2])
{
    uint16_t const sp = get_port(addr[0]);
    uint16_t const dp = get_port(addr[1]);
    uint16_t const lp1 = get_port(laddr[0]);
    uint16_t const lp2 = get_port(laddr[1]);

    socklen_t const len = INET6_ADDRSTRLEN;
    char sh[len], dh[len], lh1[len], lh2[len];

    if (inet_ntop(addr[0].sa_family, addr[0], sh, sizeof(sh)) == NULL) {
        return -1; 
    }
    if (inet_ntop(addr[1].sa_family, addr[1], dh, sizeof(dh)) == NULL) {
        return -1; 
    }
    if (inet_ntop(laddr[0].sa_family, laddr[0], lh1, sizeof(lh1)) == NULL) {
        return -1; 
    }
    if (inet_ntop(laddr[1].sa_family, laddr[1], lh2, sizeof(lh2)) == NULL) {
        return -1; 
    }

    add_rules(nf, sh, sp, lh1, lp1, lh2, lp2, dh, dp);
}

/*
int
rtpp_netfilter_remove();
*/
