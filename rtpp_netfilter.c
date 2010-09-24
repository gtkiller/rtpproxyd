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

typedef struct rtpp_netfilter rtpp_netfilter;
int
rtpp_netfilter_init(rtpp_netfilter *nf)
{
    memset(nf, 0, sizeof(*nf));
    nf->stream = popen("/sbin/iptables-restoreasdf", "w");
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
  phost, uint16_t pport, shost, uint16_t sport, dhost, uint16_t dport)
{
    char buf[200];

    assert(nf->stream);

    int n;
    ssize_t s;
    char const fmt[] ="-%c prerouting -s %s/32 -d %s/32 -p udp -m udp "
        "--sport %u --dport %u -j dnat --to-destination %s:%u";
    n = snprintf(buf, sizeof(buf), fmt, action,
        shost, phost, sport, pport, dhost, dport);
    if (n >= sizeof(buf))
        return -1;

    s = write(fileno(nf->stream), buf, n + 1); //todo: n + 1 or n ?
    if (s < 0)
        return s;

    n = snprintf(buf, sizeof(buf), fmt, action,
        shost, phost + 1, sport, pport + 1, dhost, dport + 1);
    if (n >= sizeof(buf))
        return -1;

    s = write(fileno(nf->stream), buf, n + 1); //todo: n + 1 or n ?
    if (s < 0)
        return s;
}

static int
rtpp_netfilter_modify_post_rules(rtpp_netfilter *nf, char action,
  phost, uint16_t pport, shost, uint16_t sport, dhost, uint16_t dport)
{
    char buf[200];

    assert(nf->stream);

    int n;
    ssize_t s;
    char const fmt[] ="-%c POSTROUTING -s %s/32 -d %s/32 -p udp -m udp "
        "--sport %u --dport %u -j SNAT --to-source %s:%u";

    n = snprintf(buf, sizeof(buf), fmt, action,
        shost, dhost, sport, dport, phost, pport);
    if (n >= sizeof(buf))
        return -1;

    s = write(fileno(nf->stream), buf, n + 1); //TODO: n + 1 or n ?
    if (s < 0)
        return s;

    n = snprintf(buf, sizeof(buf), fmt, action,
        shost, dhost, sport + 1, dport + 1, phost, pport + 1);
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
  phost, uint16_t pport, shost, uint16_t sport, dhost, uint16_t dport)
{
    if (!nf->stream)
        return -1;

    if (rtpp_netfilter_modify_pre_rules(nf, 'A',
      phost, pport, shost, sport, dhost, dport) < 0)
        return -1;
    if (rtpp_netfilter_modify_post_rules(nf, 'A',
      phost, pport, shost, sport, dhost, dport) < 0)
        return -1;

    if (rtpp_netfilter_modify_pre_rules(nf, 'A',
      dhost, dport, phost, pport, shost, sport) < 0)
        return -1;

    if (rtpp_netfilter_modify_post_rules(nf, 'A',
      dhost, dport, phost, pport, shost, sport) < 0)
        return -1;
}

int
rtpp_netfilter_add_rules(rtpp_netfilter *nf, struct sockaddr const *addr[2], struct sockaddr const *laddr[2])
{
    char sh[16], dh[16], lh1[16], lh2[16];
    uint16_t sp, dp, lp1, lp2;

    if (inet_ntop(addr[0].sa_family, addr[0], sh, sizeof(sh)) == NULL) {
        return -1; 
    }
    if (inet_ntop(addr[0].sa_family, addr[1], dh, sizeof(dh)) == NULL) {
        return -1; 
    }
    if (inet_ntop(addr[0].sa_family, laddr[0], ph1, sizeof(ph1)) == NULL) {
        return -1; 
    }
    if (inet_ntop(addr[0].sa_family, laddr[1], ph2, sizeof(ph2)) == NULL) {
        return -1; 
    }
    //TODO: retrieve ports from addr and laddr

}

const char *inet_ntop(int af, const void *src,
                      char *dst, socklen_t size);

/*
int
rtpp_netfilter_remove();
*/
