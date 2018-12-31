package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestWhois(t *testing.T) {
	t.Skip()

	domains := strings.Fields(googleDomains)

	for _, domain := range domains {
		t.Logf("domain: %s", domain)
		expires, err := getDomainExpiration(context.Background(), domain)
		if err != nil {
			t.Errorf("domain: %s: error: %s", domain, err)
		} else if expires.Before(time.Now()) {
			t.Errorf("domain: %s: expected domain to be non-expired, actually expires %s", domain, expires)
		}
	}
}

const googleDomains = `google.com
google.ac
google.ad
google.ae
google.com.af
google.com.ag
google.com.ai
google.al
google.am
google.co.ao
google.com.ar
google.as
google.at
google.com.au
google.az
google.ba
google.com.bd
google.be
google.bf
google.bg
google.com.bh
google.bi
google.bj
google.com.bn
google.com.bo
google.com.br
google.bs
google.bt
google.co.bw
google.by
google.com.bz
google.ca
google.com.kh
google.cc
google.cd
google.cf
google.cat
google.cg
google.ch
google.ci
google.co.ck
google.cl
google.cm
google.cn
google.com.co
google.co.cr
google.com.cu
google.cv
google.com.cy
google.cz
google.de
google.dj
google.dk
google.dm
google.com.do
google.dz
google.com.ec
google.ee
google.com.eg
google.es
google.com.et
google.fi
google.com.fj
google.fm
google.fr
google.ga
google.ge
google.gf
google.gg
google.com.gh
google.com.gi
google.gl
google.gm
google.gp
google.gr
google.com.gt
google.gy
google.com.hk
google.hn
google.hr
google.ht
google.hu
google.co.id
google.iq
google.ie
google.co.il
google.im
google.co.in
google.io
google.is
google.it
google.je
google.com.jm
google.jo
google.co.jp
google.co.ke
google.ki
google.kg
google.co.kr
google.com.kw
google.kz
google.la
google.com.lb
google.com.lc
google.li
google.lk
google.co.ls
google.lt
google.lu
google.lv
google.com.ly
google.co.ma
google.md
google.me
google.mg
google.mk
google.ml
google.com.mm
google.mn
google.ms
google.com.mt
google.mu
google.mv
google.mw
google.com.mx
google.com.my
google.co.mz
google.com.na
google.ne
google.com.nf
google.com.ng
google.com.ni
google.nl
google.no
google.com.np
google.nr
google.nu
google.co.nz
google.com.om
google.com.pk
google.com.pa
google.com.pe
google.com.ph
google.pl
google.com.pg
google.pn
google.com.pr
google.ps
google.pt
google.com.py
google.com.qa
google.ro
google.rs
google.ru
google.rw
google.com.sa
google.com.sb
google.sc
google.se
google.com.sg
google.sh
google.si
google.sk
google.com.sl
google.sn
google.sm
google.so
google.st
google.sr
google.com.sv
google.td
google.tg
google.co.th
google.com.tj
google.tk
google.tl
google.tm
google.to
google.tn
google.com.tr
google.tt
google.com.tw
google.co.tz
google.com.ua
google.co.ug
google.co.uk
google.com.uy
google.co.uz
google.com.vc
google.co.ve
google.vg
google.co.vi
google.com.vn
google.vu
google.ws
google.co.za
google.co.zm
google.co.zw
admob.com
adsense.com
adwords.com
abc.xyz
android.com
blogger.com
blogspot.com
chromium.org
chrome.com
chromebook.com
cobrasearch.com
com.google
feedburner.com
doubleclick.com
igoogle.com
foofle.com
froogle.com
googleanalytics.com
google-analytics.com
googletagmanager.com
googlecode.com
googlesource.com
googledrive.com
googlearth.com
googleearth.com
googlemaps.com
googlepagecreator.com
googlescholar.com
gmail.com
googlemail.com
keyhole.com
madewithcode.com
panoramio.com
picasa.com
urchin.com
waze.com
youtube.com
yt.be
ytimg.com
youtubeeducation.com
like.com
google.org
google.net
466453.com
gooogle.com
gogle.com
ggoogle.com
gogole.com
goolge.com
googel.com
duck.com
googlee.com
googil.com
googlr.com
googl.com
gmodules.com
googleadservices.com
googleapps.com
googleapis.com
googlebot.com
googlecommerce.com
googlesyndication.com
g.co
whatbrowser.org
withgoogle.com
1e100.net
ggpht.com
googleusercontent.com
youtubegaming.com
domains.google
www.googlecapital.com
www.gv.com
blog.google`
