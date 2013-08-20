# -*- coding: utf-8 -*-
"""Copyright (C) 2013 COLDWELL AG

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
"""

import re
import base64
import binascii

from gevent.pool import Pool
from Crypto.Cipher import AES

from ... import hoster, core, javascript, container

@hoster.host
class this:
    model = hoster.HttpHoster
    name = 'share-links.biz'
    max_check_tasks = 1
    patterns = [
        hoster.Matcher('https?', ['*.share-links.biz', '*.s2l.biz'], '!/<id>'),
    ]

def normalize_url(url, pmatch):
    if not pmatch.id.startswith('_'):
        pmatch.id = '_'+pmatch.id
    return 'http://share-links.biz/'+pmatch.id

def on_check_http(file, resp):
    pool = Pool(5)
    images = re.findall("(/template/images/.*?\.gif)", resp.text)
    for image in images:
        pool.spawn(file.account.get, 'http://share-links.biz'+image, referer=resp.url)
    pool.join()

    if ' id="passwordForm"' in resp.text:
        for password in file.solve_password_www():
            if password is None:
                file.password_aborted()
            data = {"password": password, 'login': 'Submit form'}
            resp = file.account.post(file.url, data=data, referer=resp.url)
            if "The inserted password was wrong" in resp.text:
                file.password_invalid(file.retry_num < 5 and 5 or None)
            break
        
    if '<map id="captchamap"' in resp.text:
        map = {}
        for m in re.finditer(r'<area shape="rect" coords="(.*?)" href="(.*?)"', resp.text):
            rect = eval('(' + m.group(1) + ')')
            href = m.group(2)
            map[rect] = href

        url = re.search(r'<img src="(/captcha\.gif\?d=(.*?)&(amp;)?PHPSESSID=(.*?))&(amp;)?legend=1"', resp.text).group(1)
        url = hoster.urljoin(resp.url, url.replace('&amp;', '&'))
        captcha = file.account.get(url, referer=resp.url)

        for x, y in file.solve_captcha_image(retries=3, data=captcha.content, mime='image/gif', timeout=120):
            for rect, url in map.items():
                x1, y1, x2, y2 = rect
                if x >= x1 and x <= x2 and y >= y1 and y <= y2:
                    break
            else:
                continue
            break

        url = hoster.urljoin(resp.url, url.replace('&amp;', '&'))

        resp = file.account.get(url, referer=resp.url)
        if "Your choice was wrong" in resp.text:
            file.captcha_invalid(file.retry_num < 5 and 5 or None)

    links = []

    # crawl container
    try:
        m = re.findall(r"javascript:_get\('(.*?)', 0, '(rsdf|ccf|dlc)'\)", resp.text)
        if m:
            for url in m:
                url = hoster.urljoin(resp.url, "/get/{}/{}".format(url[1], url[0]))
                r = file.account.get(url, referer=resp.url)
                links.extend(container.decrypt_dlc(r.content))
    except BaseException as e:
        print e
    
    # crawl click and load 2 # xxx click and load copy/paste...
    if not links and '/lib/cnl2/ClicknLoad.swf' in resp.text:
        try:
            code = re.search(r'ClicknLoad\.swf\?code=(.*?)"', resp.text).group(1)
            url = hoster.urljoin(resp.url, "/get/cnl2/"+code)
            r = file.account.get(url, referer=resp.url)
            params = r.content.split(";;")

            strlist = list(base64.standard_b64decode(params[1]))
            strlist.reverse()
            jk = ''.join(strlist)

            strlist = list(base64.standard_b64decode(params[2]))
            strlist.reverse()
            crypted = ''.join(strlist)

            js = javascript.execute("%s f()" % jk)
            key = binascii.unhexlify(js)

            crypted = base64.standard_b64decode(crypted)

            obj = AES.new(key, AES.MODE_CBC, key)
            text = obj.decrypt(crypted)
            text = text.replace("\x00", "").replace("\r", "")

            text = text.split("\n")
            links.extend(filter(lambda x: x.strip() and True or False, links))
        except BaseException as e:
            # TODO: report script error
            print e

    # crawl web links
    if not links:
        try:
            m = re.findall(r"javascript:_get\('(.*?)', \d+, ''\)", resp.text)
            if m:
                m = set(m)
                file.init_progress(len(m))
                for id in m:
                    url = hoster.urljoin(resp.url, "/get/lnk/"+id)
                    r = file.account.get(url, referer=resp.url)
                    code = re.search(r'frm/(\d+)', r.text).group(1)
                    
                    url = hoster.urljoin(r.url, "/get/frm/"+code)
                    r = file.account.get(url, referer=r.url)
                    js = re.search(r'<script language="javascript">\s*eval\((.*)\)\s*</script>', r.text, re.DOTALL).group(1)
                    js = javascript.execute("f=%s; f" % js)
                    url = javascript.execute("window=''; parent={frames:{Main:{location:{href:''}}},location:''}; %s; parent.frames.Main.location.href" % js)
                    links.append(url)
                    file.add_progress(1)
                file.reset_progress()
        except BaseException as e:
            # TODO: report script error
            print e

    if links:
        core.add_links(links)
    else:
        file.log.warning('found no links')

    file.delete_after_greenlet()


def on_initialize_account(account):
    account.get('http://share-links.biz/secure?lng=en')
