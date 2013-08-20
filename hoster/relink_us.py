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

from ... import hoster, core, container, input
from bs4 import BeautifulSoup

@hoster.host
class this:
    model = hoster.HttpHoster
    name = 'relink.us'
    max_check_tasks = 1
    patterns = [
        hoster.Matcher('https?', '*.relink.us', '!/f/<id>'),
    ]
    url_template = 'http://www.relink.us/f/{id}'

def solve_captcha(file, last_resp, s, retry=0):
    cap = s.select('form input[type=image]')
    if not cap:
        return last_resp, s

    alt = cap[0].get('alt')
    if alt and alt != 'Captcha':
        return last_resp, s

    action, form = hoster.serialize_html_form(cap[0].find_parent('form'))
    action = hoster.urljoin(last_resp.url, action)

    src = hoster.urljoin(last_resp.url, cap[0].get("src"))
    data = file.account.get(src)
    result = input.captcha_image(data.content, 'image/jpeg', parent=file)
    if result is None:
        # request canceled
        file.captcha_aborted()

    del form['button']
    form['button.x'], form['button.y'] = result
    resp = file.account.post(action, data=form)

    if u'You have solved the captcha wrong.' in resp.text:
        if retry < 5:
            return solve_captcha(file, last_resp, s, retry + 1)
        file.captcha_invalid()

    return resp, BeautifulSoup(resp.text)

def solve_password(file, last_resp, s, retry=0):
    password = s.select('form #container-protection-password-input')
    if not password:
        return last_resp, s

    action, form = hoster.serialize_html_form(password[0].find_parent('form'))
    action = hoster.urljoin(last_resp.url, action)

    form['password'] = input.password(parent=file)
    if form['password'] is None:
        file.password_aborted()

    resp = file.account.post(action, data=form, referer=last_resp.url)
    return resp, BeautifulSoup(resp.text)

def on_check(file):
    resp = file.account.get(file.url)
    s = BeautifulSoup(resp.text)

    for i in range(5):
        if "container_captcha.php" in resp.url:
            resp, s = solve_captcha(file, resp, s)
        elif "/?pw_cid=" in resp.url:
            for i in range(5):
                if resp is None:
                    resp = file.account.get(file.url)
                    s = BeautifulSoup(resp.text)
                r, s = solve_password(file, resp, s)
                if not "/error.php" in r.url:
                    resp = r
                    break
                resp = None
            else:
                file.password_invalid()
        else:
            break

    if "gewinnspielblog.net" in resp.text:
        m = re.search(r'"http://www\.relink\.us/f/(.*?)"', resp.text)
        if not m:
            file.plugin_out_of_date(msg='error getting forward link')
        resp = file.account.get(file.url, referer=resp.url)
        s = BeautifulSoup(resp.text)

    dlc = s.select('a.dlc_button')
    if dlc:
        src = hoster.urljoin(resp.url, dlc[0].get('href'))
        if handle_dlc(file, src):
            return
        this.log.warning('error decrypting DLC container')

    links = []
    temp = s.select('table.sortable td a.submit')
    for link in temp:
        m = re.match(r"getFile\('(.*?)'\);", link.get('onclick'))
        if not m:
            continue
        url = hoster.urljoin(resp.url, 'frame.php?'+m.group(1))
        links.append(url)

    if not links:
        file.delete_after_greenlet()
        return

    file.init_progress(len(links))
    while links:
        link = links.pop(0)

        r = file.account.get(link, referer=resp.url)
        s = BeautifulSoup(r.text)
        r, s = solve_captcha(file, r, s)

        link = s.select('iframe[name="Container"]')
        if link:
            core.add_links(link[0].get('src'))

        file.add_progress(1)
        file.wait(2.35)

        file.delete_after_greenlet()

def handle_dlc(file, url):
    dlc = file.account.get(url)
    try:
        links = container.decrypt_dlc(dlc.content)
    except BaseException:
        #TODO: log DLC plugin out of date
        return False
    core.add_links(links)
    file.delete_after_check()
    return True


def on_initialize_account(self):
    self.set_user_agent()
