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
import os
from ... import hoster, container

@hoster.host
class this:
    model = hoster.HttpHoster
    name = 'ncrypt.in'
    max_check_tasks = 1
    patterns = [
        hoster.Matcher('https?', '*.ncrypt.in', '!/folder-<id>'),
    ]
    url_template = 'http://ncrypt.in/folder-{id}'

def on_initialize_account(account):
    account.cookies['SITE_LANGUAGE'] = 'en'

def check_captcha(file, resp, form, data):
    if 'google.com/recaptcha' in resp.text:
        data['recaptcha_response_field'], data['recaptcha_challenge_field'] = file.solve_captcha('recaptcha', parse=resp.text, retries=1).next()
        return

    circle = form.find('input', attrs={'name': 'circle'})
    if circle:
        circle = resp.get(circle.get('src'))
        data['circle.x'], data['circle.y'] = file.solve_captcha_image(data=circle.content, mime=circle.headers['Content-Type']).next()
        return
    
    img = form.find('img', src=lambda a: a.startswith('/temp/anicaptcha/'))
    if img:
        img = resp.get(img.get('src'))
        data['captcha'] = file.solve_captcha(data=img.content, mime=img.headers['Content-Type']).next()
        return

    file.log.warning('found no useable captcha method')

def get_links(file, resp, links):
    form = resp.soup.find_all('form', target='cnl2_output')
    if form:
        for f in form:
            action, data = hoster.serialize_html_form(f)
            links |= set(container.decrypt_clickandload(data))
        return

    for link in resp.soup.find_all('a', href=lambda a: a.startswith('/container/')):
        try:
            url = link.get('href')
            func = getattr(container, 'decrypt_'+os.path.splitext(url)[1][1:])
            r = resp.get(url)
            links |= set(func(r.content))
            return
        except:
            continue

    for link in resp.soup.select('div.link'):
        onclick = link.get('onclick')
        try:
            url = re.search("window\.open\('(http://ncrypt.in/link-.*?)'", onclick).group(1)
        except AttributeError:
            continue
        r = resp.get(url)
        r = r.get(r.soup.find('frame').get('src'), allow_redirects=False)
        links.add(r.headers['Location'])

    if not links:
        file.fatal('no useable link crawling method found')

def on_check_http(file, resp):
    form = resp.soup.find('form', attrs={'name': 'protected'})
    action, data = hoster.serialize_html_form(form)

    title = resp.soup.select('h2 span.arrow')[0].text.strip()
    if title == 'Encrypted folder':
        if 'password' in data:
            data['password'] = file.solve_password_www().next()
        check_captcha(file, resp, form, data)
        resp = resp.post(action, data=data)

        title = resp.soup.select('h2 span.arrow')[0].text.strip()
        if title == 'Encrypted folder':
            file.retry('invalid captcha or password', 2)

    result = dict(package_name=title, links=set())
    get_links(file, resp, result['links'])

    return result
