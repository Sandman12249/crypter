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

from ... import hoster, input

@hoster.host
class this:
    model = hoster.HttpHoster
    name = 'dl-protect.com'
    patterns = [
        hoster.Matcher('https?', '*.dl-protect.com', '!/<id>')
    ]
    url_template = 'http://www.dl-protect.com/{id}'

def on_initialize_account(account):
    account.set_user_agent('windows')

def on_check_http(file, resp):
    #form = resp.soup.find('form')
    action, data = hoster.serialize_html_form(resp.soup)
    action = hoster.urljoin(resp.url, action)
    if 'pwd' in data:
        data['pwd'] = file.solve_password(retries=1).next()
    if 'secure' in data:
        captcha = hoster.urljoin(resp.url, resp.soup.find('img', id='captcha').get('src'))
        captcha = file.account.get(captcha, referer=resp.url)
        data['secure'] = input.captcha_text(captcha.content, captcha.headers['Content-Type'], parent=file)
    resp = file.account.post(action, data=data, referer=resp.url)
    error = resp.soup.select('div.w_warning ul li')
    if error:
        file.retry(' / '.join([e.text.strip() for e in error]).replace(' Try.', ''), seconds=1)
    return [a.get('href') for a in resp.soup.select('pre#slinks a[target="_blank"]')]
