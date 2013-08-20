# encoding: utf-8

import json
import requests
from gevent import pool
from ... import hoster, core
from ...plugintools import between

@hoster.host
class this:
    model = hoster.HttpHoster
    name = 'safelinking.net'
    favicon_url = 'https://safelinking.net/template/img/blue/logo32.png'
    patterns = [
        hoster.Matcher('https', 'safelinking.net', "!/p/<id>").set_tag("list"),
        hoster.Matcher('https', 'safelinking.net', "!/d/<id>").set_tag("direct")
    ]

def unwrap(link):
    if not link.startswith("http"):
        link = "https://safelinking.net/d/" + link
    resp = requests.head(link)
    url = resp.headers.get("location", None)
    print "Found URL:", url
    if not url:
        return False
    else:
        return url
        
def unwrap_links(links):
    collect = []
    added = 0
    for link in pool.IMapUnordered.spawn(unwrap, links, pool.Pool(20).spawn):
        if not link:
            continue
        collect.append(link)
        if len(collect) >= 20:
            added += len(collect)
            core.add_links(collect)
            collect = []
    core.add_links(collect)
    return added + len(collect)
    
def on_check(file):
    if file.pmatch.tag == "direct":
        return [unwrap(file.url)]
    resps = file.account.get(file.url)
    for result, challenge in file.solve_captcha('recaptcha', parse=resps.text):
        payload = {
            "recaptcha_challenge_field": challenge,
            "recaptcha_response_field": result,
            "post-protect": 1,
        }
        resp = file.account.post(file.url, data=payload, headers=dict(Origin="https://safelinking.net", Referer=file.url))
        error = resp.soup.find("div", class_="msg msg-error")
        print error
        if error:
            text = error.text
            if "CAPTCHA code you entered was wrong" in text:
                continue
            else:
                file.fatal(text)
        break
    else:
        file.input_aborted()
    
    try:
        links = [i["full"] for i in json.loads(between(resp.text, '"d_links":', '};'))]
    except ValueError:
        file.set_offline()
    
    if unwrap_links(links):
        file.delete_after_greenlet()
    else:
        file.no_download_link()