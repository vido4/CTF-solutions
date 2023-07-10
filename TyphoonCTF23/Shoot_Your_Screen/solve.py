import requests
import base64
import time
dictionary = {}
cookies = {'no_touchy': 'f9292b83d60b3cfb4cb58263a335385c'}
text = ""
flag = ""
started = False
for i in range(100):
    resp = requests.get("https://typhoonconctf-2023-shootyourscreen.chals.io/", cookies=cookies)

    try:
        i = resp.text.index("color: #")
    except Exception as e:
        print(e)
        print(resp.text)
        continue

    target_value = resp.text[i+18:i+22]
    #text += target_value
    if not started and target_value == "UzNE":
        started = True

    if started:
        flag += target_value
    print(f"|{target_value}|{base64.b64decode(target_value)}")

    if target_value == "ZH0=":
        break
#UzNEe3dlbGxf
