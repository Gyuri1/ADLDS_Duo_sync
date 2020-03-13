#!/usr/bin/env python
"""

ADLDS_Duo_sync


Copyright (c) 2018-2020 Cisco and/or its affiliates.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""


import base64, email, hmac, hashlib, urllib
import requests,six, json, time, sys
from datetime import date, timedelta
import datetime
from ldap3 import Server, Connection, ALL

## Admin API
api_ikey="XY"
api_skey="12"
duo_host="api-11.duosecurity.com"


## AD parameters
ad_server_name   = "adlds.domain.local"
ad_username = "DOMAIN\\admin"
ad_password = "BigSecret"
ad_base_dn  = "DC=domain,DC=local"
ad_port = 389
ad_filter="(&(objectCategory=Person)(sAMAccountName=*)(memberOf=cn=duo,cn=Users,dc=domain,dc=local))"



# Duo Service URL
service_url ="/admin/v1/users"

# Disable cert warning
requests.packages.urllib3.disable_warnings()

""" necessary headers for Duo """
duo_headers = {'Content-Type':'application/x-www-form-urlencoded', 
            'User-Agent': 'Duo API Python/4.2.3',
            'Host':duo_host}

def encode_headers(params):
    """ encode headers """
    encoded_headers = {}
    for k, v in params.items():
        if isinstance(k, six.text_type):
            k = bytes(k.encode())
        if isinstance(v, six.text_type):
            v = v.encode('ascii')
        encoded_headers[k] = v
    return encoded_headers 


def merge_two_dicts(x, y):
    """Given two dicts, merge them into a new dict as a shallow copy."""
    z = x.copy()
    z.update(y)
    return z

def sign(method, host, path, params, skey, ikey):
       # create canonical string
        now = email.utils.formatdate()
        canon = [now, method.upper(), host.lower(), path]
        args = []
        for key in sorted(params.keys()):
            val = params[key]
            #if isinstance(val, unicode):
            #    val = val.encode("utf-8")
            args.append(
                '%s=%s' % (urllib.parse.quote(key, '~'), urllib.parse.quote(val, '~')))
        canon.append('&'.join(args))
        canon = '\n'.join(canon)
        # sign canonical string
        sig = hmac.new(skey.encode(), canon.encode(), hashlib.sha1)
        auth = '%s:%s' % (ikey, sig.hexdigest())

        # return headers
        return {'Date': now, 'Authorization': 'Basic %s' % base64.b64encode(auth.encode()).decode()}


def DuoUserCreate(username, phone, upn, mobile, email):
    if email == None or email == "<no value>":
        post_data = {"username": upn, "status": "active"}
    else:
    	post_data = {"username": upn, "email":email,"status": "active"}

    params1= sign("POST", duo_host, service_url, post_data, api_skey, api_ikey)
    params2= merge_two_dicts(duo_headers, params1)
    encoded_headers = encode_headers(params2)
    response=requests.post(url="https://"+duo_host+service_url, headers=encoded_headers, data=post_data,verify=False)
    print(json.dumps(response.json(),indent=4,sort_keys=True))

    res=response.json()
    user_id=res["response"]["user_id"]

    # Creating phone device
    devicenumber=""
    if phone == None or phone == "<no value>":
        if mobile == None or mobile == "<no value>":
            return
        else:
            devicenumber=mobile
    else:
        devicenumber=phone

    print("Creating phone...")    
    #POST /admin/v1/phones
    service_url_phones= "/admin/v1/phones"
    post_data = {"number": devicenumber}
    params1= sign("POST", duo_host, service_url_phones, post_data, api_skey, api_ikey)
    params2= merge_two_dicts(duo_headers, params1)
    encoded_headers = encode_headers(params2)
    response=requests.post(url="https://"+duo_host+service_url_phones, headers=encoded_headers, data=post_data,verify=False)
    print(json.dumps(response.json(),indent=4,sort_keys=True))

    res=response.json()
    phone_id=res["response"]["phone_id"]
    
    print("user_id:", user_id, "phone_id:", phone_id)
    # Associating phone with user
    #POST /admin/v1/users/[user_id]/phones
    print("Associating phone with user...")
    post_data = {"phone_id": phone_id}
    service_url_associating= service_url+"/"+user_id+"/phones"
    params1= sign("POST", duo_host, service_url_associating, post_data, api_skey, api_ikey)
    params2= merge_two_dicts(duo_headers, params1)
    encoded_headers = encode_headers(params2)
    response=requests.post(url="https://"+duo_host+service_url_associating, headers=encoded_headers, data=post_data,verify=False)
    print(json.dumps(response.json(),indent=4,sort_keys=True))







def DuoUserEnroll(upn, email):
    if email == None or email == "<no value>":
        print("ERROR: no email address.")
        return None
    #POST /admin/v1/users/enroll
    service_url_enroll="/admin/v1/users/enroll"
    post_data = {"username": upn, "email":email}
    params1= sign("POST", duo_host, service_url_enroll, post_data, api_skey, api_ikey)
    params2= merge_two_dicts(duo_headers, params1)
    encoded_headers = encode_headers(params2)
    response=requests.post(url="https://"+duo_host+service_url_enroll, headers=encoded_headers, data=post_data,verify=False)
    print(json.dumps(response.json(),indent=4,sort_keys=True))

def DuoUserDelete(user_id):    	
    #/admin/v1/users/[user_id]
    service_url ="/admin/v1/users"+"/"+str(user_id)
    params={  }
    params1= sign("DELETE", duo_host, service_url, params, api_skey, api_ikey)
    params2= merge_two_dicts(duo_headers, params1)
    encoded_headers = encode_headers(params2)
    response=requests.delete(url="https://"+duo_host+service_url, headers=encoded_headers,verify=False)
    print(json.dumps(response.json(),indent=4,sort_keys=True))


def main(filename):
    print('Reading AD ...')
    ADcount = 0 
   
    try:
    	# list of dict
        ADusers = []
        ad_server = Server(host=ad_server_name,port=ad_port,get_info = ALL)
        ad_conn   = Connection(ad_server, user=ad_username, password= ad_password, auto_bind= True)
        ad_conn.search(search_base=ad_base_dn,search_filter = ad_filter, attributes=['cn','telephoneNumber', 'userPrincipalName', 'mobile', 'mail'])
        users = ad_conn.entries
       
        for user in users:
            dict_tmp = {}
            dict_tmp["username"]=user.cn.values[0].lower()
            dict_tmp["phone"]=user.telephoneNumber.value
            if user.userPrincipalName.value:
                dict_tmp["UPN"]=user.userPrincipalName.value.lower()
            else:
                dict_tmp["UPN"]=None
                print("ERROR: User ({}) does Not have UPN ".format(user.cn.values[0]))
                return
            dict_tmp["mobile"]=user.mobile.value

            if user.mail.value:
                dict_tmp["email"]=user.mail.value.lower()
            else:
                dict_tmp["email"]=None
            
            ADusers.append( dict_tmp )
            #print(user.cn.values)
            ADcount=ADcount+1
#        print (ADusers)
    except Exception as err:
        print("AD connection error!\n")
        return
    print("Found {} users.".format(ADcount))

    if ADcount == 0:
        print("ERROR: AD user cannot be found!\n")
        return

    print('Reading Duo Cloud ...')
    params={  }
    params1= sign("GET", duo_host, service_url, params, api_skey, api_ikey)
    params2= merge_two_dicts(duo_headers, params1)
    encoded_headers = encode_headers(params2)
    response=requests.get(url="https://"+duo_host+service_url, headers=encoded_headers,verify=False)#
    #print(json.dumps(response.json(),indent=4,sort_keys=True))

    res=response.json()
    #print(res["metadata"])
    count = 0
    APIusers=[]
    for user in res["response"]:
        count = count +1
        #print(user["username"])
        APIusers.append(user["username"])	
    print("Found {} users.".format(count))	
	

    print('Comparing databases ...')

    i = 0
    for user in APIusers:
        #print(user["username"])

        found= False
        for j in range(ADcount):
            if user.lower() == ADusers[j]["UPN"].lower():
                found = True
        if found == False:                    	
            print("Found new user in Duo Cloud: {}, will delete it!".format(user))
            for userd in res["response"]:
            	if userd["username"].lower() == user.lower():
            	    user_id = userd["user_id"]
            DuoUserDelete(user_id)
            i = i +1
    if i!=0:
    	print("Number of Deleted Duo Cloud users: {}".format(i))

    i = 0
    for user in ADusers:
        #print(user["username"])
        if user["UPN"].lower() not in APIusers:
            print("Found new users in LDS: {}, will create it!".format(user))
            DuoUserCreate(user["username"], user["phone"], user["UPN"], user["mobile"], user['email'])
            DuoUserEnroll(user["UPN"], user['email'])
            i = i +1
    if i!=0:	
    	print("Number of Created Duo Cloud users: {}".format(i))

    print("Done.")


if __name__ == "__main__":
    main(sys.argv[1:])