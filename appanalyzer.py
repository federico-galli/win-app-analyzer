#!/usr/bin/env python3

#v0.2 29lug19
#Read a list of windows generated logfiles (formatted ad user.name_logfile.txt) 
#and output a parsed list.
#We are looking for not listed software in app_match, sort of anti installer.

#Depends on pysmb: pip3 install --user pysmb
#https://pysmb.readthedocs.io/en/latest/api/smb_SMBConnection.html

#0.1 basic functions
#0.2 reads from smb remote share

import os
import tempfile
from smb.SMBConnection import SMBConnection

smbusername='testuser'
smbpassword=smbusername
smbclientname='testdc'
smbdomain='testdomain.internal'
smbshare='resources'
smbpath='log/'

#list of permitted apps
app_match=["name","microsoft","google","python","adobe","apple","office",
"windows","intel","dell","vnc","vpn","icloud","bonjour","smartbyte","calibre",
"texturepacker","mtg arena","ibm aspera connect","spark ar studio","affinity designer",
"affinity photo","slack","teams machine-wide installer","4k video downloader",
"4k stogram","blender","cyberduck"]

def parselog(log):
#for each line of the log checks if an app from the list is matched. If not, increments
#i counter. When the counter matches the lenght of the list, it means that the line is never
#matched. This is what we are looking for. Then adds to parsedlog list to return.
  i=0
  parsedlog=[]

  for line in log.splitlines():
    for app in app_match:
      if app not in str(line.lower()):
        i += 1
        if len(app_match) == i:
          parsedlog.append(line.strip())
          i = 0
      else:
        i = 0
        break

  parsedlog = list(filter(None, parsedlog)) # clean empty elements
  return parsedlog

#open smb connection to domain controller
def opensmbconn():
  conn = SMBConnection(smbusername, smbpassword, 'appanalyzer', smbclientname , domain=smbdomain, use_ntlm_v2=True)
  assert conn.connect(smbclientname + '.' + smbdomain)
  return conn

#list txt logs on smb destination
def getloglist(shared=smbshare,path=smbpath):
  conn = opensmbconn()
  results = conn.listPath(shared, path, pattern='*.txt')
  conn.close()
  return results

#reads txt and put in an obj file
def readsmbfile(x):
  file_obj = tempfile.NamedTemporaryFile()
  conn = opensmbconn()
  file_attributes, filesize = conn.retrieveFile(smbshare, smbpath+str(x.filename), file_obj)
  conn.close()
  file_obj.seek(0,0)
  contents=file_obj.read()
  file_obj.close()
  return contents

for x in getloglist():
  username = (x.filename.split('_')[1][:-4])
  contents = readsmbfile(x)

  log = contents.decode('utf-16').encode('utf-8').decode('utf-8') #to check. used to elude the byte string

  if len(parselog(log)) > 0:
    print(username)
    print(parselog(log))

