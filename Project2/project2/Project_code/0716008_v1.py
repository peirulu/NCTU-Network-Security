#!/usr/bin/env python
# coding: utf-8

#import library
import json
import re
import os
import sys
import random

#sql rules
def sql(temp,sql_score):
    try:
        url_sql=temp['url']['query']
        sql_keyword=["FROM","SELECT","WHERE","Submit=Submit&id=1"]
        for keywords in sql_keyword:
            if keywords in url_sql:
                sql_score+=5
        query_sql=temp['query']
        match=re.search("GET.*vulnerabilities.*sql",query_sql)
        if(match):
            sql_score+=20
    except:
        sql_score+=0
    return sql_score

#ddos port 80 
def ddos(temp,ddos_score,v2):
    try:
        port=temp['destination']['port']
        v2+=1
        if port==80:
            ddos_score+=0.01
    except:
        ddos_score+=0     
    return ddos_score,v2

#brute force 
def brute(temp,brute_score,v1_users,v1_count):
    try:
        url_brute=temp['url']['query']
        brute_keyword=['Login','username','password']
        v1_count+=1
        try:
            tmp=url_brute.split("username=")
            username=tmp[1]
            if username not in v1_users:
                v1_users.append(username)
        except:
            pass
        for keywords in brute_keyword:
            if keywords in url_brute:
                brute_score+=1

        query_brute=temp['query']
        match=re.search("GET.*vulnerabilities.*brute",query_brute)
        if(match):
            brute_score+=20
    except:
        brute_score+=0
    return brute_score,v1_users,v1_count

#port scanning trait
def port_scanning(temp,port_scanning_score,dest_port,source_port,src_dest_port):
    try:
        event_code=temp['event']['code']
        if event_code==5156:
            port_scanning_score+=1
            try:
                tmp_dest_port=temp['winlog']['event_data']['DestPort']
                if tmp_dest_port not in dest_port:
                    dest_port.append(tmp_dest_port)
                    src_dest_port[tmp_dest_port]=[]
                    
                tmp_source_port=temp['winlog']['event_data']['SourcePort']
                if tmp_source_port not in src_dest_port[tmp_dest_port]:
                    src_dest_port[tmp_dest_port].append(tmp_source_port)                 
            except:
                pass        
    except:
        port_scanning_score+=0
    return port_scanning_score,dest_port,source_port,src_dest_port

#phishing trait
def phish(temp,phish_score):
    try:
        suspicious=["cmd.exe","tar.exe"]
        process_name=temp['winlog']['event_data']['ProcessName']
        for words in suspicious:
            if words in process_name:
                phish_score+=60
    except:
        phish_score+=0
    try:
        event_action=["Removable Storage","Authorization Policy Change"]
        win_task=temp['event']['action']
        
        if win_task in event_action:
            phish_score+=80
    except:
        phish_score+=0
    return phish_score

def double_verify_port_scan(src_dest_ip_port):
    difference=dict()
    for key1,value1 in src_dest_ip_port.items():
        for key2,value2 in value1.items():
            if len(value2)>10:
                value2.sort()
                for i in range(1,len(value2)):
                    keyd=value2[i]-value2[i-1]
                    if keyd not in difference:
                        difference[keyd]=1
                    else:
                        difference[keyd]+=1
                try:
                    difference_value=0
                    try:
                        difference_value+=difference[1]
                        try:
                            difference_value+=difference[2]
                        except:
                            pass
                    except:
                        pass
                    
                    rate=(difference_value/(len(value2)-1))
                    difference={}
                except:
                    rate=0
                if rate>0.5:
                    return True
    return False

def double_verify_brute(v,v1_list):
    if len(v1_list)>0:
        return True
    elif v>1000:
        return True
    return False

def double_verify_ddos(v,v2):
    ratio=v*100/v2
    if ratio>0.6:
        return True
    else:
        return False

def judge_2(trait_1,v1_users,src_dest_port,v2):
    trait_2=dict()
    for k,v in trait_1.items():
        if(k=="Attack 1"):
            if double_verify_brute(v,v1_users)==True:
                trait_2[k]=v
        elif(k=="Attack 2"):
            if double_verify_ddos(v,v2)==True:
                trait_2[k]=v
        elif(k=="Attack 3"):
            if double_verify_port_scan(src_dest_ip_port)==True:
                trait_2[k]=v
        else:
            trait_2[k]=v
    return trait_2
                
def judge(score,v1_users,src_dest_port,v2):
    
    trait_1=dict()
    for k,v in score.items():
        if v>0:
            trait_1[k]=v
    answer=""
        
    if len(trait_1)==0:
        if double_verify_port_scan(src_dest_port)==True:
                answer="Attack 3"
    else:
        tmp_1=sorted(trait_1.items(),key=lambda x:x[1],reverse=True)
        ans_1=tmp_1[0][0]
        trait_2=judge_2(trait_1,v1_users,src_dest_port,v2)
        tmp=sorted(trait_2.items(),key=lambda x:x[1],reverse=True)
        try:
            answer=tmp[0][0]
        except:
            answer=ans_1
            if double_verify_port_scan(src_dest_port)==True:
                if answer=="Attack 2":
                    answer="Attack 3"
    if answer=="":
        attacks=["Attack 1","Attack 2","Attack 3","Attack 4","Attack 5"]
        answer=random.choice(attacks)

    return answer

def port_scanning_2(temp,src_dest_ip_port):
    try:
        dest_ip=temp['destination']['ip']
        dest_port=temp['destination']['port']
        src_ip=temp['source']['ip']
        src_port=temp['source']['port']
        
        keys_dest=dest_ip
        if keys_dest not in src_dest_ip_port:
            src_dest_ip_port[keys_dest]=dict()
        if src_ip not in src_dest_ip_port[keys_dest]:
            src_dest_ip_port[keys_dest][src_ip]=[]
        if src_port not in src_dest_ip_port[keys_dest][src_ip]:
            src_dest_ip_port[keys_dest][src_ip].append(src_port)     
    except:
        pass  
    return src_dest_ip_port

#main program
path=sys.argv[1]
t=os.listdir(path)
file=[]
for files in t:
    if "Test" in files:
        file.append(files)
file.sort()
testcase=0

for file_name in file:
    testcase+=1
    brute_score=0
    ddos_score=0
    port_scanning_score=0
    phish_score=0
    sql_score=0
    #verification parameters
    v1_users=list()
    v1_count=0
    v2=0
    dest_port=[]
    source_port=[]
    src_dest_port=dict()
    src_dest_ip_port=dict()
    
    for line in open(path+"/"+file_name+"/winlogbeat.json","r"):
        temp=json.loads(line)
        phish_score=phish(temp,phish_score)
        port_scanning_score,dest_port,source_port,src_dest_port=port_scanning(temp,port_scanning_score,dest_port,source_port,src_dest_port)
        
    for line in open(path+"/"+file_name+"/packetbeat.json","r"):
        temp=json.loads(line)
        sql_score=sql(temp,sql_score)
        brute_score,v1_users,v1_count=brute(temp,brute_score,v1_users,v1_count)
        ddos_score,v2=ddos(temp,ddos_score,v2)
        src_dest_ip_port=port_scanning_2(temp,src_dest_ip_port)
   
    #print("score:",brute_score,ddos_score,port_scanning_score,phish_score,sql_score)
    score={"Attack 1":brute_score,"Attack 2":ddos_score,"Attack 3":port_scanning_score,"Attack 4":phish_score,"Attack 5":sql_score}
    answer=judge(score,v1_users,src_dest_ip_port,v2)
    print("testcase",testcase,":",answer)
    