#!/usr/bin/python
#coding:utf-8

import socket
import dpkt
import binascii
import struct
import tarfile
print "begin rad"
import uuid
import re
import time
import datetime
import shutil
import os
import pymysql
import  sys

import pcapy
from impacket.ImpactDecoder import *


reload(sys)
sys.setdefaultencoding("utf8")


def mac_addr(address):
    """Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

    # callback for received packets

singKey = ''
packdate = {singKey:''}
isBegin = False
isEnd = False
def recv_pkts(hdr, data):
    #packet = EthDecoder().decode(data)
    #print packet
    cou = 0
    cons  = connDB()
    con = cons[0]
    cur = cons[1]
    nameP = re.compile('filename=".*"')
    #for ts, data in dataP:
    if True:
        try:
            ether = dpkt.ethernet.Ethernet(data)
            
            if ether.type != dpkt.ethernet.ETH_TYPE_IP: raise
            ip = ether.data
            print "begin dump"
            tmpSql = """ INSERT INTO `htprequestlog201706` (`CreateTime`, `src`, `ds`,     `url`,   `sn`,  `filename`, `bodyhex`, `method`, `useagent`, `cookies`, timemasks, calltime, bodystr)
                                                    VALUES ('{0}',      '{1}',  '{2}', '{3}', '{4}',  '{5}',     '{6}',      '{7}',     '{8}',      '{9}',     '{10}'  , '{11}', '{12}' );"""
            ltime=time.localtime(hdr.getts()[0])
            timeStr=time.strftime("%Y-%m-%d %H:%M:%S", ltime)
            tmpSql= tmpSql.replace('{11}',timeStr)
            try:
                src = socket.inet_ntoa(ip.src)
                ds = socket.inet_ntoa(ip.dst)

                #request
                http_data =  dpkt.ethernet.Ethernet(data).data.data.data
                url = ''
                try:
                    request = dpkt.http.Request(http_data)
                    print 'Ethernet Frame:', mac_addr()
                    print request
                    tmpSql =tmpSql.replace("{7}", request.method)
                    url = request.uri
                    tmpSql =  tmpSql.replace("{3}", request.uri)
                    #tmpSql.replace("{9}", request)
                    #取出 head 里边的东西
                    headItems = request.headers.items()
                    for it in headItems:
                        if it[0].find("cookie") != -1:
                            tmpSql = tmpSql.replace("{9}", it[1])
                        if it[0].find("user-agent") != -1:
                            tmpSql = tmpSql.replace("{8}", it[1])
                    response = dpkt.http.Response(http_data)
                    print response
                except Exception as e:
                    print e
              
                dataS = str(data)
                #tmpSql = tmpSql.replace("{12}", dataS)
               
                #执行sql ，插入到数据库中

                tmpSql = tmpSql.replace("{0}", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
                tmpSql = tmpSql.replace("{1}", src)
                tmpSql = tmpSql.replace("{2}", ds)

                if True:
                    #取出file name
                    #print dataS
                    fileName = ''
                    for item in nameP.findall(dataS):
                        try:
                            fileName = item.split('"')[1]
                        except Exception as e:
                            print e
                    row_data = binascii.hexlify(data)
                    tmpSql = tmpSql.replace("{5}", fileName)
                    tmpSql = tmpSql.replace("{6}", row_data[0:9000])
                    #print row_data
                    if row_data.find("1f8b") != -1 and row_data.find("0d0a2d") != -1:
                        #print row_data
                        #print src
                        #取出gzip 的数据， 解压缩
                        #print cou
                        tmpSql = readGzip(row_data, cou,fileName, tmpSql)

                        cou = cou + 1
                    elif row_data.find("1f8b") !=-1
                        isBegin = True
                        #根据mac 地址存储
                    elif row_data.find("0d0a2d") !=-1:
                        isEnd = True
                    exeUpdate(cur, tmpSql)
                    con.commit()
            except Exception as e:
                print e
                pass
        except Exception as e:
            print e
            pass
            
    connClose(con,cur)

def readPackFile():
    """

    :return:
    """
    #pcapRead = dpkt.pcap.Reader(file("e:/out032202.cap", "rb"))
    #读文件
    # list all the network devices
    #直接抓包
    pcapy.findalldevs()

    max_bytes = 20480
    promiscuous = False
    read_timeout = 10000 # in milliseconds
    pc = pcapy.open_live("eth1", max_bytes,
        promiscuous, read_timeout)

    pc.setfilter('tcp port 80')



    packet_limit = -1 # infinite
    pc.loop(packet_limit, recv_pkts) # capture packets

def connDB(): #连接数据库函数
    conn=pymysql.connect(host='10.169.124.237',port=3306, user='root',passwd='123456',db='intelligent',charset='utf8')
    cur=conn.cursor();
    return (conn,cur);

def exeUpdate(cur,sql):#更新语句，可执行update,insert语句
    sta=cur.execute(sql);
    return(sta);

def exeDelete(cur,IDs): #删除语句，可批量删除
    for eachID in IDs.split(' '):
        sta=cur.execute('delete from relationTriple where tID =%d'% int(eachID));
    return (sta);

def exeQuery(cur,sql):#查询语句
    cur.execute(sql);
    return (cur);

def connClose(conn,cur):#关闭所有连接
    cur.close();
    conn.close()

if __name__ == "__main__":
    readPackFile()
    print "end read"

