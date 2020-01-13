#!/usr/bin/env python
#!/coding = utf-8

import scapy.all  as scapy
import scapy.layers.http as http
#import scapy_ssl_tls.ssl_tls as ssl_tls
#scapy_http可以详细的解析报文的各个头部，包括Unknown_Headers，解析为 Additional-Headers，但是无法解析User_Agent这种带下划线的，因此最终使用了scapy.layers.http
#import scapy_http.http as http
import scapy.layers.tls.all as tls
import tkinter
import windnd
from tkinter.messagebox import  showinfo
import os
import json
import time

def dragged_files(files):
    pull_line = canvas.create_rectangle(1.5, 1.5, 0, 23, width=0, fill="white")
    canvas.coords(pull_line, (0, 0, 200, 60))
    win.update()
    pcap_path = files[0].decode('gbk')
    print('开始解析报文：%s'%pcap_path)
    start_time  =  time.time()
    print(start_time)
    var = open_pcap_file(pcap_path)
    if  not var:
        use_time = float(time.time()) - float(start_time)
        print(use_time)
        print(time.time())
        showinfo('解析报文成功',('消耗总时间为：%s'%use_time))

def open_pcap_file(pcap_path):
    (filename, extension) = os.path.splitext(pcap_path)
    try :
        packets = scapy.rdpcap(pcap_path)
    except:
        showinfo('文件格式不正确：',pcap_path)
        return 'File error'
    tcp_port_dict = {}
    udp_port_dict = {}
    #tcp_complete_data_tag用于标示该tcp三次握手是否正常抓取
    tcp_complete_data_tag = {}
    #packet_num = 0
    fill_line = canvas.create_rectangle(1.5, 1.5, 1.5, 22, width=0, fill="green")
    n = 200/len(packets)
    for p in packets:
        n = n + 200/len(packets)
        canvas.coords(fill_line, (0, 0, n, 60))
        win.update()
        #p.show()
        if p.haslayer('TCP') and p['IP'].len > p['TCP'].dataofs*4+20: 
            k = (p['TCP'].sport,p['TCP'].dport)
            g = (p['TCP'].dport,p['TCP'].sport)
            if k in tcp_port_dict or g in tcp_port_dict:
                try:
                    tcp_port_dict[k] += 1
                except:
                    tcp_port_dict[g] += 1
            else:
                tcp_port_dict[k] = 1
                if k in tcp_complete_data_tag and tcp_complete_data_tag[k] >= 2:
                    parse_tcp(p)
                if g in tcp_complete_data_tag and tcp_complete_data_tag[g] >= 2:
                    parse_tcp(p)
        elif p.haslayer('TCP') and p['IP'].len <= p['TCP'].dataofs*4+20:
            k = (p['TCP'].sport,p['TCP'].dport)
            g = (p['TCP'].dport,p['TCP'].sport)
            if k in tcp_complete_data_tag or g in tcp_complete_data_tag:
                try:
                    tcp_complete_data_tag[k] += 1
                except:
                    tcp_complete_data_tag[g] += 1
            else:
                tcp_complete_data_tag[k] = 1
        elif p.haslayer('UDP'):
            if p['UDP'].sport ==53 or p['UDP'].dport == 53:
                parse_dns(p)
            elif  p.haslayer('Raw'):
                k = (p['UDP'].sport,p['UDP'].dport)
                g = (p['UDP'].dport,p['UDP'].sport)
                if k in udp_port_dict or g in udp_port_dict:
                    try:
                        udp_port_dict[k] +=1
                    except:
                        udp_port_dict[g] +=1
                else:
                    udp_port_dict[k] = 1
                    parse_udp(p)
    write_dict(filename,ua_dict,'_ua_dict.log')
    write_dict(filename,host_dict,'_host_dict.log')
    write_dict(filename,ser_name_dict,'_ser_name_dict.log')
    write_dict(filename,tcp_stream_dict,'_tcp_stream_dict.log')
    write_dict(filename,udp_stream_dict,'_udp_stream_dict.log')
    write_dict(filename,headers_dict,'_headers_dict.log')
    write_dict(filename,dns_dict,'_dns_dict.log')
    packets.clear()

def write_dict(filename,target_dict,target_path):
    if target_dict:
        f = open(filename+ target_path,'w')
        try :
            json.dump(target_dict,f,indent=1)
            # f.write(json.dumps(target_dict,indent=1))
        finally:
            f.close()
            target_dict.clear()

def add_dict_var(var,dict):
    try:
        dict[var] += 1
    except:
        dict[var] = 1

def parse_tcp(pcap):
    #pcap.show()
    if pcap.haslayer('HTTPRequest'):
        parse_http_ua_host(pcap)
        parse_http_headers(pcap)
    elif pcap.haslayer('ServerName'):
        parse_tls(pcap)
    elif pcap.haslayer('Raw'):
        parse_other_tcp(pcap)
    else:
        #在测试网易严选时，其443端口的报文被识别为TLS，从而导致无法识别该流，下面函数就是为了解决该情况下的问题
        parse_special_tcp(pcap)

def parse_udp(pcap):
    udp_data = str(pcap['Raw'].load[0:20])+'    '+str(pcap['IP'].dport)+':'+str(pcap['IP'].sport)
    add_dict_var(udp_data,udp_stream_dict)

def parse_http_ua_host(p):
    if  p["HTTPRequest"].Host:
        host = p["HTTPRequest"].Host.decode('utf-8')
        #print (host)
    else:
        host =  'NUNLL_in_next_packet'
    add_dict_var(host,host_dict)
    #print(p["HTTPRequest"].User_Agent)
    #UA有可能不在第一个报文中，这样会导致UA变成NoneType,NoneType无法decode
    if  p["HTTPRequest"].User_Agent:
        ua = p["HTTPRequest"].User_Agent.decode('utf-8')
    else:
        ua = 'NUNLL_in_next_packet'
    add_dict_var(ua,ua_dict)


def parse_http_headers(pcap):
    http_fields = json.dumps(str(pcap["HTTPRequest"].fields),indent=1)
    #http_fields = pcap["HTTPRequest"].fields
    #print(http_fields)
    add_dict_var(http_fields,headers_dict)

def parse_tls(pcap):
    ser_name = pcap['ServerName'].servername.decode('utf-8')
    print(ser_name)
    add_dict_var(ser_name,ser_name_dict)

def parse_other_tcp(pcap):
    #对于443端口的TCP报文，即便非TLS报文，也会被scapy进行解析，最终导致['RAW']出现移位，因此需要参考parse_special_tcp的写法
    #data = str(pcap['Raw'].load[0:20])+'    '+str(pcap['IP'].dport)+':'+str(pcap['IP'].sport)
    len = pcap['TCP'].dataofs*4 + 20 + 14
    data = str(bytes(pcap)[len:len+20])+'    '+str(pcap['IP'].dport)+':'+str(pcap['IP'].sport)
    add_dict_var(data,tcp_stream_dict)

def parse_dns(pcap):
    print('dns')
    if pcap.haslayer('DNS Question Record'):
        try:
            data = pcap['DNS Question Record'].qname.decode('utf-8')
            print(data)
            add_dict_var(data,dns_dict)
        except:
            pass

def parse_special_tcp(p):
    len = p['TCP'].dataofs*4+20+14
    special_data = str(bytes(p)[len:len+20])+'    '+str(p['IP'].dport)+':'+str(p['IP'].sport)
    print(special_data)
    add_dict_var(special_data,tcp_stream_dict)

if __name__ == "__main__":
    win = tkinter.Tk()
    win.geometry('300x100')
    win.title('报文解析')
    label = tkinter.Label(win, text = "请拖动报文到此处进行解析", font=('Arial', 15))
    label.pack()
    ua_dict = {}
    host_dict = {}
    ser_name_dict = {}
    udp_stream_dict = {}
    tcp_stream_dict = {}
    dns_dict = {}
    headers_dict = {}
    tkinter.Label(win, text='解析进度:', ).place(x=20, y=60)
    canvas = tkinter.Canvas(win, width=200, height=22, bg="white")
    canvas.place(x=80, y=60)
    windnd.hook_dropfiles(win,func = dragged_files )
    #filter_http_headers("e:/admin/Desktop/demo.pcapng")
    win.mainloop()