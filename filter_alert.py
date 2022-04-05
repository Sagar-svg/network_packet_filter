import sys
import subprocess
import read_dump 
import re
import time
import asyncio
import multiprocessing as mp
import threading as mt
import os
import datetime


alert_file_name = "Alert_logs.log"
log_file_name = "Network_logs.log"
		

	


class Filter_alert:
	
	filtered_logs = [] #to store the filtered logs
	alert_logs = [] #to store the alert logs fetched from reading alert logs file.
	snort_log_file = ''
	alert_log_file = ''
	tcpdump_log_file = ''
	
	
	def updateAlertFile(logs):
		td = datetime.datetime.now
		with open(alert_file_name, 'a') as f:
			for i in logs.split('\n'):
				if(len(i) != 0 and  (i[0] == " " or i[0] == "\t")):
					f.write(i.strip()+" ")
				elif len(i) != 0: 
					f.write("\n")
					f.write(td().strftime("%m/%d")+"-")
					f.write(i+" ")
	
	def updateLogFile(logs):
		td = datetime.datetime.now
		with open(log_file_name, 'a') as f:
			for i in logs.split('\n'):
				if(len(i) != 0 and  (i[0] == " " or i[0] == "\t")):
					f.write(i.strip()+" ")
				elif len(i) != 0: 
					f.write("\n")
					f.write(td().strftime("%m/%d")+"-")
					f.write(i+" ")
	async def get_alert_logs(file_name):
		a = 0
		strLen = 0;
		f_size = 0
		while True:
			if(os.stat('/var/log/snort/'+file_name).st_size>f_size):
				f_size = os.stat('/var/log/snort/'+file_name).st_size
				log_list = read_dump.Read_dump.read_dump(file_name)
				log_list = log_list[0].decode("utf-8")
				if(strLen<len(log_list)):
					Filter_alert.updateAlertFile(log_list[strLen:])
					strLen = len(log_list)
				log_date_time = re.findall('\d\d:\d\d:\d\d.\d\d\d\d\d\d',log_list)
				log_list = re.split('\d\d:\d\d:\d\d.\d\d\d\d\d\d',log_list)[1:]
				log_list = list(zip(log_date_time,log_list))
				if(a<len(log_list)):
					Filter_alert.alert_logs.extend(log_list[a:])
					a = len(log_list)
			await asyncio.sleep(0.1)
		
	async def filter_log():
		a = 0
		b = 0
		#with open("allLog", 'a', 'utf-8') as f:
		while True:
			filtered_log_list = []
			
			if(a<len(read_dump.Read_dump.final_list)):
				
				log_list = read_dump.Read_dump.final_list[a:]
				print("length of the log_list is",len(log_list))
				print("value b", b)
				alert_log_list = Filter_alert.alert_logs[b:]
				#f.writeline(str(log_list[a]))
				#for j in alert_log_list:
				while(a<len(read_dump.Read_dump.final_list) and b<len(Filter_alert.alert_logs)):
					#f.writeline(str(log_list[a]))
					
					if(read_dump.Read_dump.final_list[a][1] == Filter_alert.alert_logs[b][1]):
						a = a+1
						b = b+1
						print("Matched "+read_dump.Read_dump.final_list[a-1][1]+"--"+Filter_alert.alert_logs[b-1][1])
					else:
						filtered_log_list.append(read_dump.Read_dump.final_list[a])
						Filter_alert.filtered_logs.append(read_dump.Read_dump.final_list[a])
						a = a+1
						print("UnMatched "+read_dump.Read_dump.final_list[a-1][1]+"--"+Filter_alert.alert_logs[b][1])
				#Filter_alert.filtered_logs.extend(read_dump.Read_dump.final_list[a:])
				#if(a<len(log_list)-1):
					#filtered_log_list.extend(log_list[a+1:])
				#]	Filter_alert.filtered_logs.extend(filtered_log_list)
				#a = len(read_dump.Read_dump.final_list)
			#	if(b==len(Filter_alert.alert_logs) and a < len(read_dump.Read_dump.final_list)):
			#		Filter_alert.filtered_logs.extend(read_dump.Read_dump.final_list[a:])
			#		a = len(read_dump.Read_dump.final_list)
				
				#b = len(Filter_alert.alert_logs)
			await asyncio.sleep(0.1)
						
	async def show_logs_metadata():
		while True:	
			print("length of the filtered_log is",len(Filter_alert.filtered_logs))
			print("length of thr alert log list", len(Filter_alert.alert_logs))
			print("length of the finallist is",len(read_dump.Read_dump.final_list))
			await asyncio.sleep(1)
		
		
	async def main():
		#task1 = asyncio.create_task(read_dump.Read_dump.get_dump(Filter_alert.snort_log_file, Filter_alert.updateLogFile)) #this gathers all the logs from network interface.
		task1 = asyncio.create_task(read_dump.Read_dump.get_tcpdump(Filter_alert.tcpdump_log_file, Filter_alert.updateLogFile)) #this gathers all the logs from network interface.
		task2 = asyncio.create_task(Filter_alert.get_alert_logs(Filter_alert.alert_log_file)) #this gathers all thr alert logs and stores it in alert_logs list.
		task3 = asyncio.create_task(Filter_alert.filter_log()) #This helps us to filter out the alert logs from all the logs and stores it in to #filtered_logs list
		task4 = asyncio.create_task(Filter_alert.show_logs_metadata())
		await task1
		await task2
		await task3
	def main1():
		print("started main1","*"*500)
		asyncio.run(Filter_alert.main())
		
class start_snort:
	preDate = datetime.datetime.now()
	dump_fileName = 'tcplogs.'+ str(int(datetime.datetime.timestamp(preDate)))
	Filter_alert.tcpdump_log_file = dump_fileName + '.pcap'
	cmd1 = 'sudo tcpdump -i enp0s3 -vv -w '+Filter_alert.tcpdump_log_file
	cmd2 = 'sudo snort -A fast -c /etc/snort/snort.conf -l /var/log/snort'
	cmd3 = 'sudo ls /var/log/snort'
	cmd4 = 'sudo ls '
	
	def packet_logger():
		try:	
			subprocess.Popen(start_snort.cmd1.split(' '))
			#os.spawnl(os.P_NOWAIT, start_snort.cmd1.split(' ')[1:])
		except KeyboardInterrupt:
			print("Pressed CTRL-C")
			temp.kill()
		
	def get_log_file():......
		try:
			temp = subprocess.Popen(start_snort.cmd3.split(' '), stdout = subprocess.PIPE)
			output, err = temp.communicate()
			Filter_alert.snort_log_file = re.findall('snort.log.\d*', output.decode('utf-8'))[-1]
		except KeyboardInterrupt:
			print("Pressed CTRL-C")
			temp.kill()
			
	def get_alert_file():
		try:
			temp = subprocess.Popen(start_snort.cmd3.split(' '), stdout = subprocess.PIPE)
			output, err = temp.communicate()
			#outputlist = temp.communicate()
			Filter_alert.alert_log_file = re.findall('tcpdump.log.\d*', output.decode('utf-8'))[-1]
		except KeyboardInterrupt:
			print("Pressed CTRL-C")
			temp.kill()
	
	def get_tcpdumplog_file():
		try:
			temp = subprocess.Popen(start_snort.cmd4.split(' '), stdout = subprocess.PIPE)
			output, err = temp.communicate()
			Filter_alert.tcpdump_log_file = re.findall('tcplogs.\d*', output.decode('utf-8'))[-1]
		except KeyboardInterrupt:
			print("Pressed CTRL-C")
			temp.kill()
			
			
	def IDS():
		try:
			subprocess.Popen(start_snort.cmd2.split(' '))		
			#os.spawnl(os.P_NOWAIT, start_snort.cmd2.split(' ')[1:])
		except KeyboardInterrupt:
			print("Pressed CTRL-C")
			temp.kill()
	
if '__main__' == __name__:
	#if(len(sys.argv) == 3):
		#
	
	#p1 = mp.Process(target = start_snort.packet_logger)
	#start_snort.get_log_file()
	#p2 = mp.Process(target = start_snort.IDS)
	
	#p1.start()
	#p2.start()
	
	#p1.join()
	#p2.join()
	
	#p3 = mp.Process(target = Filter_alert.main1)
	#p3.start()
	
	#p3.join()
	try:
		start_snort.packet_logger()
		
		start_snort.IDS()
		time.sleep(4)
		start_snort.get_log_file()
		start_snort.get_alert_file()
		Filter_alert.main1()	
	except KeyboardInterrupt:
		print("pressed CTRL-C")
		
	
	
	
	print("logger process ID")
	print("IDS process ID")	
	#start_snort.get_alert_file()
	#asyncio.run(Filter_alert.main(sys.argv[1], sys.argv[2]))
	#start_snort.get_log_file()
	#else:
	#	print("Please provide the file name \ncmd: python3 {0}.py <alert_filename> <log_filename>".format(sys.argv[0]))
