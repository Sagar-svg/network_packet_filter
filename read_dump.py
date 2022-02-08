import subprocess
import sys
import time
import re
import asyncio
import os
class Read_dump:

	final_list = []#stores all the logs till now

	def read_dump(file_name):
		cmd = 'sudo tcpdump -v -nn -r /var/log/snort/'
		cmd = cmd + file_name
		outputlist = ""
		temp = subprocess.Popen(cmd.split(' '), stdout = subprocess.PIPE)
		
		outputlist = temp.communicate()
		return outputlist
		
	async def get_dump(file_name, func):
		curr = ""
		lst_curr = ""
		f_size = 0
		strLen = 0;
		a = 0
		while(1):
			if(os.stat('/var/log/snort/'+file_name).st_size > f_size):
				f_size = os.stat('/var/log/snort/'+file_name).st_size
				outputlist = Read_dump.read_dump(file_name)
				decodedList = outputlist[0].decode("utf-8")
				if(len(decodedList)>strLen):
					func(decodedList[strLen:])
					strLen = len(decodedList)
				date_time = re.findall('\d\d:\d\d:\d\d.\d\d\d\d\d\d', decodedList)
				output_list = re.split('\d\d:\d\d:\d\d.\d\d\d\d\d\d',decodedList)
				output_list = list(zip(date_time, output_list[1:]))
				
				if(len(Read_dump.final_list)<len(output_list)):
					if(curr != ""):
						curr = output_list[-1][0]
						
						required_list = []
						if(curr != lst_curr):
							#print("length of the list is",len(output_list))
							for i in output_list[-1::-1]:
								if(i[0] != lst_curr):
										required_list.append(i)
								else:
									lst_curr = curr
									Read_dump.final_list.extend(required_list[-1::-1])
									break
						
						
					else:
						
						
						curr = output_list[-1][0]
						Read_dump.final_list.extend(output_list[a:])
						
						
						lst_curr = curr
					a = len(Read_dump.final_list)-1
			await asyncio.sleep(1)				

if __name__ == '__main__':
	if len(sys.argv) == 2:
		Read_dump.get_dump()
	else:
		print("Please provide the filename; python3 {0} <filename>".format(sys.argv[0]))
