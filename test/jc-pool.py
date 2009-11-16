#!/usr/bin/env python
# coding=UTF-8

from multiprocessing import Pool,Lock, Manager
from time import sleep

global counter
counter = 0

def cb(r):
    global counter
    print counter, r
    counter +=1
    
def writefile(host):
	try:
		file=open("toto.txt","a")
	except IOError:
		print "## I can't read the file you specified"
	file.write("changing ntp for %s\n"%host)
	sleep (2)
	file.write("OK %s\n"%host)
	file.close()
	

def ntp(host,lock, ok):
	lock.acquire()
	print "changing ntp for %s"%host
	lock.release()
	sleep (3)
	writefile(host)
	ok.write("child write\n")
    	return 0

if __name__ == '__main__':
	num = 6
	pool = Pool(processes=num)              # start 4 worker processes
	manager = Manager()
	lock = manager.Lock()
	hosts = ["1.1.1.1","2.2.2.2","3.3.3.3","4.4.4.4", "5.5.5.5","6.6.6.6","7.7.7.7","8.8.8.8"]
	
	try:
		ok=open("titi.txt","a")
	except IOError:
		print "## I can't read the file you specified"
	ok.write("parent opening\n")
	
	for host in hosts:
		result = pool.apply_async(ntp, (host,lock,ok)) #,callback=cb)     # evaluate "f(10)" asynchronously
		#print result.get()
	pool.close()
	pool.join()
	#print counter
	
	#print result.get(timeout=1)           # prints "100" unless your computer is *very* slow
	#print pool.map(f, range(10))          # prints "[0, 1, 4,..., 81]"

