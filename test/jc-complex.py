#!/usr/bin/env python
# coding=UTF-8

import os
from multiprocessing import Process, Queue, current_process, Lock, Pool
from time import sleep

def ntptest(host):
	sleep (10)
	return 0

def worker(queue,lock):
	lock.acquire()
	print 'starting child process with id: ', os.getpid()
	print 'parent process:', os.getppid()
	lock.release()
	host = queue.get()
	ntptest(host)
	lock.acquire()
	print "changing ntp for %s"%host
	lock.release()
	return 0


def main():
	PROCESSES = 3 
	hosts = ["10.10.10.100","10.10.10.99","127.0.0.1","192.168.22.2", "172.15.1.1"]
	
	queue = Queue()
	lock = Lock()
	
	#result = pool.applyAsync(f, (10,))
	
	for host in hosts:
		print ">>> Host %s"%host
		queue.put(host)
	
	j = 0
	for i in hosts:
		if j == 3:
			j = 0
		while j < 3:
			proc = Process(target=worker, args=(queue,lock))
			proc.start()
			j = j + 1
	#proc.join()
		
if __name__ == '__main__':
	main()
	
