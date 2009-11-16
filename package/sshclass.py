#!/usr/bin/env python
# coding=UTF-8

"""
    Sshclass is a module to be used with Netios.
    It is the interface based on Pexpect (http://pexpect.sourceforge.net/pexpect.html)
    that handles the SSH connection process.

    Netios is a tool to mass configure a park of cisco devices.
    Its primary feature is password updating, but it can be extended if
    you provide it with a file containing any cisco command you wish.
    Copyright (C) 2009  Jean-Christophe Baptiste
    (jc@phocean.net, http://www.phocean.net)

    All the credits go to the Pexpect developpers, which is a great module.
    Plese check http://pexpect.sourceforge.net/pexpect.html
 
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
 
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import pexpect, sys, os, re, datetime

def time (flag):
	"""
	Timestamp function
	The flag determines if it returns a timestamp formatted for a log file itself or its content
	"""
	if flag:
		hor=datetime.datetime.now()
		hor=hor.strftime("%b  %d %H:%M:%S ")
		return (hor)
	else:
		hor=datetime.datetime.now()
		hor=hor.strftime("%Y-%m-%dT%H%M")
		return (hor)

class sshConn:
	"""
	This class handles a generic SSH connection, using the Pexpect library
	"""
	
	def __init__ (self,host,user,password,startTime,logincount, debug):
		"""
		Initialize the sshConn instance and fix a generic prompt that is supposed to work with most SSH servers
		"""
		self.host=host
		self.user=user
		self.password=password
		self.prompt="\$|\%|\#|\>"
		self.startTime=startTime
		self.ssh=None
		self.logincount=logincount
		self.debug=debug
		self.ppid=os.getppid()
		self.pid=os.getpid()

	def error (self,type):
		"""
		Snippet to handle error messages (except)
		Return 1
		"""
		if type == 'timeout':
			return "### SSH Timeout : is SSH on ?"
		elif type == 'keyboardinterrupt':
			return "### User keyboard interrupt"
		elif type == "eof":
			return "### Connection refused by the remote host !"
		elif type == "denied":
			return '### Permission denied on host. Can\'t login'
		elif type == 'user':
			return '### Wrong username or/and password !'
		elif type == 'ena':
			return "### Access Denied : wrong Enable password"
		elif type == 'unexp_ena':
			return "### Can't enter Enable mode : unexpected answer"
		self.ssh.kill(0)

	def login (self,verb):
		"""
		Handle the SSH Login
		Return 0
		"""
		try:
			self.ssh = pexpect.spawn ('ssh %s@%s'%(self.user,self.host))
			#self.ssh.logfile = sys.stdout
			if self.debug is True:
				if os.path.exists('log') == False:
					os.mkdir('log')
				if os.path.exists("log/%s"%self.startTime) == False:
					os.mkdir("log/%s"%self.startTime)
				fout = file ("log/%s/%s-%s.%d.log"%(self.startTime,self.host,time(0), self.logincount),"w")
				self.ssh.logfile = fout
<<<<<<< HEAD
			print "~ SSH session n°%d"%self.logincount
			i = self.ssh.expect (["assword:", r"yes/no"],timeout=80)
	# --- prompted for password
=======
			#print "~ SSH session n°%d"%self.logincount
			i = self.ssh.expect (["assword:", r"yes/no"],timeout=7)
			# prompted for password
>>>>>>> dev
			if i==0:
				if verb:
					print "[%d:%d]\t%s\tAuthenticating"%(self.ppid,self.pid,self.host)
				self.ssh.sendline(self.password)
			elif i==1:
				# prompted for key
				if verb:
					print "[%d:%d]\t%s\tKey request"%(self.ppid,self.pid,self.host)
				self.ssh.sendline("yes")
				self.ssh.expect("assword", timeout=7)
				self.ssh.sendline(self.password)
<<<<<<< HEAD
	# --- prompt after password input : denied or choice for a terminal type
			i = self.ssh.expect (['Permission denied', 'Terminal type', self.prompt, 'assword'],timeout=60)
	# --- permission denied : call to error function
=======
			# prompt after password input : denied or choice for a terminal type
			i = self.ssh.expect (['Permission denied', 'Terminal type', self.prompt, 'assword'],timeout=15)
			# permission denied : call to error function
>>>>>>> dev
			if i == 0:
				return (self.error('denied'))
			elif i == 1:
				# send terminal type
				if verb:
					print "[%d:%d]\t%s\tSSH Login OK... need to send terminal type."%(self.ppid,self.pid,self.host)
				self.ssh.sendline('vt100')
				self.ssh.expect (self.prompt)
			elif i == 2:
			# login successful
				if verb:
					print "[%d:%d]\t%s\tSSH Login OK."%(self.ppid,self.pid,self.host)
			elif i == 3:
			# wrong username
				return (self.error('user'))
			# deactivate echo
			self.ssh.setecho("False")
			return 0
		except pexpect.TIMEOUT:
			return (self.error ('timeout'))
		except pexpect.EOF:
			return (self.error ('eof'))
		except KeyboardInterrupt:
			return (self.error ('keyboard'))

	def interactive(self):
		"""
		Interactive SSH session
		return 0
		"""
		try:
			self.ssh.interact()
			return 0
		except pexpect.TIMEOUT:
			return (self.error ('timeout'))
		except pexpect.EOF:
			return (self.error ('eof'))
		except KeyboardInterrupt:
			return (self.error ('keyboard'))

	def ssh_close(self,ct):
		"""
		Close the SSH connection
		Exit works in most cases
		A flag can be activated if it is a Cisco router still in <configure> mode that we need to logout
		Return 0
		"""
		try:
			# flag indicates that end is necessary before closing (conf t)
			if ct==1 :
				self.ssh.sendline ('end')
				self.ssh.expect(self.prompt)
				self.ssh.sendline("exit")
			elif ct==0 :
				self.ssh.sendline("exit")
			self.ssh.close()
			if self.ssh.logfile:
				self.ssh.logfile.close()
			return 0
		except pexpect.TIMEOUT:
			return (self.error ('timeout'))
		except pexpect.EOF:
			return (self.error ('eof'))
		except KeyboardInterrupt:
			return (self.error ('keyboard'))

	def __del__(self):
		"""
		Clear the instance
		No special handling
		"""
		pass
