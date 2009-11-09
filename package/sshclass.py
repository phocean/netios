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
	
	def __init__ (self,host,user,password,log,startTime,logincount, debug):
		"""
		Initialize the sshConn instance and fix a generic prompt that is supposed to work with most SSH servers
		"""
		self.host=host
		self.user=user
		self.password=password
		self.prompt="\$|\%|\#|\>"
		self.startTime=startTime
		self.log=log
		self.ssh=None
		self.logincount=logincount
		self.debug=debug

	def error (self,type):
		"""
		Snippet to handle error messages (except)
		Return 1
		"""
		if type == 'timeout':
			print "### SSH Timeout : check that the SSH service is on"
			self.log.write ("%sCould not open SSH socket\n"%time(1))
		elif type == 'keyboardinterrupt':
			print "### User keyboard interrupt"
			self.log.write ("%sUser keybord interrupt\n"%time(1))
		elif type == "eof":
			print "### The socket has been closed or interrupted on the remote host !"
			self.log.write ("%sConnection closed by peer\n"%time(1))
		elif type == "denied":
			print '### Permission denied on host. Can\'t login'
			self.log.write ("%sPermission denied on host. Can\'t login\n"%time(1))
		elif type == 'user':
			print '### Wrong username or/and password !'
			self.log.write ("%sWrong username or/and password\n"%time(1))
		elif type == 'ena':
			print "### Access Denied : wrong Enable password"
			self.log.write ("%sWrong Enable password\n"%time(1))
		elif type == 'unexp_ena':
			print "### Can't enter Enable mode : unexpected answer"
			self.log.write ("%sUnexpeted answer while entering Enable mode\n"%time(1))
		self.ssh.kill(0)
		return 1

	def login (self,verb):
		"""
		Handle the SSH Login
		Return 0
		"""
		try:
			self.ssh = pexpect.spawn ('ssh %s@%s'%(self.user,self.host))
			#self.ssh.logfile = sys.stdout
			if self.debug is True:
				if self.logincount > 0:
					fout = file ("log/%s/%s-%s.log.%d"%(self.startTime,self.host,time(0), self.logincount),"w")
				else:
					fout = file ("log/%s/%s-%s.log"%(self.startTime, self.host, time(0)),"w")
				self.ssh.logfile = fout
			print "~ SSH session n°%d"%self.logincount
			i = self.ssh.expect (["assword:", r"yes/no"],timeout=7)
			# --- prompted for password
			if i==0:
				if verb:
					print ">>> Authenticating"
				self.ssh.sendline(self.password)
			elif i==1:
				# --- prompted for key
				if verb:
					print ">>> Key request"
				self.ssh.sendline("yes")
				self.ssh.expect("assword", timeout=7)
				self.ssh.sendline(self.password)
			# --- prompt after password input : denied or choice for a terminal type
			i = self.ssh.expect (['Permission denied', 'Terminal type', self.prompt, 'assword'],timeout=15)
			# --- permission denied : call to error function
			if i == 0:
				return (self.error('denied'))
			elif i == 1:
				# --- send terminal type
				if verb:
					print '>>> SSH Login OK... need to send terminal type.'
				self.ssh.sendline('vt100')
				self.ssh.expect (self.prompt)
			elif i == 2:
			# --- login successful
				if verb:
					print '>>> SSH Login OK.'
			elif i == 3:
			# --- wrong username
				return (self.error('user'))
			# --- deactivate echo
			self.ssh.setecho("False")
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

	def interactive(self):
		"""
		Interactive SSH session
		return 0
		"""
		try:
			self.ssh.interact()
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

	def ssh_close(self,ct):
		"""
		Close the SSH connection
		Exit works in most cases
		A flag can be activated if it is a Cisco router still in <configure> mode that we need to logout
		Return 0
		"""
		try:
			# --- flag indicates that end is necessary before closing (conf t)
			if ct==1 :
				self.ssh.sendline ('end')
				self.ssh.expect(self.prompt)
				self.ssh.sendline("exit")
			elif ct==0 :
				self.ssh.sendline("exit")
			self.ssh.close()
			#self.ssh.logfile.close()
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

	def __del__(self):
		"""
		Clear the instance
		No special handling
		"""
		pass
