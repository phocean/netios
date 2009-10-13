#!/usr/bin/env python
# coding=UTF-8

#===============================================================================
#    Ciscoclass is the module containing the Cisco object for CiscoRemote
#    Its attributes contain some selected IOS commands useful to the program.
#
#    CiscoRemote is a tool to mass configure a park of cisco devices.
#    Its primary feature is password updating, but it can be extended if
#    you provide it with a file containing any cisco command you wish.
#    Copyright (C) 2009  Jean-Christophe Baptiste
#    (jc@phocean.net, http://www.phocean.net)
# 
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
# 
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
# 
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#===============================================================================

from sshclass import *

#===============================================================================
# Cisco class inherited from the sshConn class ;
# contains specific Cisco properties and commands
#===============================================================================
					
class ciscoSsh(sshConn):
	
	def __init__(self,host,user,password,enapass,log,startTime,logincount):
		sshConn.__init__(self, host, user, password, log,startTime,logincount)
		self.enapass=enapass
		self.prompt="\$|\%|\#|\>"
		self.confprompt="\(config\)\#|\(config-line\)\#"

# --- enable mode	
	def ena (self):
		self.ssh.sendline ('enable')
		try:
			i = self.ssh.expect([r'assword',self.prompt])
		# --- already in enable mode (ex : tacacs)
		# --- if self.ssh.expect(['>','#'], timeout=2) == 1:
		except pexpect.TIMEOUT:
			i = self.ssh.expect(self.prompt)
			if i == 0:
				#print "already tacacs"
				return 0
		# --- no prompt, serious timeout issue
			else:
				self.error(timeout)
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')
		if i == 0:
			# --- send enable password
			self.ssh.sendline (self.enapass)
			# --- should be enabled
			try:
				self.ssh.expect(self.prompt)
			except pexpect.TIMEOUT:
				self.error ('timeout')
			except pexpect.EOF:
				self.error ('eof')
			except KeyboardInterrupt:
				self.error ('keyboard')
		elif i == 1:
			#print "already enabled (tacacs)"
			pass
		# --- define terminal length
		self.ssh.sendline ('terminal length 0')
		try:
			self.ssh.expect(self.prompt)
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')
		# --- define terminal width
		self.ssh.sendline ('terminal width 80')
		try:
			self.ssh.expect(self.prompt)
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')
		# --- return OK status
		return 0

# --- configure terminal mode
	def conft (self):
		try:
			self.ssh.sendline ('configure terminal')
			self.ssh.expect(self.confprompt)
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

# --- change user password
	def ssh_change(self,newuser,password):
		self.ssh.sendline ("username %s secret 0 %s"%(newuser,password))
		try:
			i = self.ssh.expect ([self.confprompt,"ERROR: Can not have both a user password and a user secret"])
			if i == 0:
		# --- all fine : return OK
				return 0
			elif i == 1:
		# --- erase old password style user
				self.ssh.sendline ("no username %s"%newuser)
				try:
					self.ssh.expect (self.confprompt)
				except pexpect.TIMEOUT:
					self.error ('timeout')
				except pexpect.EOF:
					self.error ('eof')
				except KeyboardInterrupt:
					self.error ('keyboard')
		# --- send again the "secret" command
				self.ssh.sendline ("username %s secret 0 %s"%(newuser,password))
				try:
					self.ssh.expect (self.confprompt)
				except pexpect.TIMEOUT:
					self.error ('timeout')
				except pexpect.EOF:
					self.error ('eof')
				except KeyboardInterrupt:
					self.error ('keyboard')
		# --- all fine now : return OK
				return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

# --- change user password, old style
	def pass_change_old(self,password):
		try:
			self.ssh.sendline ("username %s password %s"%(self.user,password))
			self.ssh.expect (self.confprompt)
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

# --- change enable password
	def ena_change(self, enapass):
		try:
			self.ssh.sendline ("enable secret 0 %s"%enapass)
			self.ssh.expect (self.confprompt)
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

# --- apply AAA
	def aaa(self):
		try:
			self.ssh.sendline ("no aaa new-model")
			self.ssh.expect (self.confprompt)
			self.ssh.sendline ("aaa new-model")
			self.ssh.expect (self.confprompt)
			self.ssh.sendline ('aaa authentication login default local group tacacs+ enable')
			self.ssh.expect (self.confprompt)
			self.ssh.sendline ("aaa authentication enable default group tacacs+ enable")
			self.ssh.expect (self.confprompt)
			self.ssh.sendline ("aaa authorization exec default local group tacacs+ if-authenticated")
			self.ssh.expect (self.confprompt)
			self.ssh.sendline ("aaa authorization commands 1 default local group tacacs+ if-authenticated")
			self.ssh.expect (self.confprompt)
			self.ssh.sendline ("aaa authorization commands 15 default local  group tacacs+ if-authenticated")
			self.ssh.expect (self.confprompt)
			self.ssh.sendline ("aaa authorization network default local group tacacs+")
			self.ssh.expect (self.confprompt)
			self.ssh.sendline ("aaa accounting exec default  start-stop group  tacacs+")
			self.ssh.expect (self.confprompt)
			self.ssh.sendline ("aaa accounting commands 1 default start-stop group tacacs+")
			self.ssh.expect (self.confprompt)
			self.ssh.sendline ("aaa accounting commands 15 default start-stop group tacacs+")
			self.ssh.expect (self.confprompt)
			self.ssh.sendline ("aaa accounting network default start-stop group tacacs+")
			self.ssh.expect (self.confprompt)
			self.ssh.sendline ("aaa accounting system default start-stop group tacacs+")
			self.ssh.expect (self.confprompt)		
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

# --- show username
	def show_username(self):
		try:
	# --- filter show run for user names
			self.ssh.sendline ("show run | include username")
	# --- expecting some characters after the current prompt
			self.ssh.expect ("$.*"+self.prompt)
	# --- grab the content
			res=self.ssh.before
	# --- split the string into a table
			userlines = re.split("\n+", res)
	# --- parse the table to clean up garbage (empty lines or eventually not filtered input)
			nblines = len(userlines)
			i=0
			while i < nblines:
				match = re.match("^username",userlines[i])
	# --- delete the table entry if the line does not start with username
				if not match:
					del(userlines[i])
					nblines = nblines-1
					i = i-1
	# --- extract the user name
				else :
					res = re.match(r"(\w+) (\w+)",userlines[i])
					userlines[i]=res.group(2)
				i=i+1
	# --- return the number of users
			return (userlines)
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

# --- show run
	def sh_run(self):
		try:	
			self.ssh.sendline ("show run")
			self.ssh.expect ("$.*"+self.prompt)
			res=self.ssh.before
			userlines = re.split("\n+", res)
			print ("%s"%userlines)
			return (userlines)
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

# --- delete user
	def delete_user(self,user,userlist):
		for i in userlist:
			if i != user:
				try:
					self.ssh.sendline("no username %s"%i)
					self.ssh.expect (self.confprompt)
					print ">>> User \'%s\' deleted"%i
				except pexpect.TIMEOUT:
					self.error ('timeout')
				except pexpect.EOF:
					self.error ('eof')
				except KeyboardInterrupt:
					self.error ('keyboard')
		return 0
		

# --- send out an customized command, without any warranty
	def custcommand(self,command):
		try:
			self.ssh.sendline ("%s"%command)
			self.ssh.expect ([self.confprompt,self.prompt])
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

# --- exit
	def exit(self):
		try:
			self.ssh.sendline ("exit")
			self.ssh.expect(self.prompt)
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

# --- write mem
	def writemem(self):
		try:
			self.ssh.sendline ("end")
			self.ssh.expect (self.prompt)
			self.ssh.sendline ("write mem")
			self.ssh.expect (self.prompt)
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

	def __del__(self):
		pass
