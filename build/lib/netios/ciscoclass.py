#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Ciscoclass is the module containing the Cisco object for Netios
    Its attributes contain some selected IOS commands useful to the program.

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

from sshclass import *
					
class ciscoSsh(sshConn):
	"""
	This class is inherited from the sshConn class of sshclass
	It is the interface to handle a Cisco router
	"""
	def __init__(self,host,user,password,enapass,startTime,logincount, debug):
		"""
		Initialize the cisco instance and fix the prompts (for <enable> and <configure terminal> modes)
		"""
		sshConn.__init__(self, host, user, password,startTime,logincount, debug)
		self.enapass=enapass
		self.prompt="\n\S+(\$|#|>){1}$"
		# ^.*\(config\)\#|\(config-line\)\#
		self.confprompt="\n\S+\(config\)\#|\(config-line\)\#"
	
	def ena (self):
		"""
		Enter <enable> mode
		Return 0
		"""
		try:
			self.ssh.sendline ('enable')
			i = self.ssh.expect([r'assword',self.prompt])
			if i == 0:
				# send enable password
				self.ssh.sendline (self.enapass)
				# should be enabled
				self.ssh.expect(self.prompt)
			elif i == 1:
				#print "already enabled (tacacs)"
				pass
			self.ssh.sendline ('terminal width 80')
			self.ssh.expect(self.prompt)
			# return OK status
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

	def conft (self):
		"""
		Enter <configure terminal> mode
		Return 0
		"""
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

	def ssh_change(self,newuser,password):
		"""
		Update the ssh password (eg. create a local user)
		Return 0
		"""
		self.ssh.sendline ("username %s secret 0 %s"%(newuser,password))
		try:
			i = self.ssh.expect ([self.confprompt,"\t\t\t\tERROR: Can not have both a user password and a user secret"])
			if i == 0:
			# all fine : return OK
				return 0
			elif i == 1:
				# erase old password style user
				self.ssh.sendline ("no username %s"%newuser)
				try:
					self.ssh.expect (self.confprompt)
				except pexpect.TIMEOUT:
					self.error ('timeout')
				except pexpect.EOF:
					self.error ('eof')
				except KeyboardInterrupt:
					self.error ('keyboard')
				# send again the "secret" command
				self.ssh.sendline ("username %s secret 0 %s"%(newuser,password))
				try:
					self.ssh.expect (self.confprompt)
				except pexpect.TIMEOUT:
					self.error ('timeout')
				except pexpect.EOF:
					self.error ('eof')
				except KeyboardInterrupt:
					self.error ('keyboard')
				# all fine now : return OK
				return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

	def pass_change_old(self,password):
		"""
		(Deprecated)
		Update the userpassword (mode password)
		Return 0
		"""
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

	def ena_change(self, enapass):
		"""
		Update the enable password
		Return 0
		"""
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

	def show_username(self):
		"""
		Retrieve the list of local users and store them in a table
		Return the table of local users
		"""
		try:
			# filter show run for user names
			self.ssh.sendline ("show run | include username")
			# expecting some characters after the current prompt
			self.ssh.expect (self.prompt)
			# grab the content
			res=self.ssh.before
			# split the string into a table
			userlines = re.split("\n+", res)
			# parse the table to clean up garbage (empty lines or eventually not filtered input)
			nblines = len(userlines)
			i=0
			while i < nblines:
				match = re.match("^username",userlines[i])
					# delete the table entry if the line does not start with username
				if not match:
					del(userlines[i])
					nblines = nblines-1
					i = i-1
				# extract the user name
				else :
					res = re.match(r"(\w+) (\w+)",userlines[i])
					userlines[i]=res.group(2)
				i=i+1
			# return the table of users
			return (userlines)
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

	def show_ntp(self):
		"""
		Retrieve the list of ntp servers and store them in a table
		Return the table of ntp servers
		"""
		try:
			# filter show run for user names
			self.ssh.sendline ("show run | include ntp server")
			# expecting some characters after the current prompt
			self.ssh.expect (self.prompt)
			# grab the content
			res=self.ssh.before
			# split the string into a table
			ntpserv = re.split("\n+", res)
			# parse the table to clean up garbage (empty lines or eventually not filtered input)
			nblines = len(ntpserv)
			i=0
			while i < nblines:
				match = re.match("^ntp server",ntpserv[i])
				# delete the table entry if the line does not start with "ntp server"
				if not match:
					del(ntpserv[i])
					nblines = nblines-1
					i = i-1
				# extract the ntp servers IP
				else :
					res = re.match(r"(\w+) (\w+) ((\d+.){3}\d+)",ntpserv[i])
					ntpserv[i]=res.group(3)
				i=i+1
			# return the table
			return (ntpserv)
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

	def ntp_server(self,ntpsrv):
		"""
		Add ntp servers to the router (the list of servers is read as a parameter)
		Return 0
		"""
		try:
			for i in ntpsrv:
				self.ssh.sendline ("ntp server %s"%i)
				self.ssh.expect (self.confprompt)
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

	def no_ntp_server(self,ntpsrv):
		"""
		Clear ntp servers from the router (the list of servers is read as a parameter)
		Return 0
		"""
		try:
			for i in ntpsrv:
				self.ssh.sendline ("no ntp server %s"%i)
				self.ssh.expect (self.confprompt)
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

	def sh_run(self):
		"""
		Show running configuration
		(note that the issued command are echoed - I could not find a trick at this time
		so this require a workaround to clean it up, processed by netios)
		Return a list with the lines of the running configuration
		"""
		config = []
		try:	
			self.ssh.setecho(False)
			self.ssh.sendline ("show run")
			i = 0
			while i == 0:
				# workaround to get rid off weired characters given by pexpect
				# It is dirty and probably slow
				# I hope to find a better solution some day
				i = self.ssh.expect (["\s?-{2}More-{2}\s?$",self.prompt])
                                res = re.sub(r"[\b]+",'',self.ssh.before)
                                res = re.sub(r"^ {1} +"," ",res)
                                res = re.sub(r"^ +acces","acces",res)
                                res = re.sub(r"^ +!","!",res)
                                config.append( re.sub(r"\s$","",res) )
				if i == 0:
					# pass the cisco pager -- More --
					self.ssh.send(" ")
			#config=re.split("\n+",res)
			return (config)
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

	def delete_user(self,user,userlist):
		"""
		Delete users in the user list received as a parameter
		Return 0
		"""
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
		
	def custcommand(self,command):
		"""
		Send a customized command, input by the user
		Note that there is no - and could not really be any - check
		Return 0
		"""
		try:
			self.ssh.sendline ("%s"%command)
			# [Ii]ncomplete|[Ee]rror|[Ff]ailed|[Ii]nvalid
			i = self.ssh.expect (['\n%',self.confprompt,self.prompt])
			if i == 0:
			  return 1
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

	def exit(self):
		"""
		Send <exit>
		Return 0
		"""
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

	def writemem(self):
		"""
		Send <write memory> command
		From our perspective, we are in <configure terminal> mode at this time, so we have to send <end> first
		Return 0
		"""
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
		"""
		Clear the instance
		No special handling
		"""
		pass
