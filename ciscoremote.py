#!/usr/bin/env python
# coding=UTF-8

#===============================================================================
#    CiscoRemote is a tool to mass configure a park of cisco devices.
#    Its primary feature is password updating, but it can be extended if
#    you provide it with a file containing any cisco command you wish.
#    Copyright (C) 2009  Jean-Christophe Baptiste
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

import pexpect, sys, getpass, re, datetime, os
from optparse import OptionParser

ciscoprompt = "\$|\%|\#|\>"

#===============================================================================
#  Generic SSH class based on pexpect, managing the connection
#===============================================================================

class sshConn:
	
	def __init__ (self,host,user,password,prompt,log,startTime):
		self.host=host
		self.user=user
		self.password=password
		self.prompt=prompt
		self.startTime=startTime
		self.log=log
		self.ssh=None
		
	def error (self,type):
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
		try:
			self.ssh = pexpect.spawn ('ssh %s@%s'%(self.user,self.host))
			self.ssh.logfile = sys.stdout 
			fout = file ("log/%s/%s-%s.log"%(self.startTime,time(0),self.host),"w")
			self.ssh.logfile = fout
			i = self.ssh.expect (["assword:", r"yes/no"],timeout=7)
			if i==0:
				if verb:
					print ">>> Authenticating"
				self.ssh.sendline(self.password)
			elif i==1:
				if verb:
					print ">>> Key request"
				self.ssh.sendline("yes")
				self.ssh.expect("assword", timeout=7)
				self.ssh.sendline(self.password)
			# login processes
			i = self.ssh.expect (['Permission denied', 'Terminal type', self.prompt, 'assword'],timeout=15)
			if i == 0:
				return (self.error('denied'))
			elif i == 1:
				if verb:
					print '>>> SSH Login OK... need to send terminal type.'
				self.ssh.sendline('vt100')
				self.ssh.expect (self.prompt)
			elif i == 2:
				if verb:
					print '>>> SSH Login OK.'
			elif i == 3:
				return (self.error('user'))
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')
	
	def interactive(self):
		try:
			self.ssh.interact()
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')
		
	def ssh_close(self,ct):
		try:
			if ct==1 :
				self.ssh.sendline ('end')
				self.ssh.expect(self.prompt)
				self.ssh.sendline("exit")
			elif ct==0 :
				self.ssh.sendline("exit")
			#self.ssh.expect(pexpect.EOF)
			self.ssh.close()
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

#===============================================================================
# Cisco class inherited from the sshConn class ;
# contains specific Cisco properties and commands
#===============================================================================
					
class ciscoSsh(sshConn):
	
	def __init__(self,host,user,password,prompt,enapass,log,startTime):
		sshConn.__init__(self, host, user, password, prompt,log,startTime)
		self.enapass=enapass
		
	def ena (self):
		try:
			self.ssh.sendline ('enable')
			self.ssh.expect(r'assword')
			self.ssh.sendline (self.enapass)
			i = self.ssh.expect(['>','#'], timeout=2)
			if i == 0:
				return (self.error('ena'))
			elif i == 1:
				self.ssh.sendline ('terminal length 0')
				self.ssh.expect(self.prompt)
				return 0
			else:
				return (self.error('unexp_ena'))
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')
	
	def conft (self):
		try:
			self.ssh.sendline ('configure terminal')
			self.ssh.expect(self.prompt)
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')
	
	def ssh_change(self,newuser,password):
		try:
			self.ssh.sendline ("username %s secret 0 %s"%(newuser,password))
			self.ssh.expect (self.prompt)
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')
	
	def pass_change_old(self,password):
		try:
			self.ssh.sendline ("username %s password %s"%(self.user,password))
			self.ssh.expect (self.prompt)
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')

	def ena_change(self, enapass):
		try:
			self.ssh.sendline ("enable secret 0 %s"%enapass)
			self.ssh.expect (self.prompt)
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')
	
	def show_username(self):
		try:
			
			self.ssh.sendline ("show run | include username")
			self.ssh.expect ("$.*"+self.prompt)
			res=self.ssh.before
			userlines = re.split("\n+", res)
			nblines = len(userlines)
			i=0
			while i < nblines:
				match = re.match("^username",userlines[i])
				if not match:
					del(userlines[i])
					nblines = nblines-1
					i = i-1
				else :
					res = re.match(r"(\w+) (\w+)",userlines[i])
					userlines[i]=res.group(2)
				i=i+1
			return (userlines)
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')
	
	def delete_user(self,user,userlist):
		try:
			for i in userlist:
				if i != user:
					self.ssh.sendline("no username %s"%i)
					print ">>> User \'%s\' deleted"%i
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')
	
	def custcommand(self,command):
		try:
			self.ssh.sendline ("%s"%command)
			self.ssh.expect (self.prompt)
			return 0
		except pexpect.TIMEOUT:
			self.error ('timeout')
		except pexpect.EOF:
			self.error ('eof')
		except KeyboardInterrupt:
			self.error ('keyboard')
	
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

#===============================================================================
# horodating function
# according to the receive flag, it returns a format for a log file entry or the
# file name itself
#===============================================================================
def time (flag):
	if flag:
		hor=datetime.datetime.now()
		hor=hor.strftime("%b  %d %H:%M:%S ")
		return (hor)
	else:
		hor=datetime.datetime.now()
		hor=hor.strftime("%Y-%m-%dT%H%M")
		return (hor)
	
#===============================================================================
# next functions just take care of user input
#===============================================================================
def credentials():
	print ">>> Current credentials"
	user = raw_input('  Username: ')
	sshpass = getpass.getpass('  Current SSH Password: ')
	enapass = getpass.getpass('  Current enable Password: ')
	return (user,sshpass,enapass)

def new_user():
	print ">>> New user"
	newuser = raw_input('  New Username: ')
	return(newuser)
	
def new_pass():
	while 1:
		newpassword = getpass.getpass('  New SSH Password: ')
		newpasswordconfirm = getpass.getpass('  Confirm New SSH Password: ')
		if newpassword != newpasswordconfirm:
			print 'New Passwords do not match !'
		else:
			break
	return (newpassword)

def new_ena():
	while 1:
		newena = getpass.getpass('  New Enable Password: ')
		newenaconfirm = getpass.getpass('  Confirm New Enable Password: ')
		if newena != newenaconfirm:
			print '  New Passwords do not match !'
		else:
			break
	return (newena)

#===============================================================================
# Just call the appropriate object attribute and gives some feedback to the user
#===============================================================================
def connect (host,user,sshpass,enapass, log, startTime,verb):
	log.write ("%s* Trying to connect to %s\n"%(time(1),host))
	print ">>> Connecting to %s..."%host
	cisco = ciscoSsh(host, user, sshpass,ciscoprompt,enapass,log,startTime)
	ret = cisco.login(verb)
	if ret != 0 :
		log.write ("%sConnection to %s failed - exiting\n"%(time(1),host))
		return (1)
	log.write ("%sConnected\n"%time(1))
	if verb:
		print ">>> Entering Enable mode"
	ret = cisco.ena()
	if ret != 0 :
		log.write ("%sFailed to enter Enable mode on %s - exiting\n"%(time(1),host))
		return (1)
	log.write ("%sEntered Enable mode\n"%time(1))
	return(cisco)

#===============================================================================
# Same, but considering the configure terminal mode
#===============================================================================
def confter(cisco,log,verb):
	if verb:
		print ">>> Entering Configure Terminal mode"
	ret = cisco.conft()
	if ret != 0 :
		log.write ("%sFailed to enter Configure Terminal mode- exiting\n"%(time(1),host))
		return (1)
	log.write ("%sEntered configure terminal mode\n"%time(1))
	return (cisco)

#===============================================================================
# Main function for password updating.
# To make sure every thing went well, it tries to reconnect with the new credential
# and give back a shell to the user otherwise, so that it is still possible to
# manually correct the problem (and keep a ssh connection up
#===============================================================================
def changepass (host,user,newuser,sshpass,sshpassNew, enapass,enapassNew,log,startTime,verb,sim):
	cisco=connect(host, user, sshpass, enapass, log, startTime,verb)
	if isinstance(cisco,ciscoSsh) != True:
		if verb == True:
			print ("### Could not retrieve an object")
		return 1
	cisco=confter(cisco,log,verb)
	if verb == True:
		print ">>> Changing passwords"
	if sim == False:
		ret = cisco.ssh_change(newuser,sshpassNew)
		if ret != 0 :
			log.write ("%sFailed to change SSH password - exiting\n"%time(1))
			print "## Failed to change SSH password !"
			return (1)
	else:
		log.write ("%sOperation changing password skipped : simulation mode\n"%time(1))
		if verb == True:
			print ">>> Operation changing password skipped : simulation mode"
	log.write ("%sSSH password successfully changed\n"%time(1))
	if verb == True:
		print ">>> Password successfully changed"
	if sim == False:
		ret = cisco.ena_change(enapassNew)
		if ret != 0 :
			log.write ("%sFailed to change Enable password- exiting\n"%time(1))
			print "## Failed to change Enable password"
			return (1)
	else:
		log.write ("%sOperation changing enable password skipped : simulation mode\n"%time(1))
		if verb == True:
			print ">>> Operation changing enable password skipped : simulation mode"
	log.write ("%sEnable password successfully changed\n"%time(1))
	if verb == True:
		print ">>> Enable password successfully changed"
	# fermeture de la connexion en cours
	ret = cisco.ssh_close(0)
	if ret != 0 :
		log.write ("%sFailed to close SSH connection properly - exiting\n"%time(1))
		print "## Failed to close SSH connection properly"
		return (1)
	else :
		log.write ("%sSSH connection closed\n"%time(1))
		if verb:
			print ">>> SSH connection closed"
	log.write ("%s* Initial connection to %s closed\n"%(time(1),host))
	#time.sleep(3)
	# validation of new credentials (simuler connexion)
	cisco=connect(host, user, sshpassNew, enapassNew, log, startTime,verb)
	if isinstance(cisco,ciscoSsh) != True:
		if verb == True:
			print ("### Could not retrieve an object")
		#print ("%s"%sshpassNew)
		# new user log in failed : stop here, don't delete any account
		log.write ("%sFailed do log-in with new credentials - stopping here for %s\n"%time(1),host)
		print "## Failed do log-in with new credentials - stopping here for this host"
		return 1
	ret = cisco.ssh_close(0)
	if ret != 0 :
		log.write ("%sFailed to close SSH connection properly - exiting\n"%time(1))
		print "## Failed to close SSH connection properly"
		return (1)
	else :
		log.write ("%sSSH connection closed\n"%time(1))
		if verb:
			print ">>> SSH connection closed"
	# deletion of extra accounts
	cisco=connect(host, user, sshpassNew, enapassNew, log, startTime,verb)
	if isinstance(cisco,ciscoSsh) != True:
		if verb == True:
			print ("### Could not retrieve an object")
		#print ("Password %s"%sshpassNew)
		# new user log in failed : stop here, don't delete any account
		log.write ("%sFailed do log-in with new credentials - stopping here for %s\n"%(time(1),host))
		print "## Failed do log-in with new credentials - stopping here for this host"
		return 1
	# ajouter retours erreur
	userlist = cisco.show_username()
	if verb == True:
		print ">>> User list :\n  %s"%userlist
	cisco=confter(cisco,log,verb)
	ret = cisco.delete_user(newuser,userlist)
	if ret != 0 :
		log.write ("%sFailed to delete users properly - check it manually\n"%time(1))
		print "## Failed to delete users properly - check it manually"
		return (1)
	else :
		log.write ("%sUnderisable users deleted\n"%time(1))
		if verb:
			print ">>> Underisable users deleted"
	# check again the connection
	# open a new session cisco2 and keep the cisco one alive until it is checked
	# give back a shell to the user otherwise
	cisco2=connect(host, newuser, sshpassNew, enapassNew, log, startTime,verb)
	if cisco2 == 1 :
		# new user log in failed : stop here, don't delete any account
		log.write ("%sValid user potentially deleted by mistake on %s\n"%time(1),host)
		print "## OUPS ! Something got smelly : I could not log-in back. I am afraid that I deleted the valid user. Please check it manually in the session below :"
		cisco.interactive()
		ret = cisco.ssh_close(0)
		if ret != 0 :
			log.write ("%sFailed to close SSH connection properly - exiting\n"%time(1))
			print "## Failed to close SSH connection properly"
			return (1)
		else :
			log.write ("%sSSH connection closed\n"%time(1))
			if verb:
				print ">>> SSH connection closed"
		return 1
	# all fine !
	log.write ("%sOld user deleted and new user validated for %s\n"%(time(1),host))
	# write conf to startup config
	ret=cisco.writemem()
	if verb:
		print ">>> New user validated again"
		print ">>> Exiting and closing connection"
	ret = cisco2.ssh_close(0)
	if ret != 0 :
		log.write ("%sFailed to close SSH connection properly - exiting\n"%time(1))
		print "## Failed to close SSH connection properly"
		return (1)
	else :
		log.write ("%sSSH connection closed\n"%time(1))
		if verb:
			print ">>> SSH connection closed"
	ret = cisco.ssh_close(0)
	if ret != 0 :
		log.write ("%sFailed to close SSH connection properly - exiting\n"%time(1))
		print "## Failed to close SSH connection properly"
		return (1)
	else :
		log.write ("%sSSH connection closed\n"%time(1))
		if verb:
			print ">>> SSH connection closed"
	return 0

#===============================================================================
# This function read the command file line by line and send it to the cisco device
#===============================================================================
def custom (host,user,sshpass,enapass,commandfile,log,startTime,verb,sim):
	cisco=connect(host, user, sshpass, enapass, log, startTime,verb)
	if isinstance(cisco,ciscoSsh) != True:
		if verb == True:
			print ("### Could not retrieve an object")
		return 1
	cisco=confter(cisco,log,verb)
	try:
		if verb == True:
			print (">>> Opening command file %s"%commandfile)
		hostfile=open("%s"%commandfile,"r")
	except IOError:
		print "## I can't read the file you specified"
		sys.exit(2)
	if verb:
		print ">>> Parsing commands"
	for command in hostfile:
		if command and command[-1] == '\n':
			command = command[:-1]
		print ("... %s"%command)
		if sim == False :
			ret = cisco.custcommand(command)
			if ret != 0:
				log.write ("%sSkip %s\n"%(time(1),host))
				error = open ("log/%s/Command Error-%s.log"%(startTime,time(0)),"w")
				error.write ("%s"%host)
				#print "## Skip %s"%host
				#next
				print ("Command %s failed : aborting"%command)
				return 1
		else:
			log.write ("%sOperation skipped : simulation mode\n"%(datetime.time(1)))
			if verb == True:
				print ">>> Operation skipped : simulation mode"
	hostfile.close()
	# retour erreur
	ret=cisco.writemem()
	print "## All commands parsed"
	log.write ("%s## All commands parsed ##\n"%time(1))
	return 0

#===============================================================================
# Put down the program options
#===============================================================================
def process_args(): 
    parser = OptionParser(usage="usage: %prog [options] host1 host2 ... hostn", version="%prog 0.1")
    parser.add_option("-v", "--verbose", action="store_true", dest="verb", help="Print verbose output.")
    parser.add_option("-f", "--hostfile", action="store", dest="file", help="Remote hosts file.")
    parser.add_option("-c","--commands", action="store", dest="commandfile", help="Commands file")
    parser.add_option("-n","--newuser", action="store_true", dest="newusr", help="Add user mode")
    parser.add_option("-u","--showuser", action="store_true", dest="showusr", help="Show user mode")
    parser.add_option("-s","--simulate", action="store_true", dest="simu", help="Simulation mode")
    return parser

#===============================================================================
# Takes care of file opening
#===============================================================================
def fileopen(path):
	try:
		file=open("%s"%path,"r")
	except IOError:
		print "## I can't read the file you specified"
		sys.exit(2)
	return (file)

#===============================================================================
# Call successively functions providing credential, in case of
# modification of an existing user
#===============================================================================

def credential_chain(log):
	(user,sshpass,enapass)=credentials()
	print ">>> New Passwords..."
	print ">>> ...for the SSH..."
	sshpassNew = new_pass ()
	print ">>> ...for the Enable mode..."
	enapassNew = new_ena ()
	log.write ("%sCredential successfully read\n"%time(1))
	return (user,sshpass,enapass,sshpassNew,enapassNew)

#===============================================================================
# Call successively functions providing credential, in case of
# new user creation
#===============================================================================

def credential_chain_new(log):
	newuser=new_user()
	(user,sshpass,enapass,sshpassNew,enapassNew)=credential_chain(log)
	return (newuser,user,sshpass,enapass,sshpassNew,enapassNew)

#===============================================================================
# List the userfile and print it to stdout and file
#===============================================================================

def userlist(host,user,sshpass,enapass,log, startTime,verb):
	cisco=connect(host,user,sshpass,enapass, log, startTime,verb)
	if isinstance(cisco,ciscoSsh) != True:
		if verb == True:
			print ("### Could not retrieve an object")
		return 1
	userlist = cisco.show_username()
	if os.path.exists('out') == False:
	   os.mkdir('out')
	if os.path.exists('out/%s'%startTime) == False:
	   os.mkdir('out/%s'%startTime)
	if userlist:
		if verb == True:
			print "<-- %s -->"%host
		flist = open ("out/%s/users.log"%startTime,"a")
		flist.write ("%s"%host)
		for user in userlist:
			print "%s"%user
			flist.write (";%s"%user)
		flist.write ("\n")
	else :
		print "## Empty string returned !"
		log.write ("%sEmpty string returned instead of username list\n"%time(1))
		return 1
	log.write ("%sRetrieved successfully an user list\n"%time(1))
	flist.close()
	return 0
		

#------------------------------------------------------------------------- Main
		
def main():
	# open log file
	if os.path.exists('log') == False:
	   os.mkdir('log')
	#time.sleep(1)
	startTime=time(0)
	if os.path.exists('log/%s'%startTime) == False:
	   os.mkdir('log/%s'%startTime)
	log = open ("log/%s/CiscoRemote-%s.log"%(startTime,startTime),"w")
	log.write ("%s## CiscoRemote started ##\n"%time(1))
	# check the options
	parser = process_args()
	(opts, hosts) = parser.parse_args()
	if opts.verb == True:
		verb = True
	else:
		verb = False
	if opts.simu == True:
		sim = True
	else:
		sim = False
	if opts.commandfile is not None:
		print "attention"
		ret = raw_input("Yes / No")
		res = re.match("Y",ret)
		#if res
		
	# applying commands from a file to the hosts in the host file
	if opts.commandfile is not None and opts.file is not None:
		# hotes + commandes
		try:
			hostfile = fileopen("%s"%opts.file)
		except IOError:
			print "## I can't read the file you specified"
			sys.exit(2)
		(user,sshpass,enapass,sshpassNew,enapassNew)=credential_chain(log)
		for host in hostfile:
			if host and host[-1] == '\n':
				host = host[:-1]
			ret = changepass(host,user,sshpass,sshpassNew,enapass,enapassNew,log,startTime,verb,sim)
			if ret != 0:
				log.write ("%sSkip %s\n"%(time(1),host))
				error = open ("log/%s/HostError-%s.log"%(startTime,time(0)),"w")
				error.write ("%s"%host)
				print "## Skip %s"%host
				next
		hostfile.close()
		print "## All hosts parsed"
		log.write ("%s## All host parsed ##\n"%time(1))
	# applying commands from the file to the hosts in args
	elif opts.commandfile is not None and len(sys.argv) > 1:
		#arguments + commandes
		(user,sshpass,enapass)=credentials()
		for host in hosts:
			if host and host[-1] == '\n':
				host = host[:-1]
			ret = custom(host,user,sshpass,enapass,opts.commandfile,log,startTime,verb,sim)
			if ret != 0:
				log.write ("%sSkip %s\n"%(time(1),host))
				error = open ("log/%s/HostError-%s.log"%(startTime,time(0)),"w")
				error.write ("%s"%host)
				print "## Skip %s"%host
				next
			print "## All hosts parsed"
			log.write ("%s## All host parsed ##\n"%time(1))
	# changing password for hosts in the file
	elif opts.file is not None:
		try:
			hostfile = fileopen("%s"%opts.file)
		except IOError:
			print "## I can't read the file you specified"
			sys.exit(2)
		if opts.showusr:
			(user,sshpass,enapass)=credentials()
			for host in hostfile:
				if host and host[-1] == '\n':
					host = host[:-1]
				ret=userlist(host,user,sshpass,enapass,log,startTime,verb)
				if ret != 0:
					log.write ("%sSkip %s\n"%(time(1),host))
					error = open ("log/%s/HostError-%s.log"%(startTime,time(0)),"w")
					error.write ("%s"%host)
					print "## Skip %s"%host
					next
			print "## All hosts parsed"
		elif opts.showusr is None:
			if opts.newusr:
				if sim:
					newuser=user
				(newuser,user,sshpass,enapass,sshpassNew,enapassNew)=credential_chain_new(log)
			else:
				(user,sshpass,enapass,sshpassNew,enapassNew)=credential_chain(log)
				newuser=user
			for host in hostfile:
				if host and host[-1] == '\n':
					host = host[:-1]
				ret = changepass(host,user,newuser,sshpass,sshpassNew,enapass,enapassNew,log,startTime,verb,sim)
				if ret != 0:
					log.write ("%sSkip %s\n"%(time(1),host))
					error = open ("log/%s/HostError-%s.log"%(startTime,time(0)),"w")
					error.write ("%s"%host)
					print "## Skip %s"%host
					next
		hostfile.close()
		print "## All hosts parsed"
		log.write ("%s## All host parsed ##\n"%time(1))
	# changing password for hosts in args
	else:
		if len(sys.argv) <= 1:
			parser.print_help()
			log.write ("%sNo host provided - exiting\n"%time(1))
			sys.exit(2)
		if opts.showusr:
			(user,sshpass,enapass)=credentials()
			for host in hosts:
				ret=userlist(host,user,sshpass,enapass,log,startTime,verb)
				if ret != 0:
					log.write ("%sSkip %s\n"%(time(1),host))
					error = open ("log/%s/HostError-%s.log"%(startTime,time(0)),"w")
					error.write ("%s"%host)
					print "## Skip %s"%host
					next
			print "## All hosts parsed : check out the './out' folder for user list"
			log.write ("%s## All host parsed ##\n"%time(1))
		elif opts.showusr is None:
			if opts.newusr:
				(newuser,user,sshpass,enapass,sshpassNew,enapassNew)=credential_chain_new(log)
				if sim is True:
					newuser=user
			else:
				(user,sshpass,enapass,sshpassNew,enapassNew)=credential_chain(log)
				newuser=user
			for host in hosts:
				ret = changepass(host,user,newuser,sshpass,sshpassNew,enapass,enapassNew,log,startTime,verb,sim)
				if ret != 0:
					log.write ("%sSkip %s\n"%(time(1),host))
					error = open ("log/%s/HostError-%s.log"%(startTime,time(0)),"w")
					error.write ("%s"%host)
					print "## Skip %s"%host
					next
			print "## All hosts parsed"
			log.write ("%s## All host parsed ##\n"%time(1))
	log.close()
	sys.exit()

if __name__ == '__main__':
    try:
        main()
    except pexpect.ExceptionPexpect, e:
        print str(e)
        sys.exit(1)
    except OSError:
    	log.write ("%sInput / Output error\n"%time(1))
    	sys.exit(1)
    except KeyboardInterrupt:
    	print "\n>>> Keyboard Interrupted"
    	log.write ("%sKeyboard Interrupted\n"%time(1))
    	sys.exit(1)
