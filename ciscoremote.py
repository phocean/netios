#!/usr/bin/env python
# coding=UTF-8

#===============================================================================
#    CiscoRemote is a tool to mass configure a park of cisco devices.
#    Its primary feature is password updating, but it can be extended if
#    you provide it with a file containing any cisco command you wish.
#    Copyright (C) 2009  Jean-Christophe Baptiste
#    (jc@phocean.net, http://www.phocean.net)
#
#    All the credits go to the Pexpect developpers, which is a great module.
#    Plese check http://pexpect.sourceforge.net/pexpect.html
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

import getpass
from ciscoclass import *
from optparse import OptionParser
	
#===============================================================================
# next functions just take care of user input
#===============================================================================

# --- current ssh and enable passwords
def credentials():
	print ">>> Current credentials"
	user = raw_input('  Username: ')
	sshpass = getpass.getpass('  Current SSH Password: ')
	enapass = getpass.getpass('  Current enable Password: ')
	return (user,sshpass,enapass)

# --- new user name
def new_user():
	print ">>> New user"
	newuser = raw_input('  New Username: ')
	return(newuser)

# --- new ssh password	
def new_pass():
	while 1:
		newpassword = getpass.getpass('  New SSH Password: ')
		newpasswordconfirm = getpass.getpass('  Confirm New SSH Password: ')
		if newpassword != newpasswordconfirm:
			print 'New Passwords do not match !'
		else:
			break
	return (newpassword)

# --- new enable password
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
def connect (host,user,sshpass,enapass, log, startTime,verb,logincount):
	log.write ("%s* Trying to connect to %s\n"%(time(1),host))
	if verb:
		print ">>> Connecting to %s..."%host
# --- create the cisco object
	cisco = ciscoSsh(host, user, sshpass,enapass,log,startTime,logincount)
# --- logging
	ret = cisco.login(verb)
# --- connection failed
	if ret != 0 :
		log.write ("%sConnection to %s failed - exiting\n"%(time(1),host))
		return (1)
# --- connection successful
	log.write ("%sConnected\n"%time(1))
	if verb:
		print ">>> Entering Enable mode"
# --- entering enable mode
	ret = cisco.ena()
	if ret != 0 :
		log.write ("%sFailed to enter Enable mode on %s - exiting\n"%(time(1),host))
		return (1)
	log.write ("%sEntered Enable mode\n"%time(1))
# --- return the object
	return(cisco)

#===============================================================================
# Same thing to enter the configure terminal mode
#===============================================================================
def confter(cisco,log,verb):
	if verb:
		print ">>> Entering Configure Terminal mode"
	ret = cisco.conft()
	if ret != 0 :
		log.write ("%sFailed to enter Configure Terminal mode- exiting\n"%time(1))
		return (1)
	log.write ("%sEntered configure terminal mode\n"%time(1))
	return (cisco)

#===============================================================================
# Main function for password updating.
# To make sure every thing went well, it tries to reconnect with the new credential
# and give back a shell to the user otherwise, so that it is still possible to
# manually correct the problem (and keep a ssh connection up
#===============================================================================
def changepass (host,user,newuser,sshpass,sshpassNew, enapass,enapassNew,log,startTime,verb,sim, aaa, tac, nocheck):
	logincount = 0 # login ID for concurrent ssh session
# --- call to connect function
	cisco=connect(host, user, sshpass, enapass, log, startTime,verb, logincount)
# --- if cisco is an object, the connection process was successful
	if isinstance(cisco,ciscoSsh) != True:
		if verb == True:
			print ("### Could not retrieve an object")
		return (1)
# --- call to function to enter configure terminal mode
	cisco=confter(cisco,log,verb)
	if verb == True:
		print ">>> Changing passwords"
# --- not simulation : we call the function to change the ssh password
	if sim == False:
		if aaa == True:
			ret = cisco.aaa()
			if ret != 0 :
				log.write ("%sFailed to change AAA mode - exiting\n"%time(1))
				print "## Failed to change AAA mode !"
				return (1)
			else:
				log.write ("%sAAA mode changed\n"%time(1))
				if verb == True:
					print ">>> AAA mode changed"
		ret = cisco.ssh_change(newuser,sshpassNew)
		if ret != 0 :
			log.write ("%sFailed to change SSH password - exiting\n"%time(1))
			print "## Failed to change SSH password !"
			return (1)
# --- simulation : we don't do anything and continue
	else:
		log.write ("%sOperation changing password skipped : simulation mode\n"%time(1))
		if verb == True:
			print "!!! Operation changing password skipped : simulation mode"
	log.write ("%sSSH password successfully changed\n"%time(1))
	if verb == True:
		print ">>> Password successfully changed"
# --- not simulation : we change the enable password
	if sim == False:
		ret = cisco.ena_change(enapassNew)
		if ret != 0 :
			log.write ("%sFailed to change Enable password- exiting\n"%time(1))
			print "## Failed to change Enable password"
			return (1)
# --- simulation : we don't do anything and continue
	else:
		log.write ("%sOperation changing enable password skipped : simulation mode\n"%time(1))
		if verb == True:
			print "!!! Operation changing enable password skipped : simulation mode"
	log.write ("%sEnable password successfully changed\n"%time(1))
	if verb == True:
		print ">>> Enable password successfully changed"
# --- validate the new credentials (simuler connexion)
	if verb == True:
			print ("... Checking new credentials")
# --- try to connect with the new password
	if nocheck is None:
		logincount = logincount + 1
		if tac == True:
			cisco2=connect(host, user, sshpass, enapass, log, startTime,verb, logincount)
		else:
			cisco2=connect(host, newuser, sshpassNew, enapassNew, log, startTime,verb, logincount)
	# --- test if connection was successful
		if isinstance(cisco2,ciscoSsh) != True:
			if verb == True:
				print ("### Could not retrieve an object")
# --- new user log in failed : stop here, don't delete any account
			log.write ("%sFailed do log-in with new credentials - stopping here for %s\n"%(time(1),host))
			print "## Failed do log-in with new credentials - stopping here for this host"
			return (1)
		ret = cisco2.ssh_close(0)
		if ret != 0 :
			log.write ("%sFailed to close SSH connection properly - exiting\n"%time(1))
			print "## Failed to close SSH connection properly"
			return (1)
		else :
			log.write ("%sSSH connection closed\n"%time(1))
			if verb:
				print ">>> New credentials working well : SSH connection closed"
# --- delete extra accounts
	ret = cisco.exit()
	if ret != 0 :
		log.write ("%sFailed to exit\n"%time(1))
		print "## Failed to exit"
		return (1)
	userlist = cisco.show_username()
	if verb == True:
		print ">>> User list :\n  %s"%userlist
## --- configure terminal mode
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
# --- check again the connection
# --- open a new session cisco2 and keep the cisco one alive until it is checked
# --- give back a shell to the user otherwise
	if nocheck is None:
		logincount = logincount + 1
		if tac == True:
			cisco2=connect(host, user, sshpass, enapass, log, startTime,verb, logincount)
		else:
			cisco2=connect(host, newuser, sshpassNew, enapassNew, log, startTime,verb, logincount)
		if cisco2 == 1 :
	# --- new user log in failed : stop here, don't delete any account
			log.write ("%sValid user potentially deleted by mistake on %s - Manual session\n"%(time(1),host))
			print "## OUPS ! Something got smelly : I could not log-in back. I am afraid that I deleted the valid user. Please check it manually in the session below :"
	# --- open interactive shell to allow the user to check it
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
				return (1)
		# --- we close connections
		ret = cisco2.ssh_close(0)
		if ret != 0 :
			log.write ("%sFailed to close SSH connection properly - exiting\n"%time(1))
			print "## Failed to close SSH connection properly"
			return (1)
		else :
			log.write ("%sSSH connection closed\n"%time(1))
			if verb:
				print ">>> SSH Test connection closed"
# --- all fine !
	log.write ("%sOld user deleted and new user validated for %s\n"%(time(1),host))
# --- write conf to startup config
	ret=cisco.writemem()
	if verb:
		print ">>> New user validated again"
		print ">>> Exiting and closing connection"
# --- we close connection
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
# Change AAA
#===============================================================================


#===============================================================================
# This function read the command file line by line and send it to the cisco device
#===============================================================================
def custom (host,user,sshpass,enapass,commandfile,log,startTime,verb,sim):
# --- open the connection
	logincount = 0
	cisco=connect(host, user, sshpass, enapass, log, startTime,verb, logincount)
	if isinstance(cisco,ciscoSsh) != True:
		if verb == True:
			print ("### Could not retrieve an object")
		return 1
# --- enter configure terminal mode
	cisco=confter(cisco,log,verb)
# --- open the file of custom commands
	try:
		if verb == True:
			print (">>> Opening command file %s"%commandfile)
		hostfile=open("%s"%commandfile,"r")
	except IOError:
		print "## I can't read the file you specified"
		sys.exit(2)
	if verb:
		print ">>> Parsing commands"
# --- parse the host file
	for command in hostfile:
		if command and command[-1] == '\n':
			command = command[:-1]
		print ("... %s"%command)
	# --- not simulating : send the custom command to each host of the file
		if sim == False :
			ret = cisco.custcommand(command)
			if ret != 0:
				log.write ("%sSkip %s\n"%(time(1),host))
				error = open ("log/%s/Command Error.log"%startTime,"w+")
				error.write ("%s\n"%host)
				#print "## Skip %s"%host
				#next
				print ("Command %s failed : aborting"%command)
				return 1
	# --- simulating : don't do anything and continue
		else:
			log.write ("%sOperation skipped : simulation mode\n"%(datetime.time(1)))
			if verb == True:
				print ">>> Operation skipped : simulation mode"
# --- close the file
	hostfile.close()
# --- retour erreur
	ret=cisco.writemem()
	print "## All commands parsed"
	log.write ("%s## All commands parsed ##\n"%time(1))
	return 0

#===============================================================================
# Put down the program options
#===============================================================================
def process_args(): 
	parser = OptionParser(usage="usage: %prog [options] host1 host2 ... hostn", version="%prog 0.41")
	parser.add_option("-v", "--verbose", action="store_true", dest="verb", help="Print verbose output.")
	parser.add_option("-f", "--hostfile", action="store", dest="file", metavar="FILE", help="Remote hosts file.")
	parser.add_option("-c","--commands", action="store", dest="commandfile", metavar="FILE", help="Commands file")
	parser.add_option("-n","--newuser", action="store_true", dest="newusr", help="Add user mode")
	parser.add_option("-t","--tacacs", action="store_true", dest="tacacs", help="The management account is a tacacs one")
	parser.add_option("","--no-check", action="store_true", dest="nocheck", help="No proof check")
	parser.add_option("-u","--showuser", action="store_true", dest="showusr", help="Show user mode")
	parser.add_option("-s","--simulate", action="store_true", dest="simu", help="Simulation mode")
	parser.add_option("-r","--shrun", action="store_true", dest="showrun", help="[EXPERIMENTAL] Show Run")
	parser.add_option("-a","--aaa", action="store_true", dest="aaa", help="[EXPERIMENTAL] Change AAA model")
	return parser

#===============================================================================
# Generic function to open files
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
	(user,sshpass,enapass,sshpassNew,enapassNew)=credential_chain(log)
	newuser=new_user()
	return (newuser,user,sshpass,enapass,sshpassNew,enapassNew)

#===============================================================================
# List users and print it to stdout and file
#===============================================================================

def userlist(host,user,sshpass,enapass,log, startTime,verb):
# --- open a connection
	logincount = 0
	cisco=connect(host,user,sshpass,enapass, log, startTime,verb, logincount)
	if isinstance(cisco,ciscoSsh) != True:
		if verb == True:
			print ("### Could not retrieve an object")
		return 1
# --- call the function to extract users
	userlist = cisco.show_username()
	
# --- log it in a dedicated folder
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
		print "### Empty string returned !"
		log.write ("%sEmpty string returned instead of username list\n"%time(1))
		return 1
	log.write ("%sRetrieved successfully an user list\n"%time(1))
	flist.close()
	return 0

#===============================================================================
# show run and print it to stdout
#===============================================================================		
def show_run(host,user,sshpass, enapass, log, startTime, verb):
	logincount = 0
	cisco=connect(host,user,sshpass,enapass, log, startTime,verb, logincount)
	if isinstance(cisco,ciscoSsh) != True:
		if verb == True:
			print ("### Could not retrieve an object")
		return 1
	cisco.sh_run()
	return 0

#==============================================================================#
#----------------------------------- MAIN -------------------------------------#
#==============================================================================#
		
def main(log,startTime):
	
# --- check the options
	parser = process_args()
	(opts, hosts) = parser.parse_args()
	if len(hosts) < 1 and opts.file is None:
		parser.error("incorrect number of arguments")
	if opts.verb == True:
		verb = True
	else:
		verb = False
	if opts.simu == True:
		sim = True
		verb = True
	else:
		sim = False
	if opts.aaa == True:
		aaa = True
	else:
		aaa = False
	if opts.tacacs == True:
		tac = True
	else:
		tac = False
	if opts.commandfile is not None:
		print "Attention !! Use it at your own risk : I don't check the commands, so the command file has to be safe and clean. Confirm :"
		ret = raw_input("Yes / No")
		res = re.match("Y",ret)
		if res == None:
			sys.exit(1)
	error = None
		
# --- applying commands from a file to the hosts in the host file
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
			print ">>> Working on host %s"%host
			ret = changepass(host,user,sshpass,sshpassNew,enapass,enapassNew,log,startTime,verb,sim, aaa, tac, opts.nocheck)
			if ret != 0:
				log.write ("%sSkip %s\n"%(time(1),host))
				# --- Log file for hosts in error
				if error is None:
					error = open ("log/%s/HostError.log"%startTime,"w+")
				error.write ("%s\n"%host)
				print "### Skip %s"%host
				continue
		try:
			hostfile.close()
		except IOError:
			print "## I can't close the file you specified"
		print "### All hosts parsed"
		log.write ("%s### All host parsed ##\n"%time(1))
		
# --- applying commands from the file to the hosts in args
	elif opts.commandfile is not None and len(sys.argv) > 1:
		#arguments + commandes
		(user,sshpass,enapass)=credentials()
		for host in hosts:
			if host and host[-1] == '\n':
				host = host[:-1]
			print ">>> Working on host %s"%host
			ret = custom(host,user,sshpass,enapass,opts.commandfile,log,startTime,verb,sim)
			if ret != 0:
				log.write ("%sSkip %s\n"%(time(1),host))
				# --- Log file for hosts in error
				if error is None:
					error = open ("log/%s/HostError.log"%startTime,"w+")
				error.write ("%s\n"%host)
				print "### Skip %s"%host
				continue
			print "### All hosts parsed"
			log.write ("%s### All host parsed ##\n"%time(1))
			
# --- changing password for hosts in the file
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
				print ">>> host %s"%host
				ret=userlist(host,user,sshpass,enapass,log,startTime,verb)
				if ret != 0:
					log.write ("%sSkip %s\n"%(time(1),host))
					# --- Log file for hosts in error
					if error is None:
						error = open ("log/%s/HostError.log"%startTime,"w+")
					error.write ("%s\n"%host)
					print "### Skip %s"%host
					continue
		elif opts.showusr is None:
			if opts.newusr:
				(newuser,user,sshpass,enapass,sshpassNew,enapassNew)=credential_chain_new(log)
				if sim:
					newuser=user
			else:
				(user,sshpass,enapass,sshpassNew,enapassNew)=credential_chain(log)
				newuser=user
			for host in hostfile:
				if host and host[-1] == '\n':
					host = host[:-1]
				print ">>> Working on host %s"%host
				ret = changepass(host,user,newuser,sshpass,sshpassNew,enapass,enapassNew,log,startTime,verb,sim, aaa, tac, opts.nocheck)
				if ret != 0:
					log.write ("%sSkip %s\n"%(time(1),host))
					# --- Log file for hosts in error
					if error is None:
						error = open ("log/%s/HostError.log"%startTime,"w+")
					error.write ("%s\n"%host)
					print "### Skip %s"%host
					continue
		try:
			hostfile.close()
		except IOError:
			print "## I can't close the file you specified"
			sys.exit(2)
		print "### All hosts parsed"
		log.write ("%s### All host parsed ##\n"%time(1))
		
# --- show run
	elif opts.showrun:
		if len(sys.argv) <= 2:
			parser.print_help()
			log.write ("%sNo host provided - exiting\n"%time(1))
			sys.exit(2)
		(user,sshpass,enapass)=credentials()
		ret = show_run(host,user,sshpass,enapass,log,startTime,verb)
		## nécessaire ???
		if ret != 0:
			log.write ("%sSkip %s\n"%(time(1),host))
			# --- Log file for hosts in error
			if error is None:
				error = open ("log/%s/HostError.log"%startTime,"w+")
			error.write ("%s\n"%host)
			print "### Skip %s"%host
			#continue
		print "### All hosts parsed : check out the './out' folder for user list"
		log.write ("%s### All host parsed ##\n"%time(1))
		
# --- changing password for hosts in args
	else:
		if len(sys.argv) <= 1:
			parser.print_help()
			log.write ("%sNo host provided - exiting\n"%time(1))
			sys.exit(2)
		if opts.showusr:
			(user,sshpass,enapass)=credentials()
			for host in hosts:
				if host and host[-1] == '\n':
					host = host[:-1]
				print ">>> host %s"%host
				ret=userlist(host,user,sshpass,enapass,log,startTime,verb)
				if ret != 0:
					log.write ("%sSkip %s\n"%(time(1),host))
					# --- Log file for hosts in error
					if error is None:
						error = open ("log/%s/HostError.log"%startTime,"w+")
					error.write ("%s\n"%host)
					print "### Skip %s"%host
					continue
			print "### All hosts parsed : check out the './out' folder for user list"
			log.write ("%s### All host parsed ##\n"%time(1))
		elif opts.showusr is None:
			if opts.newusr:
				(newuser,user,sshpass,enapass,sshpassNew,enapassNew)=credential_chain_new(log)
				if sim is True:
					newuser=user
			else:
				(user,sshpass,enapass,sshpassNew,enapassNew)=credential_chain(log)
				newuser=user
			for host in hosts:
				if host and host[-1] == '\n':
					host = host[:-1]
				print ">>> Working on host %s"%host
				ret = changepass(host,user,newuser,sshpass,sshpassNew,enapass,enapassNew,log,startTime,verb,sim, aaa, tac, opts.nocheck)
				if ret != 0:
					log.write ("%sSkip %s\n"%(time(1),host))
					# --- Log file for hosts in error
					if error is None:
						error = open ("log/%s/HostError.log"%startTime,"w+")
					error.write ("%s\n"%host)
					print "### Skip %s"%host
					continue
			print "### All hosts parsed"
			log.write ("%s### All host parsed ##\n"%time(1))
	try:
		log.close()
		if error:
			error.close()
	except IOError:
			print "## I can't close the file you specified"
	return 0

if __name__ == '__main__':
    try:
		# --- open log file
		if os.path.exists('log') == False:
			os.mkdir('log')
		#time.sleep(1)
		startTime=time(0)
		if os.path.exists('log/%s'%startTime) == False:
			os.mkdir('log/%s'%startTime)
		log = open ("log/%s/CiscoRemote-%s.log"%(startTime,startTime),"w")
		log.write ("%s## CiscoRemote started ##\n"%time(1))
		ret = main(log,startTime)
		if ret==0:
			sys.exit(0)
		else:
			sys.exit(1)
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
