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
from optparse import OptionParser, OptionGroup
	
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
def connect (host,user,sshpass,enapass, log, startTime,verb,logincount, debug):
	log.write ("%s* Trying to connect to %s\n"%(time(1),host))
	if verb:
		print ">>> Connecting to %s..."%host
# --- create the cisco object
	cisco = ciscoSsh(host, user, sshpass,enapass,log,startTime,logincount, debug)
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
def changepass (host,user,newuser,sshpass,sshpassNew, enapass,enapassNew,log,startTime,verb,sim, aaa, tac, nocheck, debug):
	logincount = 0 # login ID for concurrent ssh session
# --- call to connect function
	cisco=connect(host, user, sshpass, enapass, log, startTime,verb, logincount, debug)
# --- if cisco is an object, the connection process was successful
	if isinstance(cisco,ciscoSsh) != True:
		if verb:
			print ("### Could not retrieve an object")
		return (1)
# --- call to function to enter configure terminal mode
	cisco=confter(cisco,log,verb)
	if isinstance(cisco,ciscoSsh) != True:
		if verb:
			print ("### Configure Terminal : could not retrieve an object")
		return (1)
	if verb:
		print ">>> Changing passwords"
# --- not simulation : we call the function to change the ssh password
	if sim is None:
		if aaa:
			ret = cisco.aaa()
			if ret != 0 :
				log.write ("%sFailed to change AAA mode - exiting\n"%time(1))
				print "## Failed to change AAA mode !"
				return (1)
			else:
				log.write ("%sAAA mode changed\n"%time(1))
				if verb:
					print ">>> AAA mode changed"
		ret = cisco.ssh_change(newuser,sshpassNew)
		if ret != 0 :
			log.write ("%sFailed to change SSH password - exiting\n"%time(1))
			print "## Failed to change SSH password !"
			return (1)
# --- simulation : we don't do anything and continue
	else:
		log.write ("%sOperation changing password skipped : simulation mode\n"%time(1))
		if verb:
			print "!!! Operation changing password skipped : simulation mode"
	log.write ("%sSSH password successfully changed\n"%time(1))
	if verb:
		print ">>> Password successfully changed"
# --- not simulation : we change the enable password
	if sim is None:
		ret = cisco.ena_change(enapassNew)
		if ret != 0 :
			log.write ("%sFailed to change Enable password- exiting\n"%time(1))
			print "## Failed to change Enable password"
			return (1)
# --- simulation : we don't do anything and continue
	else:
		log.write ("%sOperation changing enable password skipped : simulation mode\n"%time(1))
		if verb:
			print "!!! Operation changing enable password skipped : simulation mode"
	log.write ("%sEnable password successfully changed\n"%time(1))
	if verb:
		print ">>> Enable password successfully changed"
# --- validate the new credentials (simuler connexion)
	if verb:
			print ("... Checking new credentials")
# --- try to connect with the new password
	if nocheck is None:
		logincount = logincount + 1
		if tac:
			cisco2=connect(host, user, sshpass, enapass, log, startTime,verb, logincount, debug)
		else:
			cisco2=connect(host, newuser, sshpassNew, enapassNew, log, startTime,verb, logincount, debug)
	# --- test if connection was successful
		if isinstance(cisco2,ciscoSsh) != True:
			if verb:
				print ("### Could not retrieve an object")
# --- new user log in failed : stop here, don't delete any account
			log.write ("%sFailed do log-in with new credentials - stopping here for %s\n"%(time(1),host))
			print "## Failed do log-in with new credentials - stopping here for this host"
			return (1)
		# --- we close connection
		close_connect(cisco2, log, verb, 0)
# --- delete extra accounts
	ret = cisco.exit()
	if ret != 0 :
		log.write ("%sFailed to exit\n"%time(1))
		print "## Failed to exit"
		return (1)
	userlist = cisco.show_username()
	if verb:
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
		if verb == True:
			print ">>> Underisable users deleted"
# --- check again the connection
# --- open a new session cisco2 and keep the cisco one alive until it is checked
# --- give back a shell to the user otherwise
	if nocheck is None:
		logincount = logincount + 1
		if tac:
			cisco2=connect(host, user, sshpass, enapass, log, startTime,verb, logincount, debug)
		else:
			cisco2=connect(host, newuser, sshpassNew, enapassNew, log, startTime,verb, logincount, debug)
		if cisco2 == 1 :
	# --- new user log in failed : stop here, don't delete any account
			log.write ("%sValid user potentially deleted by mistake on %s - Manual session\n"%(time(1),host))
			print "## OUPS ! Something got smelly : I could not log-in back. I am afraid that I deleted the valid user. Please check it manually in the session below :"
	# --- open interactive shell to allow the user to check it
			cisco.interactive()
			# --- we close connection
			close_connect(cisco, log, verb, 0)
			ret = cisco.ssh_close(0)
			return (1)
		# --- we close connection
		close_connect(cisco2, log, verb, 0)
# --- all fine !
	log.write ("%sOld user deleted and new user validated for %s\n"%(time(1),host))
# --- write conf to startup config
	ret=cisco.writemem()
	if verb:
		print ">>> New user validated again"
		print ">>> Exiting and closing connection"
# --- we close connection
	close_connect(cisco, log, verb, 0)
	return 0

#===============================================================================
# This function read the command file line by line and send it to the cisco device
#===============================================================================
def custom (host,user,sshpass,enapass,commandfile,log,startTime,verb,sim, debug):
# --- open the connection
	logincount = 0
	error = None
	cisco=connect(host, user, sshpass, enapass, log, startTime,verb, logincount, debug)
	if isinstance(cisco,ciscoSsh) != True:
		if verb:
			print ("### Could not retrieve an object")
		return 1
# --- enter configure terminal mode
	cisco=confter(cisco,log,verb)
	if isinstance(cisco,ciscoSsh) != True:
		if verb:
			print ("### Configure Terminal : could not retrieve an object")
		return (1)
# --- open the file of custom commands
	if verb:
		print (">>> Opening command file %s"%commandfile)
	commands = fileopen("%s"%commandfile)
	if verb:
		print ">>> Parsing commands"
# --- parse the host file
	for command in commands:
		command = line_cleanup(command)
		print ("... %s"%command)
	# --- not simulating : send the custom command to each host of the file
		if sim is None :
			ret = cisco.custcommand(command)
			if ret != 0:
				f_command_skip(host,error,log)
				continue
	# --- simulating : don't do anything and continue
		else:
			log.write ("%sOperation skipped : simulation mode\n"%(datetime.time(1)))
			if verb:
				print ">>> Operation skipped : simulation mode"
# --- close the file
	fileclose(commands)
	print "## All commands parsed"
	log.write ("%s## All commands parsed ##\n"%time(1))
# --- write conf to startup config
	ret=cisco.writemem()
	if verb:
		print ">>> Exiting and closing connection"
# --- we close connection
	close_connect(cisco, log, verb, 0)
	return 0

#===============================================================================
# Put down the program options
#===============================================================================
def process_args(): 
	parser = OptionParser(usage="usage: %prog [options] host1 host2 ... hostn", version="%prog 0.42-isis-a")
	parser.add_option("-v", "--verbose", action="store_true", dest="verb", help="Print verbose output.")
	parser.add_option("-f", "--hostfile", action="store", dest="file", metavar="FILE", help="Remote hosts file.")
	parser.add_option("-c","--commands", action="store", dest="commandfile", metavar="FILE", help="Commands file")
	parser.add_option("-n","--newuser", action="store_true", dest="newusr", help="Add user mode")
	parser.add_option("-t","--tacacs", action="store_true", dest="tacacs", help="The management account is a tacacs one")
	parser.add_option("--no-check", action="store_true", dest="nocheck", help="No proof check")
	parser.add_option("-u","--showuser", action="store_true", dest="showusr", help="Show user mode")
	parser.add_option("-s","--simulate", action="store_true", dest="simu", help="Simulation mode")
	parser.add_option("-r","--shrun", action="store_true", dest="showrun", help="[EXPERIMENTAL] Show Run")
	parser.add_option("-a","--aaa", action="store_true", dest="aaa", help="[EXPERIMENTAL] Change AAA model")
	return parser

#===============================================================================
# Little function to open files
#===============================================================================
def fileopen(path):
	try:
		file=open("%s"%path,"r")
	except IOError:
		print "## I can't read the file you specified"
		sys.exit(2)
	return (file)

#===============================================================================
# Little function to close files
#===============================================================================
def fileclose(file):
	try:
		file.close()
	except IOError:
		print "## I can't close the file you specified"
	return 0

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

def userlist(host,user,sshpass,enapass,log, startTime,verb, debug):
# --- open a connection
	logincount = 0
	cisco=connect(host,user,sshpass,enapass, log, startTime,verb, logincount, debug)
	if isinstance(cisco,ciscoSsh) != True:
		if verb:
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
		if verb:
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
	# --- we close connection
	close_connect(cisco, log, verb, 0)
	return 0

#===============================================================================
# Update ntp servers
#===============================================================================

def ntpserver(host,user,sshpass,enapass,log, startTime,verb,newntpsrv, debug):
# --- open a connection
	logincount = 0
	cisco=connect(host,user,sshpass,enapass, log, startTime,verb, logincount, debug)
	if isinstance(cisco,ciscoSsh) != True:
		if verb:
			print ("### Could not retrieve an object")
		return 1
# --- call the function to extract ntp servers
	ntpsrv = cisco.show_ntp()
# --- log it in a dedicated folder
	if os.path.exists('out') == False:
	   os.mkdir('out')
	if os.path.exists('out/%s'%startTime) == False:
	   os.mkdir('out/%s'%startTime)
# --- enter configure terminal mode
	cisco=confter(cisco,log,verb)
	if isinstance(cisco,ciscoSsh) != True:
		if verb:
			print ("### Configure Terminal : could not retrieve an object")
		return (1)
# --- print and suppress ntp servers
	if ntpsrv:
		if verb:
			print "<-- %s -->"%host
		flist = open ("out/%s/ntp.log"%startTime,"a")
		flist.write ("%s"%host)
		for i in ntpsrv:
			print "%s"%i
			flist.write (";%s"%i)
		ret = cisco.no_ntp_server(ntpsrv)
		if ret != 0:
			log.write ("%sSkip %s\n"%(time(1),host))
			error = open ("log/%s/ntpserver.log"%startTime,"w+")
			error.write ("%s\n"%host)
			print ("Command no 'ntp server' failed with %s"%i)
		flist.write ("\n")
		flist.close()
	else :
		print "### Empty string returned !"
		log.write ("%sEmpty string returned instead of ntp server list\n"%time(1))
		#return 1
# --- add ntp servers
	if newntpsrv:
		for i in newntpsrv:
			print "... added %s"%i
		ret=cisco.ntp_server(newntpsrv)
		if ret != 0:
			log.write ("%sSkip %s\n"%(time(1),host))
			error = open ("log/%s/ntpserver.log"%startTime,"w+")
			error.write ("%s\n"%host)
			print ("Command 'ntp server' failed with %s"%i)
	log.write ("%sRetrieved successfully a ntp server list\n"%time(1))
	# --- write conf to startup config
	ret=cisco.writemem()
	if verb:
		print ">>> Exiting and closing connection"
# --- we close connection
	close_connect(cisco, log, verb, 0)
	return 0

#===============================================================================
# show run and print it to stdout
#===============================================================================		
def show_run(host,user,sshpass, enapass, log, startTime, verb, debug):
	logincount = 0
	cisco=connect(host,user,sshpass,enapass, log, startTime,verb, logincount, debug)
	if isinstance(cisco,ciscoSsh) != True:
		if verb:
			print ("### Could not retrieve an object")
		return 1
	cisco.sh_run()
	return 0

#===============================================================================
# close connection
#===============================================================================	
def close_connect(cisco, log, verb, flag):
	ret = cisco.ssh_close(flag)
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
# clean go to line character
#===============================================================================
def line_cleanup(line):
	if line and line[-1] == '\n':
		line = line[:-1]
	return line

#===============================================================================
# host error log function
#===============================================================================
def f_error_skip(host,error,log):
	log.write ("%sSkip %s\n"%(time(1),host))
	# --- Log file for hosts in error
	if error is None:
		error = open ("log/%s/HostError.log"%startTime,"w+")
		error.write ("%s\n"%host)
		print "### Skip %s"%host
	return 0

#===============================================================================
# command error log function
#===============================================================================
def f_command_skip(command,host,error,log):
	log.write ("%sSkip %s\n"%(time(1),command))
	# --- Log file for hosts in error
	if error is None:
		error = open ("log/%s/CommandError.log"%startTime,"w+")
		error.write ("%s --> %s\n"%(host,command))
		print "### Skip %s"%command
	return 0

#===============================================================================
# end of hosts process log function
#===============================================================================
def f_hosts_end(log):
	print "### All hosts parsed"
	log.write ("%s### All host parsed ##\n"%time(1))
	return 0

#===============================================================================
# Put down the program options
#===============================================================================
def process_args(): 
	parser = OptionParser(usage="usage: %prog [options] host1 host2 ... hostn", version="%prog 0.51")
	#group = OptionGroup(parser, "Options","Optional settings for tracing and debugging.")
	parser.add_option("-v", "--verbose", action="store_true", dest="verb", help="Print verbose output.")
	parser.add_option("-d","--debug", action="store_true", dest="debug", help="Debug mode : verbose and extra logs")
        #parser.add_option_group(group)
        group = OptionGroup(parser, "Password change mode","Mode to edit the local admin account of a router within SSH.")
	group.add_option("-f", "--hostfile", action="store", dest="file", metavar="FILE", help="Remote hosts file.")
	group.add_option("-c","--commands", action="store", dest="commandfile", metavar="FILE", help="Commands file")
	group.add_option("-n","--newuser", action="store_true", dest="newusr", help="Add user mode")
	group.add_option("-t","--tacacs", action="store_true", dest="tacacs", help="The management account is a tacacs one")
        group.add_option("-s","--simulate", action="store_true", dest="simu", help="Simulation mode")
        group.add_option("-a","--aaa", action="store_true", dest="aaa", help="[EXPERIMENTAL] Change AAA model")
        group.add_option("--no-check", action="store_true", dest="nocheck", help="No proof check")
        parser.add_option_group(group)
        group = OptionGroup(parser, "User list mode","Mode to retrieve the local users configured in a router")
        group.add_option("-u","--showuser", action="store_true", dest="showusr", help="Show user mode")
        parser.add_option_group(group)
        group = OptionGroup(parser, "Show run mode","Mode to retrieve the whole running configuration a router")
	group.add_option("-r","--shrun", action="store_true", dest="showrun", help="[EXPERIMENTAL] Show Run")
        parser.add_option_group(group)
        group = OptionGroup(parser, "NTP change mode","Mode to update the ntp servers set in a router")
	group.add_option("-p","--ntp-server", action="append", dest="ntp", help="[EXPERIMENTAL] Change ntp servers")
        parser.add_option_group(group)
	return parser

#===============================================================================
# Check options
#===============================================================================
def opts_check(parser,hosts,opts):

# --- not file mode and no argument
	if len(hosts) < 1 and opts.file is None:
		parser.error("### Incorrect number of arguments ###")
# --- various warnings
	if opts.debug:
		print \
"################################################################################\n\
# Beware that in debug mode, logfiles may contain sensible data like passwords.#\n\
# Erase them after use : rm -rf log                                            #\n\
################################################################################\n"
		
	if opts.commandfile:
		print \
"###############################################################################\n\
# Use this mode at your own risk :                                            #\n\
# I don't check the commands, so the command file has to be safe and clean.   #\n\
###############################################################################\n\
>> Confirm :"
		ret = raw_input("Yes / No\n")
		res = re.match("Y|y",ret)
		if res == None:
			sys.exit(1)

# --- check triggered options
        passmode_trig = opts.file or opts.commandfile or opts.newusr or opts.tacacs or opts.simu or opts.aaa or opts.simu
        shusrmode_trig = opts.showusr
        shrunmode_trig = opts.showrun
        ntpmode_trig = opts.ntp
        if (
        (passmode_trig and (shusrmode_trig or shrunmode_trig or ntpmode_trig)) or
        (shusrmode_trig and (shrunmode_trig or ntpmode_trig)) or
        (shrunmode_trig and ntpmode_trig)
        ):
          parser.error("Given options are mutually exclusive - check HELP\n")
	return opts

#==============================================================================#
#----------------------------------- MAIN -------------------------------------#
#==============================================================================#
		
def main(log,startTime):
	
# --- check the options
	parser = process_args()
# --- retrieve options and hosts through the args (those will be overwritten if a file is given with -f)
	(opts, hosts) = parser.parse_args()
# --- check for content and compatibility between modes	
	opts = opts_check(parser,hosts,opts)
# --- open the error filehandler only one time, when the first host error happen	
	error = None

# --- begin of custom command mode
	if opts.commandfile:
	# --- host file
		if opts.file:
			hosts = fileopen("%s"%opts.file)		
	# --- read credentials
		(user,sshpass,enapass)=credentials()		
	# -- hosts parsing
		for host in hosts:
			# clean up
			host=line_cleanup(host)
			print ">>> Working on host %s"%host
			ret = custom(host,user,sshpass,enapass,opts.commandfile,log,startTime,opts.verb,opts.simu, opts.debug)
			if ret != 0:
				f_error_skip(host,error,log)
				continue
		if opts.file:
			fileclose(hosts)
		f_hosts_end(log)
# --- end of custom command mode

# --- show user mode
	elif opts.showusr:
		# --- host file
		if opts.file:
			hosts = fileopen("%s"%opts.file)
		(user,sshpass,enapass)=credentials()
		for host in hosts:
			# clean up
			host=line_cleanup(host)
			print ">>> Host %s"%host
			ret=userlist(host,user,sshpass,enapass,log,startTime,opts.verb, opts.debug)
			if ret != 0:
				f_error_skip(host,error,log)
				continue
		if opts.file:
			fileclose(hosts)
		f_hosts_end(log)
# --- end of show user mode

# --- show run mode
	elif opts.showrun:
		# --- host file
		if opts.file:
			hosts = fileopen("%s"%opts.file)
		(user,sshpass,enapass)=credentials()
		for host in hosts:
			# clean up
			host=line_cleanup(host)
			print ">>> Host %s"%host
			ret=show_run(host,user,sshpass,enapass,log,startTime,opts.verb, opts.debug)
			if ret != 0:
				f_error_skip(host,error,log)
				continue
		if opts.file:
			fileclose(hosts)
		f_hosts_end(log)
# --- end of show run mode

# --- ntp mode
	elif opts.ntp:
		# --- host file
		if opts.file:
			hosts = fileopen("%s"%opts.file)
		(user,sshpass,enapass)=credentials()
		for host in hosts:
			# clean up
			host=line_cleanup(host)
			print ">>> Host %s"%host
			ret=ntpserver(host,user,sshpass,enapass,log,startTime,opts.verb, opts.ntp, opts.debug)
			if ret != 0:
				f_error_skip(host,error,log)
				continue
		if opts.file:
			fileclose(hosts)
		f_hosts_end(log)
# --- end of ntp mode

# --- default mode : change password
	else:
		# --- host file
		if opts.file:
			hosts = fileopen("%s"%opts.file)
		# --- new local user mode...
		if opts.newusr:
			(newuser,user,sshpass,enapass,sshpassNew,enapassNew)=credential_chain_new(log)
			if opts.simu:
				newuser=user
		# --- ... or update local user mode
		else:
			(user,sshpass,enapass,sshpassNew,enapassNew)=credential_chain(log)
			newuser=user
		# -- hosts parsing
		for host in hosts:
			# clean up
			host=line_cleanup(host)
			print ">>> Working on host %s"%host
			ret = changepass(host,user,newuser,sshpass,sshpassNew,enapass,enapassNew,log,startTime,opts.verb,opts.simu, opts.aaa, opts.tacacs, opts.nocheck, opts.debug)
			if ret != 0:
				f_error_skip(host,error,log)
				continue
		if opts.file:
			fileclose(hosts)
		f_hosts_end(log)
# --- end of change password mode

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
