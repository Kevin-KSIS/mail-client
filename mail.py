#########################################################################
#	# Gmail SMTP port (SSL): 		465 smtp.gmail.com
#	# Gmail POP port (SSL): 		995 pop.gmail.com
#	# Mail via telnet command, RFC: https://www.ietf.org/rfc/rfc1939.txt
#	# Set less secure app:			https://www.google.com/settings/security/lesssecureapps
#
#	REQUIRE: run app in cmd (windows), require UTF-8: use command "chcp 65001"
#########################################################################

#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
import socket
import ssl
import base64
import sys
import re
import os
import time
import thread

SMTP_SERVER = "smtp.gmail.com"
POP_SERVER = "pop.gmail.com"
SMTP_PORT = 465
POP_PORT = 995


class Smtp_client:

	def __init__(self, smtpServer, email, password, isDebug = False):
		self.email = email
		self.password = password
		self.smtpServer = smtpServer
		self.sock = socket.socket()
		self.isDebug = isDebug

	def connectSSL(self, port):
		self.sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), ssl_version = ssl.PROTOCOL_SSLv23)
		
		try:
			self.sock.connect((self.smtpServer, port))
			status = self.sock.recv(1024)
			self.debugger('Connecting ... \n> ' + status)
			self.debugger("Connected to the smtp server.")
			cmd = "HELO friends"
			self.sock.send(cmd + '\r\n')
			self.debugger(cmd + '\n> ' + self.sock.recv(1024))
		except Exception as e:
			print e
			return
	
	def connect(self, port):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		try:
			self.sock.connect((self.smtpServer, port))
			status = self.sock.recv(1024)
			self.debugger('Connecting ... \n> ' + status)
			print "Connected to the smtp server."
			cmd = "HELO friends"
			self.sock.send(cmd +  '\r\n')
			self.debugger(cmd + '\n> ' + self.sock.recv(1024))
		except Exception as e:
			print e
			return

	def login(self):
		data = ["AUTH LOGIN", base64.b64encode(self.email), base64.b64encode(self.password)]
		
		for msg in data:
			self.sock.send(msg + '\r\n')
			status = self.sock.recv(1024)
			self.debugger(msg + '\n> ' + status)

			if '530' in status:
				print status
				return 0
			if "535" in status:
				print status
				return 0
			elif "235" in status:
				return 1

	def sendmsg(self, recvMail, subject, msg):
		new_mail = [
			"MAIL FROM: <{}>\r\n".format(self.email),
			"RCPT TO: <{}>\r\n".format(recvMail),
			'DATA\r\n',
			'SUBJECT: {}\r\n'.format(subject) + msg + '\r\n.\r\n'
		]

		print "\nSending ...\n"
		for code in new_mail:
			self.sock.send(code)
			status = self.sock.recv(1024)

		if 'OK' in status:
			print "Sent\n"

	def exit(self):
		print "Quit !!!"
		self.sock.close()
		sys.exit(0)

	def debugger(self, msg):
		if self.isDebug:
			print "::", msg

class Pop_client:

	def __init__(self, popServer, email, password, isDebug = False):
		self.popServer = popServer
		self.email = email
		self.password = password
		self.isDebug = isDebug

	def connectSSL(self, port):
		self.sock = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), ssl_version = ssl.PROTOCOL_SSLv23)
		try:
			self.sock.connect((self.popServer, port))
			status = self.sock.recv(1024)
			self.debugger('Connecting ... \n> ' + status)
		except Exception as e:
			print e
			return

	def connect(self, port):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			self.sock.connect((self.popServer, port))
			status = self.sock.recv(1024)
			self.debugger("Connecting ...\n> " + status)
		except Exception as e:
			print e
			
	def login(self):
		cmd = 'user ' + self.email
		self.sock.send(cmd + '\r\n')
		self.debugger(cmd + '\n> ' + self.sock.recv(1024))

		cmd = 'pass ' + self.password
		self.sock.send('pass ' + self.password + '\r\n')
		status = self.sock.recv(1024)
		self.debugger(cmd + '\n> ' + status)

		# check result
		if 'OK' in status:
			return 1
		if 'ERR' in status:
			print status
			return 0

	def sync(self):
		while True:
			# get synchronize data's count 
			path, dirs, files = os.walk("./.mails/").next()
			count = len(files)

			# create specials folder
			if not os.path.exists("./.mails"):
				os.makedirs("./.mails")

			# count mail on server
			self.sock.send('STAT\r\n')
			s = self.sock.recv(1024)
			noMail = int(s.split(' ')[1])

			# download all email, save to file
			for id in range(1, noMail + 1):
				self.sock.send("retr {}\r\n".format(id))
				body = ''
				while True:
					body += self.sock.recv(1024)
					if '\r\n.\r\n' in body:
						break

				# write contents to file
				file = open("./.mails/raw-{}.mail".format(id + count), "wb")
				file.write(body)
				file.close

			# disconnect
			self.sock.send("quit\r\n")
			self.debugger(self.sock.recv(1024))
			self.sock.close()

			# reconnect
			self.connectSSL(POP_PORT)
			self.login()

	def debugger(self, msg):
		# debugging
		if self.isDebug:
			print "::", msg

def listMail():
	# get synchronize data's count 
	path, dirs, files = os.walk("./.mails/").next()
	count = len(files)

	for file in files:
		mail = open("./.mails/{}".format(file), "rb").read()

		# get subject
		try:
			subject = base64.b64decode(re.findall("Subject:.*B\?(.*)\?=", mail)[0])
		except:
			pass

		# get sender's email
		try:
			mailfrom = re.findall("From:.*(<.*>)", mail)[0]
		except:
			pass

		# get receiver's email
		try:
			mailto = re.findall("To: (.*)\r\nContent-Type", mail)[0]
		except:
			pass

		# detect attachments
		if 'attachment' in mail:
			isAttach = '#'
		else:
			isAttach = ""

		print "{}. {}... {}\n\tFrom: {} \n\tTo: {}".format(re.findall("raw-(.*)\.", file)[0], subject, isAttach, mailfrom, mailto)
		
def readMail(id):
	mail = open("./.mails/raw-{}.mail".format(id), "rb").read()
	# get subject
	subject = base64.b64decode(re.findall("Subject:.*B\?(.*)\?=", mail)[0])
	# get email
	mailfrom = re.findall("From:.*(<.*>)", mail)[0]
	try:
		# get contents
		contents = base64.b64decode(re.findall("base64([\r\n\w\d\+=/]+)", mail)[0])
	except:
		contents = ''

	print '\nSUBJECT: {}'.format(subject)
	print 'FROM: {}\n'.format(mailfrom)
	print contents + '\n'

def delMail(id):
	# delete mail in local
	try:
		os.remove("./.mails/raw-{}.mail".format(id))
		print "Delete complete\n"
	except Exception as e:

		print e, "Can't delete mail\n"

def getAttachments(id):
	# create specials folder
	if not os.path.exists("./.files"):
		os.makedirs("./.files")

	mail = open("./.mails/raw-{}.mail".format(id)).read()

	if 'attachment' in mail:
		filename = re.findall("filename=\"(.*)\"", mail)[0]
		attach = open("./.files/" + filename, 'wb')

		x = re.findall("X-Attachment-Id.*\n\n([\r\n\w\d\+=/]+)\n", mail)[0]
		attach.write(base64.b64decode(x))
		attach.close()
		print 'Downloaded\n'
	else:
		print 'Mail not attachments'

def menu():
	print "\n\tMENU\n"
	print "\n\t[ 1 ] New email "
	print "\n\t[ 2 ] All email	"
	print "\n\t[ 3 ] Read email "
	print "\n\t[ 4 ] Delete email "
	print "\n\t[ 5 ] Download attachments "
	print "\n\t[ 6 ] Quit "
	return int(raw_input("\nEnter a number: "))

def render(msg):
	for i in msg:
		sys.stdout.write(i)
		time.sleep(0.05)

def main():
	# set utf-8 in windows 10
	os.system("chcp 65001")

	# header
	render("===================== WELCOME TO MAIL CLIENT =====================\n")
	render("Username: ")
	uname = raw_input() 
	render("Password: ")
	passwd = raw_input()

	pop = Pop_client(POP_SERVER, uname, passwd, isDebug = False)
	pop.connectSSL(POP_PORT)
	pFlag = pop.login()

	smtp = Smtp_client(SMTP_SERVER, uname, passwd, isDebug = False)
	smtp.connectSSL(SMTP_PORT)
	sFlag = smtp.login()

	if pFlag and sFlag:
		render("Logon to server\n")
	else:
		render("Login fail")
		sys.exit(0)

	# thread synchronize
	try:
		thread.start_new_thread( pop.sync, () )
	except Exception as e:
		print e

	# menu items
	while True:
		choose = menu()

		if choose == 1:
			render("Enter email: ")
			mailto = raw_input()
			render("Enter subject: ")
			subject = raw_input()
			render("Enter message ( newline with \\n | the end with enter key ):\n> ")
			msg = raw_input()
			smtp.sendmsg(mailto, subject, msg)

		if choose == 2:
			# list all mail
			listMail()

		if choose == 3:
			# read special mail
			render("Enter mail's id: ")
			id = raw_input()
			readMail(id)

		if choose == 4:
			# Delete special mail
			render("Enter mail's id: ")
			id = raw_input()
			delMail(id)

		if choose == 5:
			# download attachments
			render("Enter mail's id: ")
			id = raw_input()
			getAttachments(id)

		if choose == 6:
			render("####### SEE YOU ######")
			break

if __name__ == '__main__':
	main()

