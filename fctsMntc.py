import logs
import BDD
import hashlib
import sqlite3
import os
import config
import shutil
import time
import autresFonctions
import socket

def verifNoeud():
	BDD.verifExistBDD()
	conn = sqlite3.connect('WTP.db')
	cursor = conn.cursor()
	cursor.execute("""SELECT IP FROM Noeuds WHERE 1""")
	rows = cursor.fetchall()
	for row in rows:
		# Prend un à un chaque noeud de la liste, et lui envoie une request.
		# Si le noeud répond, on le laisse tranquille, sinon on le met dans une autre table.
		IppeerPort = row[0]
		#Départager l'IP et le port
		pos1 = IppeerPort.find(":")
		pos1 = pos1+1
		pos2 = len(IppeerPort)
		peerPort = int(IppeerPort[pos1:pos2])
		pos1 = pos1-1
		peerIP = IppeerPort[0:pos1]
		# Liaison tcp/ip
		c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# Connection au receveur
		try:
			c.connect((peerIP, peerPort))
		except Exception as erreur:
			# Le noeud est injoignable, on le déplace dans une autre table.
			BDD.ajouterEntree("NoeudsHorsCo", IppeerPort)
			BDD.supprEntree("Noeuds", IppeerPort)
			logs.addLogs("INFO : Connection to the peer impossible : '" + str(erreur) + "' (verifNoeud())")
		else:
			sendCmd = "=cmd DemandePresence"
			sendCmd = sendCmd.encode()
			# On envoie le message
			c.send(sendCmd)
			rcvData = c.recv(1024)
			rcvData = rcvData.decode()
			if rcvData != '=cmd Present':
				# Le noeud n'est pas connecté au réseau, on le déplace dans une autre table.
				BDD.ajouterEntree("NoeudsHorsCo", IppeerPort)
				BDD.supprEntree("Noeuds", IppeerPort)

def verifNoeudHS():
	BDD.verifExistBDD()
	conn = sqlite3.connect('WTP.db')
	cursor = conn.cursor()
	cursor.execute("""SELECT IP FROM NoeudsHorsCo WHERE 1""")
	rows = cursor.fetchall()
	for row in rows:
		# Prend un à un chaque noeud de la liste, et lui envoie une request.
		# Si le noeud répond, on le laisse tranquille, sinon on le met dans une autre table.
		IppeerPort = row[0]
		#Départager l'IP et le port
		pos1 = IppeerPort.find(':')
		pos1 = pos1+1
		pos2 = len(IppeerPort)
		peerPort = int(IppeerPort[pos1:pos2])
		pos1 = pos1-1
		peerIP = IppeerPort[0:pos1]
		# Liaison tcp/ip
		c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# Connection au receveur
		try:
			c.connect((peerIP, peerPort))
		except Exception:
			logs.addLogs("ERROR : Connection to the peer out of service impossible. (verifNoeudHS())")
			# Le noeud n'est pas connecté au réseau
			# On incrémente son nombre de vérifs et on le supprime si besoin
			BDD.incrNbVerifsHS(IppeerPort)
			BDD.verifNbVerifsHS(IppeerPort)
		else:
			sendCmd = b""
			sendCmd = "=cmd DemandePresence"
			sendCmd = sendCmd.encode()
			# On envoie le message
			c.send(sendCmd)
			rcvData = c.recv(1024)
			rcvData = rcvData.decode()
			if rcvData == '=cmd Present':
				# C'est bon, le noeud est connecté au reseau,
				# on l'ajoute à la table normale et on le supprime de la table des noeuds HS
				BDD.ajouterEntree("Noeuds", IppeerPort)
				BDD.supprEntree("NoeudsHorsCo", IppeerPort)
			else:
				# Le noeud n'est pas connecté au réseau, on incrémente de 1 son nombre de vérifications.
				BDD.incrNbVerifsHS(IppeerPort)
				# On vérifie si le noeud a un nombre de vérifications inférieur à 10.
				# Si ce n'est pas le cas, il est supprimé définitivement.
				BDD.verifNbVerifsHS(IppeerPort)

def verifFichier():
	# Prend les files un à un dans la BDD, puis les vérifie.
	# Il doit être présent sur le disque.
	# LE SHA256 doit être identique au nom.
	# Sinon on envoie vers la fonction qui supprime le file de la BDD et du disque
	BDD.verifExistBDD()
	conn = sqlite3.connect('WTP.db')
	cursor = conn.cursor()
	cursor.execute("""SELECT Chemin FROM Fichiers WHERE 1""")
	rows = cursor.fetchall()
	for row in rows:
		fileName = row[0]
		path = row[0]
		while fileName.find('/') != -1:
			fileName = fileName[fileName.find('/')+1:]
		fileSHA = fileName[:fileName.find('.')]
		# Et voilà, on a juste le nom du file, sans extention,
		# ce qui correspond normalement au SHA256 du contenu de celui-ci
		try:
			file = open(path, "rb")
			contenu = file.read()
			file.close()
		except FileNotFoundError:
			logs.addLogs("INFO : The file isn't founded : "+str(path))
			BDD.supprEntree("Fichiers", fileName)
			logs.addLogs("ERROR : The file " + fileName + " has been deleted from the database.")
		else:
			# On vérifie si le SHA256 correspond au contenu du file.
			SHAContenuFichier = hashlib.sha256(str(contenu).encode('utf-8')).hexdigest()
			if fileSHA == SHAContenuFichier:
				# Le file a le même hash que son nom, c'est bon.
				# Si le programme est arrivé jusqu'à là, c'est que le file existe egalement.
				logs.addLogs("INFO : The file " + fileName + " has been verified without errors.")
			else:
				#Il y a une erreur. Le file doit être supprimé,
				# car il peut nuire au bon fonctionnement du réseau.
				BDD.supprEntree("Fichiers", fileName)
				logs.addLogs("ERROR : The file " + fileName + " contained errors. It has been deleted.")

def creerFichier():
	# Fonction qui va s'executer via la maintenance assez régulièrement
	# Elle regarde dans le dossier ADDFILES si il y a des files
	# Si oui, elle les copie dans le dossier HOSTEDFILES, les renomme de type SHA256.extention
	# Elle envoie vers la fonction contenue dans BDD.py qui va ajouter les files à la base de données
	# Et pour finir, elle supprime les files ajoutés de façon à ce que le dossier ADDFILES soit vide.
	repertoire = "ADDFILES"
	# Vérifier si le dossier ADDFILES existe, sinon le créer
	try:
		os.makedirs("ADDFILES")
	except OSError:
		if not os.path.isdir("ADDFILES"):
			raise
	# Vérifier si le dossier HOSTEDFILES existe, sinon le créer
	try:
		os.makedirs("HOSTEDFILES")
	except OSError:
		if not os.path.isdir("HOSTEDFILES"):
			raise
	dirs = os.listdir(repertoire)
	# This would print all the files and directories
	for file in dirs:
		file = repertoire + "/" + file
		if os.path.isfile(file):
			# L'élément est un file, c'est bon (et pas un dossier)
			try:
				with open(file, "rb") as fluxLecture:
					contenu = fluxLecture.read()
					fluxLecture.close()
			except UnicodeDecodeError:
				logs.addLogs("ERROR : The file is not supported : "+str(file))
				os.remove(file)
			else:
				shaFichier = hashlib.sha256(str(contenu).encode()).hexdigest()
				osef, extention = os.path.splitext(file)
				filename = shaFichier + extention
				fileDir = "HOSTEDFILES/" + filename
				fluxEcriture = open(fileDir, "wb")
				fluxEcriture.write(contenu)
				fluxEcriture.close()
				os.remove(file)
				# L'ajouter à la BDD
				BDD.ajouterEntree("Fichiers", filename)
				logs.addLogs("INFO : A new hosted file has been added successfully : " + filename)
				# On transmet à quelques noeuds l'information
				tableau = BDD.aleatoire("Noeuds", "IP", 15, "Parser")
				if isinstance(tableau, list) and len(tableau) == 15:
					# On envoi la request à chaque noeud sélectionné
					for peerIP in tableau:
						connNoeud = autresFonctions.connectionClient(peerIP)
						if str(connNoeud) != "=cmd ERROR":
							logs.addLogs("INFO : Connection with peer etablished")
							request = "=cmd newFileNetwork name " + filename + " ip " + str(config.readConfFile("MyIP")) + str(config.readConfFile("defaultPort"))
							request = request.encode()
							connNoeud.send(request)
							rcvCmd = connNoeud.recv(1024)
							connNoeud.close()
							if rcvCmd == "=cmd noParser":
								# Il faut changer le paramètre du noeud, il n'est pas parseur mais simple
								BDD.supprEntree("Noeuds", peerIP)
								BDD.ajouterEntree("Noeuds", peerIP)
							elif rcvCmd != "=cmd fileAdded":
								# Une erreur s'est produite
								logs.addLogs("ERROR : The request was not recognized in creerFichier() : "+str(rcvCmd))
						else:
							logs.addLogs("ERROR : An error occured in creerFichier() : "+str(connNoeud))
				else:
					# Une erreur s'est produite
					logs.addLogs("ERROR : There is not enough IP in creerFichier() : "+str(tableau))

def checkIntruders():
	# Cette fonction a pour but de vérifier qu'il n'y a pas de fichiers
	# Qui ne devrait pas l'être dans HOSTEDFILES, sinon ils sont supprimés
	for file in os.listdir("HOSTEDFILES/"):
		file = "HOSTEDFILES/"+file
		if os.path.isdir(str(file)) is False:
			# C'est un fichier, on vérifie qu'il existe dans la BDD
			BDD.verifExistBDD()
			conn = sqlite3.connect('WTP.db')
			cursor = conn.cursor()
			try:
				cursor.execute("""SELECT ID FROM Fichiers WHERE Chemin = ?""", (file,))
				conn.commit()
			except Exception as e:
				conn.rollback()
				logs.addLogs("ERROR : Problem with database (checkIntruders()):" + str(e))
				error += 1
			rows = cursor.fetchall()
			if str(rows) == "[]":
				# Il n'existe pas, on le déplace vers ADDFILES
				dest = "ADDFILES/"+str(file[12:])
				if file != dest:
					if os.path.exists(dest) is False:
						# Exception pour les fichiers temporels :
						# On les supprime si ils ont plus de 24h
						if str(file[12:16]) == "TEMP":
							actTime = str(time.time())
							if int(file[16:file.find(".")]) < int(actTime[:actTime.find(".")])-86400:
								os.remove(file)
								logs.addLogs("INFO : A temporary file has been deleted : "+str(file[12:]))
						else:
							try:
								shutil.copyfile(file,dest)
							except Exception as e:
								logs.addLogs("ERROR : The file " + file + " could not be copied in checkIntruders : "+str(e))
							else:
								os.remove(file)
								logs.addLogs("INFO : The file has been moved from HOSTEDFILES to ADDFILES because it was not in the database")
		else:
			# C'est un dossier, on supprime
			shutil.rmtree(file)

def supprTemp():
	# Fonction qui a pour but de supprimer les fichiers dans TEMP
	# S'ils ont plus que 5 minutes
	autresFonctions.verifFiles()
	dateAct = str(time.time())
	for file in os.listdir(".TEMP/"):
		file = str(".TEMP/"+file)
		if os.path.isdir(file) is False:
			try:
				if float(dateAct) > float(file)+300:
					os.remove(file)
			except Exception:
				os.remove(file)
		else:
			# C'est un dossier, on supprime
			shutil.rmtree(file)
