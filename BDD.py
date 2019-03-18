import os
import time
import logs
import sqlite3
import fctsClient

def creerBase():
	# Fonction qui a pour seul but de créer la base de données
	# si le file la contenant n'existe pas.
	conn = sqlite3.connect('WTP.db')
	cursor = conn.cursor()
	try:
		cursor.execute("""
			CREATE TABLE IF NOT EXISTS NoeudsHorsCo(
				id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
				IP TEXT,
				NbVerifs INTEGER
			)
		""")
		conn.commit()
		cursor.execute("""
			CREATE TABLE IF NOT EXISTS Fichiers(
				id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
				Nom TEXT,
				DateAjout TEXT,
				Taille INTEGER,
				Chemin TEXT
			)
		""")
		conn.commit()
		cursor.execute("""
			CREATE TABLE IF NOT EXISTS Noeuds(
				id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
				IP TEXT,
				Fonction TEXT default Simple,
				DerSync TEXT,
				DateAjout TEXT
			)
		""")
		conn.commit()
		cursor.execute("""
			CREATE TABLE IF NOT EXISTS FichiersExt(
				id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
				Nom TEXT,
				IP TEXT
			)
		""")
		conn.commit()
		cursor.execute("""
			CREATE TABLE IF NOT EXISTS Statistiques(
				NbNoeuds INTEGER,
				NbSN INTEGER,
				NbFichiersExt INTEGER,
				NbFichiers INTEGER,
				PoidsFichiers INTEGER,
				NbEnvsLstNoeuds INTEGER,
				NbEnvsLstFichiers INTEGER,
				NbEnvsLstFichiersExt INTEGER,
				NbEnvsFichiers INTEGER,
				NbPresence INTEGER,
				NbReceptFichiers INTEGER
			)
		""")
		conn.commit()
		cursor.execute("""
			CREATE TABLE IF NOT EXISTS DNS(
				id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
				SHA256 TEXT,
				NDD TEXT,
				PASSWORD TEXT,
				DateAjout INTEGER
			)
		""")
		conn.commit()
		cursor.execute("""
			CREATE TABLE IF NOT EXISTS BlackList(
				id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE,
				Name TEXT,
				Rank INTEGER
			)
		""")
		conn.commit()
		# On initialise les Statistiques
		cursor.execute("""INSERT INTO Statistiques (NbNoeuds, NbSN, NbFichiersExt, NbFichiers, PoidsFichiers, NbEnvsLstNoeuds, NbEnvsLstFichiers, NbEnvsLstFichiersExt, NbEnvsFichiers, NbPresence, NbReceptFichiers) VALUES (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)""")
		conn.commit()
	except Exception as e:
		conn.rollback()
		logs.addLogs("ERROR : Problem with database (creerBase()) :" + str(e))
	conn.close()

def ajouterEntree(nomTable, entree, entree1 = "", entree2 = ""):
	# Fonction qui permet d'ajouter une entrée à une table de la base
	verifExistBDD()
	error = 0
	# Vérifier si l'entrée existe déjà dans la BDD.
	# Si il existe on ne fait rien
	# Si il n'existe pas, on l'ajoute
	conn = sqlite3.connect('WTP.db')
	cursor = conn.cursor()
	try:
		if nomTable == "Noeuds":
			cursor.execute("""SELECT id FROM Noeuds WHERE IP = ?""", (entree,))
		elif nomTable == "Fichiers":
			cursor.execute("""SELECT id FROM Fichiers WHERE Nom = ?""", (entree,))
		elif nomTable == "FichiersExt":
			cursor.execute("""SELECT id FROM FichiersExt WHERE Nom = ? AND IP = ?""", (entree, entree1))
		elif nomTable == "NoeudsHorsCo":
			cursor.execute("""SELECT id FROM NoeudsHorsCo WHERE IP = ?""", (entree,))
		elif nomTable == "DNS":
			cursor.execute("""SELECT id FROM DNS WHERE NDD = ?""", (entree,))
		elif nomTable == "BlackList":
			cursor.execute("""SELECT id FROM BlackList WHERE Name = ?""", (entree,))
	except Exception as e:
		logs.addLogs("ERROR : Problem with database (ajouterEntree()):" + str(e))
		error += 1
	else:
		nbRes = 0
		rows = cursor.fetchall()
		for row in rows:
			nbRes += 1
		if nbRes != 0:
			# L'entrée existe déjà
			error = 5
			if nbRes > 1:
				logs.addLogs("ERROR : Entry presents several times in the database. (ajouterEntree())")
				error = 7
		else:
			datetimeAct = str(time.time())
			datetimeAct = datetimeAct[:datetimeAct.find(".")]
			# En fonction de la table, il n'y a pas les mêmes champs à remplir
			try:
				if nomTable == "Noeuds":
					if entree1 == "":
						entree1 = str(fctsClient.CmdDemandeStatut(entree[:entree.find(":")], entree[entree.find(":")+1:]))
						if len(entree1) < 3:
							# C'est une erreur
							logs.addLogs("ERROR : When trying to find the status of the peer : " + str(entree1))
							entree1 = "Simple"
					cursor.execute("""INSERT INTO Noeuds (IP, Fonction, DerSync, DateAjout) VALUES (?, ?, ?, ?)""", (entree, entree1, datetimeAct, datetimeAct))
				elif nomTable == "Fichiers":
					pathFichier = "HOSTEDFILES/" + entree
					cursor.execute("""INSERT INTO Fichiers (Nom, DateAjout, Taille, Chemin) VALUES (?, ?, ?, ?)""", (entree, datetimeAct, os.path.getsize(pathFichier), pathFichier))
				elif nomTable == "FichiersExt":
					cursor.execute("""INSERT INTO FichiersExt (Nom, IP) VALUES (?, ?)""", (entree, entree1))
				elif nomTable == "NoeudsHorsCo":
					cursor.execute("""INSERT INTO NoeudsHorsCo (IP, NbVerifs) VALUES (?, 0)""", (entree,))
				elif nomTable == "DNS":
					if entree1 != "" and entree2 != "":
						passwordHash = hashlib.sha256(str(entree2).encode()).hexdigest()
						try:
							cursor.execute("""INSERT INTO DNS (SHA256, NDD, PASSWORD, DateAjout) VALUES (?, ?, ?, ?)""", (entree1, entree, passwordHash, datetimeAct))
							conn.commit()
						except Exception as e:
							logs.addLogs("DNS : ERREUR :" + str(e))
					else:
						logs.addLogs("DNS : ERROR: Parameters missing when calling the function (ajouterEntree())")
						error += 1
				elif nomTable == "BlackList":
					if entree1 == "":
						entree1 = "1"
					cursor.execute("""INSERT INTO BlackList (Name, Rank) VALUES (?, ?)""", (entree, entree1))
				conn.commit()
			except Exception as e:
				conn.rollback()
				logs.addLogs("ERROR : Problem with database (ajouterEntree()):" + str(e))
	conn.close()
	return error

def supprEntree(nomTable, entree, entree1 = ""):
	# Fonction qui permet de supprimer une entrée dans une table
	error = 0
	verifExistBDD()
	conn = sqlite3.connect('WTP.db')
	cursor = conn.cursor()
	try:
		if nomTable == "Noeuds":
			cursor.execute("""DELETE FROM Noeuds WHERE IP =  ?""", (entree,))
		elif nomTable == "Fichiers":
			cursor.execute("""DELETE FROM Fichiers WHERE Nom = ?""", (entree,))
		elif nomTable == "FichiersExt":
			cursor.execute("""DELETE FROM FichiersExt WHERE Nom = ? AND IP = ?""", (entree, entree1))
		elif nomTable == "NoeudsHorsCo":
			cursor.execute("""DELETE FROM NoeudsHorsCo WHERE IP =  ?""", (entree,))
		elif nomTable == "BlackList":
			cursor.execute("""DELETE FROM BlackList WHERE Name = ?""", (entree,))
		elif nomTable == "DNS":
			if entree1 != "":
				# On vérifie que le mot de passe hashé est égal à celui de la base de données,
				# et si c'est le cas on peut suprimer la ligne
				cursor.execute("""SELECT PASSWORD FROM DNS WHERE NDD = ?""", (entree1,))
				rows = cursor.fetchall()
				passwordHash = hashlib.sha256(str(entree1).encode()).hexdigest()
				for row in rows:
					if row[0] == passwordHash:
						cursor.execute("""DELETE FROM DNS WHERE NDD = ? AND PASSWORD = ?""", (entree, passwordHash))
						conn.commit()
					else:
						# Le mot de passe n'est pas valide
						error = 5
			else:
				logs.addLogs("DNS : ERROR: There is a missing parameter to perform this action (supprEntree())")
				error += 1
		conn.commit()
	except Exception as e:
		conn.rollback()
		logs.addLogs("ERROR : Problem with database (supprEntree()):" + str(e))
	else:
		if nomTable == "Noeuds":
			logs.addLogs("INFO : The peer " + entree + " has been removed from the database.")
		elif nomTable == "Fichiers":
			path = "HOSTEDFILES/" + entree
			try:
				os.remove(path)
			except FileNotFoundError:
				logs.addLogs("INFO : The file " + entree + " was already deleted.")
			else:
				logs.addLogs("INFO : The file " + entree + " has been removed.")
		elif nomTable == "FichiersExt":
			logs.addLogs("INFO : The External file " + entree + " has been removed.")
		elif nomTable == "NoeudsHorsCo":
			logs.addLogs("INFO : The peer off " + entree + " has been permanently deleted from the database.")
		elif nomTable == "BlackList":
			logs.addLogs("INFO : The " + entree + " entry has been permanently deleted from the BlackList.")
		elif problem == 0:
			logs.addLogs("DNS : INFO : The " + entree + " entry of the " + nomTable + " table has been removed.")
		else:
			logs.addLogs("DNS : ERROR : The " + entree + " entry of the " + nomTable + " table could not be deleted")
	conn.close()
	return error

def incrNbVerifsHS(ipPort):
	# Vérifie que le noeud existe
	# Si il existe, le noeud est incémenté de 1.
	verifExistBDD()
	conn = sqlite3.connect('WTP.db')
	cursor = conn.cursor()
	try:
		cursor.execute("""SELECT ID FROM NoeudsHorsCo WHERE IP = ?""", (ipPort,))
		rows = cursor.fetchall()
	except Exception as e:
		conn.rollback()
		logs.addLogs("ERROR : Problem with database (incrNbVerifsHS()):" + str(e))
	nbRes = 0
	for row in rows:
		nbRes += 1
	if nbRes != 0:
		# Le noeud existe, on peut l'incrémenter
		try:
			cursor.execute("""UPDATE NoeudsHorsCo SET NbVerifs = NbVerifs + 1 WHERE IP = ?""", (ipPort,))
			conn.commit()
		except Exception as e:
			conn.rollback()
			logs.addLogs("ERROR : Problem with database (incrNbVerifsHS()):" + str(e))
		logs.addLogs("INFO : The number of verifications of "+ ipPort +" has been incremented by 1.")
	else:
		# Le noeud n'existe pas, juste un warning dans les logs.
		logs.addLogs("ERREUR : The peer off "+ ipPort +" could not be incremented because it no longer exists.")
	conn.close()

def verifNbVerifsHS(ipPort):
	# Vérifie que le nombre de vérifications déjà effectuées
	# S'il y en a plus que 10, le noeud est définitivement supprimé
	verifExistBDD()
	conn = sqlite3.connect('WTP.db')
	cursor = conn.cursor()
	try:
		cursor.execute("""SELECT NbVerifs FROM NoeudsHorsCo WHERE IP = ?""", (ipPort,))
		rows = cursor.fetchall()
	except Exception as e:
		conn.rollback()
		logs.addLogs("ERROR : Problem with database(verifNbVerifsHS()):" + str(e))
	nbRes = 0
	for row in rows:
		nbRes = row[0]
	if nbRes > 10:
		# Le noeud doit être supprimé
		try:
			cursor.execute("""DELETE FROM NoeudsHorsCo WHERE IP =  ?""", (ipPort,))
			conn.commit()
		except Exception as e:
			conn.rollback()
			logs.addLogs("ERROR : Problem with database (verifNbVerifsHS()):" + str(e))
		logs.addLogs("INFO : The peer off "+ ipPort +" has been removed, it no longer responds.")
	conn.close()

def verifFichier(fileName):
	# Fonction qui vérifie si le file existe dans la base de données
	verifExistBDD()
	conn = sqlite3.connect('WTP.db')
	cursor = conn.cursor()
	try:
		cursor.execute("""SELECT ID FROM Fichiers WHERE Nom = ?""", (fileName,))
		rows = cursor.fetchall()
	except Exception as e:
		conn.rollback()
		logs.addLogs("ERROR : Problem with database (verifFichier()) : " + str(e))
	FichierExiste = False
	if str(rows) != "[]":
		FichierExiste = True
	conn.close()
	return FichierExiste

def modifStats(colonne, valeur=-1):
	# Si valeur = -1, on incrémente, sinon on assigne la valeur en paramètres
	verifExistBDD()
	conn = sqlite3.connect('WTP.db')
	cursor = conn.cursor()
	try:
		if valeur == -1:
			if colonne == "NbNoeuds":
				cursor.execute("UPDATE Statistiques SET NbNoeuds = 1 WHERE 1")
			elif colonne == "NbFichiersExt":
				cursor.execute("UPDATE Statistiques SET NbFichiersExt = 1 WHERE 1")
			elif colonne == "NbSN":
				cursor.execute("UPDATE Statistiques SET NbSN = 1 WHERE 1")
			elif colonne == "NbFichiers":
				cursor.execute("UPDATE Statistiques SET NbFichiers = 1 WHERE 1")
			elif colonne == "PoidsFichiers":
				cursor.execute("UPDATE Statistiques SET PoidsFichiers = 1 WHERE 1")
			elif colonne == "NbEnvsLstNoeuds":
				cursor.execute("UPDATE Statistiques SET NbEnvsLstNoeuds = 1 WHERE 1")
			elif colonne == "NbEnvsLstFichiers":
				cursor.execute("UPDATE Statistiques SET NbEnvsLstFichiers = 1 WHERE 1")
			elif colonne == "NbEnvsLstFichiersExt":
				cursor.execute("UPDATE Statistiques SET NbEnvsLstFichiersExt = 1 WHERE 1")
			elif colonne == "NbEnvsFichiers":
				cursor.execute("UPDATE Statistiques SET NbEnvsFichiers = 1 WHERE 1")
			elif colonne == "NbPresence":
				cursor.execute("UPDATE Statistiques SET NbPresence = 1 WHERE 1")
			elif colonne == "NbReceptFichiers":
				cursor.execute("UPDATE Statistiques SET NbReceptFichiers = 1 WHERE 1")
			else:
				logs.addLogs("ERROR : This statistic is unknown : "+str(colonne))
		else:
			if colonne == "NbNoeuds":
				cursor.execute("UPDATE Statistiques SET NbNoeuds = "+str(valeur)+" WHERE 1")
			elif colonne == "NbFichiersExt":
				cursor.execute("UPDATE Statistiques SET NbFichiersExt = "+str(valeur)+" WHERE 1")
			elif colonne == "NbSN":
				cursor.execute("UPDATE Statistiques SET NbSN = "+str(valeur)+" WHERE 1")
			elif colonne == "NbFichiers":
				cursor.execute("UPDATE Statistiques SET NbFichiers = "+str(valeur)+" WHERE 1")
			elif colonne == "PoidsFichiers":
				cursor.execute("UPDATE Statistiques SET PoidsFichiers = "+str(valeur)+" WHERE 1")
			elif colonne == "NbEnvsLstNoeuds":
				cursor.execute("UPDATE Statistiques SET NbEnvsLstNoeuds = "+str(valeur)+" WHERE 1")
			elif colonne == "NbEnvsLstFichiers":
				cursor.execute("UPDATE Statistiques SET NbEnvsLstFichiers = "+str(valeur)+" WHERE 1")
			elif colonne == "NbEnvsLstFichiersExt":
				cursor.execute("UPDATE Statistiques SET NbEnvsLstFichiersExt = "+str(valeur)+" WHERE 1")
			elif colonne == "NbEnvsFichiers":
				cursor.execute("UPDATE Statistiques SET NbEnvsFichiers = "+str(valeur)+" WHERE 1")
			elif colonne == "NbPresence":
				cursor.execute("UPDATE Statistiques SET NbPresence = "+str(valeur)+" WHERE 1")
			elif colonne == "NbReceptFichiers":
				cursor.execute("UPDATE Statistiques SET NbReceptFichiers = "+str(valeur)+" WHERE 1")
			else:
				logs.addLogs("ERROR : This statistic is unknown : "+str(colonne))
		conn.commit()
	except Exception as e:
		conn.rollback()
		logs.addLogs("ERROR : Problem with database (modifStats()):" + str(e))
		logs.addLogs(str(valeur) + colonne)
	conn.close()

def compterStats(colonne):
	verifExistBDD()
	conn = sqlite3.connect('WTP.db')
	cursor = conn.cursor()
	try:
		cursor.execute("""SELECT ? FROM Statistiques WHERE 1""", (colonne,))
		conn.commit()
	except Exception as e:
		conn.rollback()
		logs.addLogs("ERROR : Problem with database (compterStats()):" + str(e))
	conn.close()

def aleatoire(nomTable, entree, nbEntrees, fonction = ""):
	# Fonction qui a pour but de renvoyer sour forme d'un tableau nbEntrees lignes
	# contenues dans nomTable de façon aléatoire.
	error = 0
	verifExistBDD()
	conn = sqlite3.connect('WTP.db')
	cursor = conn.cursor()
	try:
		if nomTable == "Noeuds":
			if fonction == "":
				fonction = "Simple"
			cursor.execute("""SELECT IP FROM Noeuds WHERE Fonction = ? ORDER BY RANDOM() LIMIT ?""", (fonction, nbEntrees))
			conn.commit()
	except Exception as e:
		conn.rollback()
		logs.addLogs("ERROR : Problem with database (aleatoire()):" + str(e))
		error += 1
	rows = cursor.fetchall()
	tableau = []
	for row in rows:
		tableau.append(row)
		# On remplit le tableau avant de le retourner
	conn.close()
	if len(tableau) != nbEntrees:
		error += 1
		# return error
		# Ligne à activer seulement lorsque le réseau fonctionne
	return tableau

def verifExistBDD():
	# Fonction qui permet d'alèger le code en évitant les duplications
	try:
		with open('WTP.db'):
			pass
	except Exception:
		logs.addLogs("ERROR : Base not found ... Creating a new base.")
		creerBase()
