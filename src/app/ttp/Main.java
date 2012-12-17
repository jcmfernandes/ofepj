// Group 9

package app.ttp;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashSet;
import java.util.Set;

import app.Configurations;

public class Main {

	private static class ServerThread extends Thread {

		private boolean listen;
		private int port;
		private ServerSocket serverSocket;
		private Set<DBEntry> db;
		

		public ServerThread(int port, Set<DBEntry> db) {
			this.port = port;
			this.db = db;
			listen = false;
		}

		public void run() {
			listen = true;
			try {
				serverSocket = new ServerSocket(port);
				while (listen) {
					Socket socket = serverSocket.accept();
					ClientThread clientThread = null;
					clientThread = new ClientThread(socket, db);
					Thread t = 	new Thread(clientThread);
					t.start();
				}
			} catch (IOException ioe) {
				// I/O error in ServerSocket
				stopServerThread();
			}
		}

		public void stopServerThread() {
			try {
				serverSocket.close();
			} catch (IOException ioe) {
				// unable to close the ServerSocket... whatever!
			}
			listen = false;
		}
	}

	public static void execute() {
		Set<DBEntry> db = new HashSet<DBEntry>();
		
		ServerThread serverThread = new ServerThread(Integer.parseInt(Configurations.B_PORT), db);
		serverThread.start();
		try {
			serverThread.join();
		} catch (InterruptedException e) {
			e.printStackTrace();
			System.out.println("Terminating.");
			System.exit(0);
		}
	}

}
