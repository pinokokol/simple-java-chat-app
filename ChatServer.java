import java.io.*;
import java.net.*;
import java.util.*;
import java.time.format.DateTimeFormatter;
import java.time.LocalDateTime;
import org.json.JSONObject;
import java.util.Arrays;
import java.util.function.IntPredicate;
import javax.net.ssl.*;
import java.security.*;

public class ChatServer {

	protected int serverPort = 8888;
	protected List<SSLSocket> clients = new ArrayList<SSLSocket>(); // list of clients

	public static void main(String[] args) throws Exception {
		new ChatServer();
	}

	public ChatServer() {
		SSLServerSocket serverSocket = null;

		// create socket
		try {
			//serverSocket = new ServerSocket(this.serverPort); // create the ServerSocket

			String passphrase = "998877";

			// preberi datoteko z odjemalskimi certifikati
			KeyStore clientKeyStore = KeyStore.getInstance("JKS"); // KeyStore za shranjevanje odjemalčevih javnih ključev (certifikatov)
			clientKeyStore.load(new FileInputStream("clients.public"), passphrase.toCharArray());

			// preberi datoteko s svojim certifikatom in tajnim ključem
			KeyStore serverKeyStore = KeyStore.getInstance("JKS"); // KeyStore za shranjevanje strežnikovega tajnega in javnega ključa
			serverKeyStore.load(new FileInputStream("server.private"), passphrase.toCharArray());

			// vzpostavi SSL kontekst (komu zaupamo, kakšni so moji tajni ključi in certifikati)
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(clientKeyStore);

			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(serverKeyStore, passphrase.toCharArray());

			SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), (new SecureRandom()));

			// kreiramo socket
			SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
			serverSocket = (SSLServerSocket) factory.createServerSocket(serverPort);
			serverSocket.setNeedClientAuth(true); // tudi odjemalec se MORA predstaviti s certifikatom
			serverSocket.setEnabledCipherSuites(new String[] {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"});
		} catch (Exception e) {
			System.err.println("[system] could not create socket on port " + this.serverPort);
			e.printStackTrace(System.err);
			System.exit(1);
		}

		// start listening for new connections
		System.out.println("[system] listening ...");
		try {
			while (true) {
				SSLSocket newClientSocket = (SSLSocket) serverSocket.accept(); // wait for a new client connection
				newClientSocket.startHandshake();
				synchronized (this) {
					clients.add(newClientSocket); // add client to the list of clients
				}
				ChatServerConnector conn = new ChatServerConnector(this, newClientSocket);
				conn.start(); // run the new thread
			}
		} catch (Exception e) {
			System.err.println("[error] Accept failed.");
			e.printStackTrace(System.err);
			System.exit(1);
		}

		// close socket
		System.out.println("[system] closing server socket ...");
		try {
			serverSocket.close();
		} catch (IOException e) {
			e.printStackTrace(System.err);
			System.exit(1);
		}
	}

	// send a message to all clients connected to the server
	public void sendToAllClients(String message) throws Exception {
		Iterator<SSLSocket> i = clients.iterator();
		while (i.hasNext()) { // iterate through the client list
			SSLSocket socket = (SSLSocket) i.next(); // get the socket for communicating with this client
			try {
				DataOutputStream out = new DataOutputStream(socket.getOutputStream());
				out.writeUTF(message); // send message to the client
			} catch (Exception e) {
				System.err.println("[system] could not send message to a client");
				e.printStackTrace(System.err);
			}
		}
	}

	// send a message to specific client connected to the server
	public void sendToSpecificClient(String message, String ip, int port, SSLSocket socket) throws Exception {
        int counter = 0;
        for (int i = 0; i < clients.size(); i++) {
            if (clients.get(i).getInetAddress().getHostName().equals(ip) && clients.get(i).getPort() == port) {
                SSLSocket secondSocket = (SSLSocket) clients.get(i);
                try {
                    DataOutputStream out = new DataOutputStream(secondSocket.getOutputStream());
                    out.writeUTF(message);
                    System.out.println("Sporocilo uspesno poslano");
                    // send message to the client
                } catch (Exception e) {
                    System.err.println("[system] could not send a message to a client");
                    e.printStackTrace(System.err);
                }
                counter++;

            }

        }

        if (counter == 0) {
            System.out.println("Naslov ali port ne obstaja");
            try {
                DataOutputStream out = new DataOutputStream(socket.getOutputStream()); // create output stream for sending messages to the client
                out.writeUTF("Naslov ali port ne obstaja");
                // send message to the client
            } catch (Exception e) {
                System.err.println("[system] could not send a message to a client");
                e.printStackTrace(System.err);
            }
        }
    }
	

	public void removeClient(SSLSocket socket) {
		synchronized (this) {
			clients.remove(socket);
		}
	}
}

class ChatServerConnector extends Thread {
	private ChatServer server;
	private SSLSocket socket;
	String senderssl;

	public ChatServerConnector(ChatServer server, SSLSocket socket) {
		this.server = server;
		this.socket = socket;
		try {
			senderssl = ((SSLSocket) socket).getSession().getPeerPrincipal().getName();
		}
		catch (SSLPeerUnverifiedException e) {
			e.printStackTrace();
		}	
		
	}

	public void run() {
		System.out.println(
				"[system] connected with " + this.socket.getInetAddress().getHostName() + ":" + this.socket.getPort());

		DataInputStream in;

		try {
			in = new DataInputStream(this.socket.getInputStream()); // create input stream for listening for incoming
			// messages
		} catch (IOException e) {
			System.err.println("[system] could not open input stream!");
			e.printStackTrace(System.err);
			this.server.removeClient(socket);
			return;
		}
		
		
		while (true) { // infinite loop in which this thread waits for incoming messages and processes them
			String msg_received;
			try {
				msg_received = in.readUTF(); // read the message from the client
			} catch (Exception e) {
				System.err.println("[system] there was a problem while reading message client on port " + this.socket.getPort() + ", removing client");
				e.printStackTrace(System.err);
				this.server.removeClient(this.socket);
				return;
			}

			JSONObject wholeMessage = new JSONObject(msg_received);
			String sender = wholeMessage.getString("sender");
			String time = wholeMessage.getString("time");
			String message = wholeMessage.getString("message");
			String[] arrayFromMessage = message.split(" ");
			String reciever = "public";
			String ip = "";
			int port = 0;

			if (arrayFromMessage[0].equals("/")) {
				reciever = arrayFromMessage[1];
				ip = arrayFromMessage[2];
				port = Integer.parseInt(arrayFromMessage[3]);
			}

			if (message.length() == 0) // invalid message
				continue;

			// send to all
			if (reciever.equals("public")) {
				
				System.out.println("[RKchat]" + "[" + time +"]" + "[" + this.socket.getPort() + " " + senderssl + "] " + "[to " + reciever + "]" + ": " + message);

				String msg_send = "[" + time +"] " + senderssl/*sender*/ + " [to " + reciever +"]" + " said: " + message.toUpperCase();

				try {
					this.server.sendToAllClients(msg_send); // send message to all clients
				} catch (Exception e) {
					System.err.println("[system] there was a problem while sending the message to all clients");
					e.printStackTrace(System.err);
					continue;
				}

			} else {
				
				System.out.println("[RKchat]" + "[" + time +"]" + "[" + this.socket.getPort() + " " + senderssl + "] " + "[to " + reciever + "]" + ": " + message);

				String msg_send = "[" + time +"] " + senderssl + " [to " + reciever +"]" + " said: " + message.toUpperCase();

				try {
					this.server.sendToSpecificClient(msg_send, ip, port, this.socket); // send message to all clients
				} catch (Exception e) {
					System.err.println("[system] there was a problem while sending the message to all clients");
					e.printStackTrace(System.err);
					continue;
				}
			}
		}
	}
}
