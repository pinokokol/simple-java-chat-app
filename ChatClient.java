import java.io.*;
import java.net.*;
import java.util.*;
import java.time.format.DateTimeFormatter;
import java.time.LocalDateTime;
import org.json.JSONObject;

public class ChatClient extends Thread {
	protected int serverPort = 8888;

	public static void main(String[] args) throws Exception {
		new ChatClient();
	}

	public ChatClient() throws Exception {
		Socket socket = null;
		DataInputStream in = null;
		DataOutputStream out = null;

		BufferedReader std_in = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Vpisite svoje ime: ");
		String ime = std_in.readLine();
		
		JSONObject wholeMessage = new JSONObject();

		DateTimeFormatter dtf = DateTimeFormatter.ofPattern("HH:mm:ss");  
   		LocalDateTime now = LocalDateTime.now();
		
		wholeMessage.put("sender", ime);
		wholeMessage.put("time", dtf.format(now));
		
		// connect to the chat server
		try {
			System.out.println("[system] connecting to chat server ...");
			socket = new Socket("localhost", serverPort); // create socket connection
			in = new DataInputStream(socket.getInputStream()); // create input stream for listening for incoming messages
			out = new DataOutputStream(socket.getOutputStream()); // create output stream for sending messages
			System.out.println("[system] connected");


			/* this.sendMessage("uporabnik " + ime + " se je povezal", out); */

			ChatClientMessageReceiver message_receiver = new ChatClientMessageReceiver(in); // create a separate thread for listening to messages from the chat server
			message_receiver.start(); // run the new thread
		} catch (Exception e) {
			e.printStackTrace(System.err);
			System.exit(1);
		}
		
		// read from STDIN and send messages to the chat server
		String userInput;
		
		
		while ((userInput = std_in.readLine()) != null) { // read a line from the console
			wholeMessage.put("message", userInput);
			this.sendMessage(wholeMessage.toString(), out); // send the message to the chat server
		}
		
		// cleanup
		out.close();
		in.close();
		std_in.close();
		socket.close();
	}

	private void sendMessage(String wholeMessage, DataOutputStream out) {
		try {
			out.writeUTF(wholeMessage); // send the message to the chat server
			out.flush(); // ensure the message has been sent
		} catch (IOException e) {
			System.err.println("[system] could not send message");
			e.printStackTrace(System.err);
		}
	}


}

// wait for messages from the chat server and print the out
class ChatClientMessageReceiver extends Thread {
	private DataInputStream in;

	public ChatClientMessageReceiver(DataInputStream in) {
		this.in = in;
	}

	public void run() {
		try {
			String message;
			while ((message = this.in.readUTF()) != null) { // read new message
				System.out.println("[RKchat] " + message); // print the message to the console
			}
		} catch (Exception e) {
			System.err.println("[system] could not read message");
			e.printStackTrace(System.err);
			System.exit(1);
		}
	}
}


