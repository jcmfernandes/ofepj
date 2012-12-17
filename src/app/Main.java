// Group 9

package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import util.CryptoWrapper;

public class Main {

	public static void main(String[] args) {
		Options opts = new Options();

		opts.addOption("h", false, "Print help for this application");
		opts.addOption("d", false, "Enable the debug mode");
		opts.addOption("gk", true, "Generate keys for the specified user identity");

		opts.addOption("a", false, "Client in mode A");
		opts.addOption("b", false, "Client in mode B");
		opts.addOption("ttp", false, "Run in TTP mode");
		
		opts.addOption("ai", true, "A user identity");
		opts.addOption("bi", true, "B user identity");

		opts.addOption("lp", true, "The listening local port (only needed by B and TTP)");
		opts.addOption("ba", true, "B's address - <host>:<port> (only needed by A)");
		opts.addOption("ta", true, "The TTP address - <host>:<port> (needed by both A and B)");

		BasicParser parser = new BasicParser();
		CommandLine cl = null;
		try {
			cl = parser.parse(opts, args);
		} catch (ParseException e) {
			e.printStackTrace();
			System.exit(-1);
		}
		
		Configurations.A_IDENTITY = cl.getOptionValue("ai", "");
		Configurations.B_IDENTITY = cl.getOptionValue("bi", "");

		Configurations.B_PORT = cl.getOptionValue("lp", "");
		Configurations.B_ADDRESS = cl.getOptionValue("ba", "");
		Configurations.TTP_ADDRESS = cl.getOptionValue("ta", "");

		if (cl.hasOption("h")) {
			System.out.println("You have asked for help!");
			for (Object o : opts.getOptions()) {
				System.out.println(o);
			}
			System.exit(0);
		}
		if (cl.hasOption("gk")) {
			String uid = cl.getOptionValue("gk", "");
			if (uid.equals("")) {
				System.err.println("Specify a user identity!");
			} else {
				CryptoWrapper.generateKeyPair(uid);
				System.out.println("Keys generated with success!");
			}
			System.exit(0);
		}
		if (cl.hasOption("d")) {
			Configurations.DEBUG = true;
			System.out.println("Debug mode enabled.");
		}
		if (cl.hasOption("a")) {
			Configurations.PRINCIPAL = Configurations.Principal.A;
			Configurations.USER_KEYPAIR = CryptoWrapper.loadKeyPair(Configurations.A_IDENTITY);
			
			System.out.print("Type the message: ");
			InputStreamReader isr = new InputStreamReader(System.in);
			BufferedReader br = new BufferedReader(isr);
			try {
				Configurations.MESSAGE = br.readLine();
			} catch (IOException e) {
				Configurations.MESSAGE = "Whatever!";
			}
		} else if (cl.hasOption("b")) {
			Configurations.PRINCIPAL = Configurations.Principal.B;
			Configurations.USER_KEYPAIR = CryptoWrapper.loadKeyPair(Configurations.B_IDENTITY);
		} else if (cl.hasOption("ttp")) {
			Configurations.PRINCIPAL = Configurations.Principal.TTP;
			Configurations.USER_KEYPAIR = CryptoWrapper.loadKeyPair(Configurations.TTP_IDENTITY);
		} else {
			System.out.println("You need to choose an operation mode.");
		}
		
		if (Configurations.PRINCIPAL != null) {
			if (Configurations.PRINCIPAL.equals(Configurations.Principal.A) || Configurations.PRINCIPAL.equals(Configurations.Principal.B)) {
				app.client.Main.execute();
			} else if (Configurations.PRINCIPAL.equals(Configurations.Principal.TTP)) {
				app.ttp.Main.execute();
			}
			System.exit(0);
		}
		
		System.out.println("Use argument -h to get help.");
	}

}
