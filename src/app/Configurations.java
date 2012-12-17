// Group 9

package app;

import java.security.KeyPair;

public abstract class Configurations {

	public static boolean DEBUG = false;
	
	public enum Principal { A, B, TTP }
	
	public static Principal PRINCIPAL;
	
	public static String B_PORT;
	public static String B_ADDRESS;
	public static String TTP_ADDRESS;
	
	public static String A_IDENTITY;
	public static String B_IDENTITY;
	public final static String TTP_IDENTITY = "TTP";
	
	public static KeyPair USER_KEYPAIR;
	
	public static String MESSAGE;
	
	public final static long TIMEOUT = 10000;
	
}
