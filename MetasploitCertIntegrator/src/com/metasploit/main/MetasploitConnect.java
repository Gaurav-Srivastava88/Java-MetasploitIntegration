package com.metasploit.main;

import com.metasploit.connector.RpcConnection;

public class MetasploitConnect {
	public static void main(final String... args) {
		String username = "msf";
		char[] password = {'I','Z','N','A','p','v','d','q'};
		String host = "192.168.1.8";
		int port = 55552;
		boolean ssl = false;
		
		RpcConnection.getConn(username, password, host, port, ssl);
	}
}