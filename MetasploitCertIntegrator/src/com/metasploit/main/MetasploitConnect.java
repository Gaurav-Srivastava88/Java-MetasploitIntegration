package com.metasploit.main;

import java.util.HashMap;

import com.metasploit.connector.RpcConnection;

public class MetasploitConnect {
	public static void main(final String... args) {
		String username = "msf";
		char[] password = {'g','a','u','r','a','v'};
		String host = "192.168.1.6";
		int port = 55552;
		boolean ssl = false;
		
		RpcConnection conn = RpcConnection.getConn(username, password, host, port, ssl);
		Object[] params = {};
		Object[] params1 = {"2", "use auxiliary/scanner/ssh/ssh_version\n"};
		Object[] params2 = {"2", "set RHOSTS 192.168.1.8\n"};
		Object[] params3 = {"2", "run\n"};
		Object[] params4 = {"2"};
		
		System.out.println(conn.execute("core.module_stats", params));
		System.out.println(conn.execute("core.version", params));
		//System.out.println(conn.execute("console.create", params));		
		System.out.println(conn.execute("module.auxiliary", params));
		System.out.println(conn.execute("console.write", params1));		
		System.out.println(conn.execute("console.write", params2));		
		System.out.println(conn.execute("console.write", params3));	
		HashMap<String, String> jsonValue = (HashMap<String, String>) conn.execute("console.read", params4);
		System.out.println(jsonValue.get("data"));
	}
}
