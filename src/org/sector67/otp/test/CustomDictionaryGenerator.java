package org.sector67.otp.test;

public class CustomDictionaryGenerator {

	public static void main(String[] args) {
		char[] list = new String("0123456789ABCDEF").toCharArray();
		for (int i = 0; i < list.length; i++) {
			for (int j = 0; j < list.length; j++) {
				System.out.print(list[i]);
				System.out.println(list[j]);
			}
		}
		

	}

}
